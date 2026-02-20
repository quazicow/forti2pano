"""CLI entry point and orchestration logic."""

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .util import setup_logging, sanitize_name
from .parser.tokenizer import tokenize
from .parser.tree import build_tree
from .parser.extractors import extract_all
from .decisions.schema import DecisionForm
from .decisions.generator import generate_decisions
from .decisions.resolver import apply_decisions
from .emitters.panos_xml import emit_xml_string
from .emitters.panos_set import emit_set_commands_string
from .model.config import PanoConfig
from .model.policy import NATPolicy, NATType, VIP
from .model.vpn import IKECryptoProfile, IPSecCryptoProfile, IKEGateway, IPSecTunnel
from .model.objects import AddressObject, AddressType, ServiceObject
from .mappings.crypto import parse_proposal, map_dh_group
from .mappings.services import is_predefined_fg_service, get_predefined_service_def, FG_TO_PANOS_SERVICE

log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="forti2pano",
        description="Convert FortiGate configuration to PAN-OS XML and set commands.",
    )
    p.add_argument(
        "input", type=Path,
        help="Path to FortiGate config file",
    )
    p.add_argument(
        "-d", "--decisions", type=Path, default=None,
        help="Path to filled-in decisions YAML (for pass 2)",
    )
    p.add_argument(
        "-o", "--output-dir", type=Path, default=Path("."),
        help="Output directory (default: current directory)",
    )
    p.add_argument("--xml-only", action="store_true", help="Output only PAN-OS XML")
    p.add_argument("--set-only", action="store_true", help="Output only set commands")
    p.add_argument("--vsys", default="vsys1", help="PAN-OS vsys (default: vsys1)")
    p.add_argument("--virtual-router", default="default", help="Virtual router (default: default)")
    p.add_argument("--vdom", default=None, help="FortiGate VDOM to process")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--version", action="version", version=f"forti2pano {__version__}")
    return p


def _create_predefined_services(config: PanoConfig):
    """Create PAN-OS service objects for FortiGate predefined services
    that are used in policies but don't have a PAN-OS predefined equivalent."""
    existing = {s.name for s in config.services}
    needed = set()

    for pol in config.security_policies:
        for svc_name in pol.services:
            if svc_name in existing:
                continue
            if is_predefined_fg_service(svc_name):
                panos_equiv = FG_TO_PANOS_SERVICE.get(svc_name)
                if panos_equiv is not None:
                    # Has a PAN-OS predefined equivalent, no custom object needed
                    continue
                defn = get_predefined_service_def(svc_name)
                if defn and svc_name not in needed:
                    needed.add(svc_name)
                    proto, port = defn
                    config.services.append(ServiceObject(
                        name=sanitize_name(svc_name),
                        protocol=proto,
                        dst_port=port,
                        description=f"Auto-created from FortiGate predefined '{svc_name}'",
                    ))
                    log.info(f"Created service object for predefined '{svc_name}' ({proto}/{port})")


def _build_nat_policies(config: PanoConfig):
    """Generate PAN-OS NAT policies from VIPs, IP Pools, and policy NAT settings."""
    nat_policies = []

    # Build zone lookup
    intf_to_zone = {}
    for zone in config.zones:
        for fg_intf in zone.interfaces_fg:
            intf_to_zone[fg_intf] = zone.name
    for iface in config.interfaces:
        if iface.zone and iface.fg_name not in intf_to_zone:
            intf_to_zone[iface.fg_name] = iface.zone

    # --- DNAT from VIPs ---
    for vip in config.vips:
        nat_name = sanitize_name(f"DNAT-{vip.name}")

        # Determine from-zone from the external interface
        from_zone = "any"
        if vip.ext_interface_fg and vip.ext_interface_fg != "any":
            from_zone = intf_to_zone.get(vip.ext_interface_fg, vip.ext_interface_fg)

        # Create address object for VIP external IP if needed
        ext_addr_name = sanitize_name(f"{vip.name}-ext")
        ext_addr_exists = any(a.name == ext_addr_name for a in config.addresses)
        if not ext_addr_exists and vip.ext_ip:
            ext_ip = vip.ext_ip
            if "/" not in ext_ip:
                ext_ip = f"{ext_ip}/32"
            config.addresses.append(AddressObject(
                name=ext_addr_name,
                addr_type=AddressType.IP_NETMASK,
                value=ext_ip,
                description=f"VIP external address for {vip.name}",
            ))

        # Create address object for mapped IP if needed
        mapped_addr_name = sanitize_name(f"{vip.name}-mapped")
        mapped_addr_exists = any(a.name == mapped_addr_name for a in config.addresses)
        if not mapped_addr_exists and vip.mapped_ip:
            mapped_ip = vip.mapped_ip
            if "/" not in mapped_ip and "-" not in mapped_ip:
                mapped_ip = f"{mapped_ip}/32"
            if "-" in mapped_ip:
                addr_type = AddressType.IP_RANGE
            else:
                addr_type = AddressType.IP_NETMASK
            config.addresses.append(AddressObject(
                name=mapped_addr_name,
                addr_type=addr_type,
                value=mapped_ip,
                description=f"VIP mapped address for {vip.name}",
            ))

        nat_pol = NATPolicy(
            name=nat_name,
            nat_type=NATType.DNAT_PORT_FORWARD if vip.port_forward else NATType.DNAT,
            from_zones=[from_zone],
            to_zones=["any"],
            destination=[ext_addr_name],
            dest_translated_address=mapped_addr_name,
            description=f"DNAT from VIP '{vip.name}'",
        )

        if vip.port_forward:
            # Set service based on port
            if vip.ext_port:
                svc_name = sanitize_name(f"svc-{vip.name}")
                config.services.append(ServiceObject(
                    name=svc_name,
                    protocol=vip.protocol,
                    dst_port=vip.ext_port,
                    description=f"VIP service for {vip.name}",
                ))
                nat_pol.service = svc_name
            if vip.mapped_port:
                nat_pol.dest_translated_port = vip.mapped_port
        else:
            nat_pol.service = "any"

        nat_policies.append(nat_pol)

    # --- SNAT from policies with NAT enabled ---
    pool_lookup = {p.name: p for p in config.ip_pools}

    for pol in config.security_policies:
        if not pol.nat:
            continue

        if pol.ippool and pol.poolname:
            # SNAT using IP Pool
            for pool_name in pol.poolname:
                pool = pool_lookup.get(pool_name)
                if not pool:
                    log.warning(f"Policy '{pol.name}' references pool '{pool_name}' which was not found")
                    continue

                nat_name = sanitize_name(f"SNAT-{pol.name}-{pool_name}")

                # Create address object for pool
                pool_addr_name = sanitize_name(f"pool-{pool_name}")
                if not any(a.name == pool_addr_name for a in config.addresses):
                    if pool.start_ip == pool.end_ip:
                        config.addresses.append(AddressObject(
                            name=pool_addr_name,
                            addr_type=AddressType.IP_NETMASK,
                            value=f"{pool.start_ip}/32",
                            description=f"IP Pool '{pool_name}'",
                        ))
                    else:
                        config.addresses.append(AddressObject(
                            name=pool_addr_name,
                            addr_type=AddressType.IP_RANGE,
                            value=f"{pool.start_ip}-{pool.end_ip}",
                            description=f"IP Pool '{pool_name}'",
                        ))

                src_type = "dynamic-ip-and-port"
                if pool.pool_type == "one-to-one":
                    src_type = "static-ip"

                nat_pol = NATPolicy(
                    name=nat_name,
                    nat_type=NATType.SNAT_DYNAMIC,
                    from_zones=pol.source_zones or ["any"],
                    to_zones=pol.dest_zones or ["any"],
                    source=pol.source_addresses or ["any"],
                    destination=pol.dest_addresses or ["any"],
                    src_translated_type=src_type,
                    src_translated_addresses=[pool_addr_name],
                    description=f"SNAT from policy '{pol.name}' using pool '{pool_name}'",
                )
                nat_policies.append(nat_pol)
        else:
            # Interface-based SNAT (use outgoing interface IP)
            nat_name = sanitize_name(f"SNAT-{pol.name}")
            nat_pol = NATPolicy(
                name=nat_name,
                nat_type=NATType.SNAT_INTERFACE,
                from_zones=pol.source_zones or ["any"],
                to_zones=pol.dest_zones or ["any"],
                source=pol.source_addresses or ["any"],
                destination=pol.dest_addresses or ["any"],
                src_translated_type="dynamic-ip-and-port",
                description=f"Interface SNAT from policy '{pol.name}'",
            )
            nat_policies.append(nat_pol)

    config.nat_policies = nat_policies


def _resolve_vpn_objects(config: PanoConfig):
    """Build PAN-OS VPN objects (crypto profiles, gateways, tunnels)
    from FortiGate phase1/phase2 data."""

    intf_map = getattr(config, '_intf_map', {})

    for p1 in config.phase1_list:
        # Parse proposals
        encryptions = []
        authentications = []
        for prop in p1.proposals:
            enc, auth = parse_proposal(prop)
            if enc and enc not in encryptions:
                encryptions.append(enc)
            if auth and auth not in authentications:
                authentications.append(auth)

        if not encryptions:
            encryptions = ["aes-256-cbc"]
        if not authentications:
            authentications = ["sha256"]

        dh_groups = [map_dh_group(g) for g in p1.dhgrp]
        if not dh_groups:
            dh_groups = ["group14"]

        # IKE Crypto Profile
        ike_cp_name = sanitize_name(f"ike-crypto-{p1.name}")
        config.ike_crypto_profiles.append(IKECryptoProfile(
            name=ike_cp_name,
            encryption=encryptions,
            authentication=authentications,
            dh_group=dh_groups,
            lifetime_seconds=min(p1.keylife, 86400),
        ))

        # IKE Gateway
        gw_name = sanitize_name(f"ike-gw-{p1.name}")
        wan_intf = p1.interface_panos or intf_map.get(p1.interface_fg, p1.interface_fg)
        config.ike_gateways.append(IKEGateway(
            name=gw_name,
            interface=wan_intf,
            peer_address=p1.remote_gw,
            psk=p1.psk,
            crypto_profile=ike_cp_name,
            ike_version=f"ikev{p1.ike_version}",
            nat_traversal=p1.nattraversal == "enable",
        ))

    # Phase2 -> IPSec crypto profiles and tunnels
    # Group phase2 entries by phase1name
    p1_lookup = {p1.name: p1 for p1 in config.phase1_list}
    p2_by_p1 = {}
    for p2 in config.phase2_list:
        p2_by_p1.setdefault(p2.phase1name, []).append(p2)

    for p1_name, p2_list in p2_by_p1.items():
        p1 = p1_lookup.get(p1_name)
        if not p1:
            log.warning(f"Phase2 references phase1 '{p1_name}' which was not found")
            continue

        gw_name = sanitize_name(f"ike-gw-{p1_name}")

        for p2 in p2_list:
            # IPSec Crypto Profile
            encryptions = []
            authentications = []
            for prop in p2.proposals:
                enc, auth = parse_proposal(prop)
                if enc and enc not in encryptions:
                    encryptions.append(enc)
                if auth and auth not in authentications:
                    authentications.append(auth)

            if not encryptions:
                encryptions = ["aes-256-cbc"]
            if not authentications:
                authentications = ["sha256"]

            dh_group = "no-pfs"
            if p2.pfs and p2.dhgrp:
                dh_group = map_dh_group(p2.dhgrp[0])

            ipsec_cp_name = sanitize_name(f"ipsec-crypto-{p2.name}")
            config.ipsec_crypto_profiles.append(IPSecCryptoProfile(
                name=ipsec_cp_name,
                encryption=encryptions,
                authentication=authentications,
                dh_group=dh_group,
                lifetime_seconds=min(p2.keylife_seconds, 86400),
            ))

            # IPSec Tunnel
            tunnel_name = sanitize_name(f"ipsec-{p2.name}")

            # Find tunnel interface from phase1 decision
            tunnel_intf = None
            # Check if phase1 has a tunnel interface assigned
            for item_p1 in config.phase1_list:
                if item_p1.name == p1_name:
                    # Look for the VPN tunnel interface decision
                    tunnel_intf = getattr(item_p1, '_tunnel_intf', None)
                    break

            # Build proxy IDs
            proxy_ids = []
            if p2.src_subnet and p2.dst_subnet:
                proxy_ids.append({
                    "name": sanitize_name(p2.name),
                    "local": p2.src_subnet,
                    "remote": p2.dst_subnet,
                })

            config.ipsec_tunnels.append(IPSecTunnel(
                name=tunnel_name,
                ike_gateway=gw_name,
                crypto_profile=ipsec_cp_name,
                tunnel_interface=tunnel_intf,
                proxy_ids=proxy_ids,
            ))


def _print_summary(config: PanoConfig):
    """Print a conversion summary."""
    print("\n" + "=" * 60)
    print("  forti2pano Conversion Summary")
    print("=" * 60)
    print(f"  Address Objects:      {len(config.addresses)}")
    print(f"  Address Groups:       {len(config.address_groups)}")
    print(f"  Service Objects:      {len(config.services)}")
    print(f"  Service Groups:       {len(config.service_groups)}")
    print(f"  Zones:                {len(config.zones)}")
    print(f"  Interfaces:           {len(config.interfaces)}")
    print(f"  Static Routes:        {len(config.static_routes)}")
    print(f"  Security Policies:    {len(config.security_policies)}")
    print(f"  NAT Policies:         {len(config.nat_policies)}")
    print(f"  IKE Crypto Profiles:  {len(config.ike_crypto_profiles)}")
    print(f"  IPSec Crypto Profiles:{len(config.ipsec_crypto_profiles)}")
    print(f"  IKE Gateways:         {len(config.ike_gateways)}")
    print(f"  IPSec Tunnels:        {len(config.ipsec_tunnels)}")
    print("=" * 60)


def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    # Validate input file
    if not args.input.exists():
        log.error(f"Input file not found: {args.input}")
        sys.exit(1)

    # === STEP 1: Parse FortiGate config ===
    log.info(f"Reading FortiGate config: {args.input}")
    raw_text = args.input.read_text(encoding="utf-8", errors="replace")
    tokens = tokenize(raw_text)
    log.info(f"Tokenized {len(tokens)} tokens")

    tree = build_tree(tokens)
    log.info(f"Built config tree with {len(tree)} top-level sections")

    # === STEP 2: Extract into intermediate model ===
    config = extract_all(tree)
    config.vsys = args.vsys
    config.virtual_router = args.virtual_router
    if args.vdom:
        config.vdom = args.vdom

    # Create service objects for predefined FortiGate services
    _create_predefined_services(config)

    # === STEP 3: Handle decisions ===
    if args.decisions:
        # PASS 2: Load user-filled decisions
        log.info(f"Loading decisions from: {args.decisions}")
        form = DecisionForm.from_yaml(args.decisions.read_text(encoding="utf-8"))

        if form.has_unresolved():
            unresolved = form.unresolved_items()
            log.error(f"{len(unresolved)} required decision(s) still need values:")
            for item in unresolved:
                log.error(f"  - {item.id}: {item.description[:80]}...")
            sys.exit(1)

        config = apply_decisions(config, form)
    else:
        # PASS 1: Generate decisions form
        form = generate_decisions(config, source_file=str(args.input))

        if form.items:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            decisions_path = args.output_dir / "decisions.yaml"
            decisions_path.write_text(form.to_yaml(), encoding="utf-8")
            log.info(f"Decisions form written to: {decisions_path}")
            log.info(f"  {len(form.items)} items need your input "
                     f"({len(form.unresolved_items())} required)")

            required_unresolved = form.unresolved_items()
            if required_unresolved:
                log.info(f"Edit the decisions file, then re-run with:")
                log.info(f"  python -m forti2pano {args.input} -d {decisions_path} -o {args.output_dir}")
                print(f"\nDecisions file written to: {decisions_path}")
                print(f"{len(required_unresolved)} required decision(s) need your input before conversion can proceed.")
                sys.exit(0)
            else:
                log.info("All required decisions have suggested values. Producing output...")
                # Apply suggestions
                for item in form.items:
                    if item.user_value is None:
                        item.user_value = item.suggested_value
                config = apply_decisions(config, form)

    # === STEP 4: Build NAT policies ===
    _build_nat_policies(config)

    # === STEP 5: Resolve VPN objects ===
    _resolve_vpn_objects(config)

    # === STEP 6: Emit outputs ===
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.set_only:
        xml_str = emit_xml_string(config)
        xml_path = args.output_dir / "panos_config.xml"
        xml_path.write_text(xml_str, encoding="utf-8")
        log.info(f"PAN-OS XML written to: {xml_path}")
        print(f"PAN-OS XML:          {xml_path}")

    if not args.xml_only:
        set_str = emit_set_commands_string(config)
        set_path = args.output_dir / "panos_set_commands.txt"
        set_path.write_text(set_str, encoding="utf-8")
        log.info(f"PAN-OS set commands written to: {set_path}")
        print(f"PAN-OS set commands: {set_path}")

    _print_summary(config)
