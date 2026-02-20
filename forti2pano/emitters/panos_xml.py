"""PAN-OS XML configuration emitter."""

import xml.etree.ElementTree as ET
from typing import List

from ..model.config import PanoConfig
from ..model.objects import AddressType
from ..model.policy import NATType
from ..mappings.services import map_service


def emit_xml(config: PanoConfig) -> ET.Element:
    """Build the full PAN-OS XML config tree."""
    root = ET.Element("config")
    devices = ET.SubElement(root, "devices")
    device_entry = ET.SubElement(devices, "entry", name=config.device_name)

    # --- vsys section ---
    vsys_el = ET.SubElement(device_entry, "vsys")
    vsys_entry = ET.SubElement(vsys_el, "entry", name=config.vsys)

    _emit_addresses(vsys_entry, config)
    _emit_address_groups(vsys_entry, config)
    _emit_services(vsys_entry, config)
    _emit_service_groups(vsys_entry, config)
    _emit_zones(vsys_entry, config)
    _emit_rulebase(vsys_entry, config)

    # --- network section ---
    network_el = ET.SubElement(device_entry, "network")
    _emit_interfaces(network_el, config)
    _emit_virtual_router(network_el, config)

    # --- VPN section (under network) ---
    _emit_ike_crypto_profiles(network_el, config)
    _emit_ipsec_crypto_profiles(network_el, config)
    _emit_ike_gateways(network_el, config)
    _emit_ipsec_tunnels(network_el, config)

    return root


def emit_xml_string(config: PanoConfig, indent: bool = True) -> str:
    """Return pretty-printed XML string."""
    root = emit_xml(config)
    if indent:
        ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def _add_member_list(parent: ET.Element, tag: str, members: List[str]):
    """Helper to add <tag><member>val1</member><member>val2</member></tag>."""
    container = ET.SubElement(parent, tag)
    for m in members:
        ET.SubElement(container, "member").text = m


def _emit_addresses(parent: ET.Element, config: PanoConfig):
    if not config.addresses:
        return
    addr_el = ET.SubElement(parent, "address")
    for addr in config.addresses:
        entry = ET.SubElement(addr_el, "entry", name=addr.name)
        if addr.addr_type == AddressType.IP_NETMASK:
            ET.SubElement(entry, "ip-netmask").text = addr.value
        elif addr.addr_type == AddressType.IP_RANGE:
            ET.SubElement(entry, "ip-range").text = addr.value
        elif addr.addr_type == AddressType.FQDN:
            ET.SubElement(entry, "fqdn").text = addr.value
        elif addr.addr_type == AddressType.IP_WILDCARD:
            ET.SubElement(entry, "ip-wildcard").text = addr.value
        if addr.description:
            ET.SubElement(entry, "description").text = addr.description


def _emit_address_groups(parent: ET.Element, config: PanoConfig):
    if not config.address_groups:
        return
    grp_el = ET.SubElement(parent, "address-group")
    for grp in config.address_groups:
        entry = ET.SubElement(grp_el, "entry", name=grp.name)
        static = ET.SubElement(entry, "static")
        for m in grp.members:
            ET.SubElement(static, "member").text = m
        if grp.description:
            ET.SubElement(entry, "description").text = grp.description


def _emit_services(parent: ET.Element, config: PanoConfig):
    if not config.services:
        return
    svc_el = ET.SubElement(parent, "service")
    for svc in config.services:
        entry = ET.SubElement(svc_el, "entry", name=svc.name)
        protocol_el = ET.SubElement(entry, "protocol")

        if svc.protocol in ("tcp", "udp"):
            proto_el = ET.SubElement(protocol_el, svc.protocol)
            if svc.dst_port:
                ET.SubElement(proto_el, "port").text = svc.dst_port
            if svc.src_port:
                ET.SubElement(proto_el, "source-port").text = svc.src_port
        elif svc.protocol == "icmp":
            # PAN-OS doesn't have ICMP as a service protocol in the same way
            # Use tcp with a comment, or skip
            proto_el = ET.SubElement(protocol_el, "tcp")
            ET.SubElement(proto_el, "port").text = "1-65535"
            ET.SubElement(entry, "description").text = f"ICMP service (type={svc.icmp_type})"
        elif svc.protocol == "ip":
            # IP protocol number - not directly supported
            proto_el = ET.SubElement(protocol_el, "tcp")
            ET.SubElement(proto_el, "port").text = "1-65535"
            if svc.protocol_number:
                ET.SubElement(entry, "description").text = f"IP protocol {svc.protocol_number}"

        if svc.description and not entry.find("description"):
            ET.SubElement(entry, "description").text = svc.description


def _emit_service_groups(parent: ET.Element, config: PanoConfig):
    if not config.service_groups:
        return
    grp_el = ET.SubElement(parent, "service-group")
    for grp in config.service_groups:
        entry = ET.SubElement(grp_el, "entry", name=grp.name)
        members_el = ET.SubElement(entry, "members")
        for m in grp.members:
            ET.SubElement(members_el, "member").text = m


def _emit_zones(parent: ET.Element, config: PanoConfig):
    if not config.zones:
        return
    zone_el = ET.SubElement(parent, "zone")
    for zone in config.zones:
        entry = ET.SubElement(zone_el, "entry", name=zone.name)
        network_el = ET.SubElement(entry, "network")
        layer3 = ET.SubElement(network_el, "layer3")
        intfs = zone.interfaces_panos if zone.interfaces_panos else zone.interfaces_fg
        for intf in intfs:
            ET.SubElement(layer3, "member").text = intf


def _emit_rulebase(parent: ET.Element, config: PanoConfig):
    rulebase = ET.SubElement(parent, "rulebase")
    _emit_security_rules(rulebase, config)
    _emit_nat_rules(rulebase, config)


def _emit_security_rules(rulebase: ET.Element, config: PanoConfig):
    if not config.security_policies:
        return
    security = ET.SubElement(rulebase, "security")
    rules = ET.SubElement(security, "rules")

    for pol in config.security_policies:
        entry = ET.SubElement(rules, "entry", name=pol.name)

        # From/To zones
        _add_member_list(entry, "from", pol.source_zones or ["any"])
        _add_member_list(entry, "to", pol.dest_zones or ["any"])

        # Source/Destination addresses
        _add_member_list(entry, "source", pol.source_addresses or ["any"])
        _add_member_list(entry, "destination", pol.dest_addresses or ["any"])

        if pol.source_negate:
            ET.SubElement(entry, "negate-source").text = "yes"
        if pol.dest_negate:
            ET.SubElement(entry, "negate-destination").text = "yes"

        # Services - map predefined FortiGate services
        mapped_services = []
        for svc in pol.services:
            mapped = map_service(svc)
            mapped_services.append(mapped)
        _add_member_list(entry, "service", mapped_services or ["application-default"])

        # Application
        _add_member_list(entry, "application", pol.application or ["any"])

        # Action
        ET.SubElement(entry, "action").text = pol.action

        # Logging
        if pol.log_start:
            ET.SubElement(entry, "log-start").text = "yes"
        if pol.log_end:
            ET.SubElement(entry, "log-end").text = "yes"

        # Security profiles
        if pol.profile_group:
            group_el = ET.SubElement(entry, "profile-setting")
            ET.SubElement(group_el, "group").text = pol.profile_group
        else:
            has_profiles = any([
                pol.av_profile, pol.vulnerability_profile,
                pol.url_filter_profile, pol.file_blocking_profile,
                pol.spyware_profile, pol.wildfire_profile,
            ])
            if has_profiles:
                profiles = ET.SubElement(entry, "profile-setting")
                profiles_el = ET.SubElement(profiles, "profiles")
                if pol.av_profile:
                    av = ET.SubElement(profiles_el, "virus")
                    ET.SubElement(av, "member").text = pol.av_profile
                if pol.vulnerability_profile:
                    vuln = ET.SubElement(profiles_el, "vulnerability")
                    ET.SubElement(vuln, "member").text = pol.vulnerability_profile
                if pol.url_filter_profile:
                    url = ET.SubElement(profiles_el, "url-filtering")
                    ET.SubElement(url, "member").text = pol.url_filter_profile
                if pol.file_blocking_profile:
                    fb = ET.SubElement(profiles_el, "file-blocking")
                    ET.SubElement(fb, "member").text = pol.file_blocking_profile
                if pol.spyware_profile:
                    spy = ET.SubElement(profiles_el, "spyware")
                    ET.SubElement(spy, "member").text = pol.spyware_profile
                if pol.wildfire_profile:
                    wf = ET.SubElement(profiles_el, "wildfire-analysis")
                    ET.SubElement(wf, "member").text = pol.wildfire_profile

        # Disabled
        if not pol.enabled:
            ET.SubElement(entry, "disabled").text = "yes"

        # Description
        if pol.description:
            ET.SubElement(entry, "description").text = pol.description


def _emit_nat_rules(rulebase: ET.Element, config: PanoConfig):
    if not config.nat_policies:
        return
    nat = ET.SubElement(rulebase, "nat")
    rules = ET.SubElement(nat, "rules")

    for nat_pol in config.nat_policies:
        entry = ET.SubElement(rules, "entry", name=nat_pol.name)

        _add_member_list(entry, "from", nat_pol.from_zones or ["any"])
        _add_member_list(entry, "to", nat_pol.to_zones or ["any"])
        _add_member_list(entry, "source", nat_pol.source or ["any"])
        _add_member_list(entry, "destination", nat_pol.destination or ["any"])

        ET.SubElement(entry, "service").text = nat_pol.service or "any"

        if nat_pol.nat_type in (NATType.DNAT, NATType.DNAT_PORT_FORWARD):
            if nat_pol.dest_translated_address:
                dst_trans = ET.SubElement(entry, "destination-translation")
                ET.SubElement(dst_trans, "translated-address").text = nat_pol.dest_translated_address
                if nat_pol.dest_translated_port:
                    ET.SubElement(dst_trans, "translated-port").text = nat_pol.dest_translated_port

        elif nat_pol.nat_type in (NATType.SNAT_DYNAMIC, NATType.SNAT_INTERFACE):
            src_trans = ET.SubElement(entry, "source-translation")
            if nat_pol.src_translated_type == "dynamic-ip-and-port":
                dip = ET.SubElement(src_trans, "dynamic-ip-and-port")
                if nat_pol.src_translated_addresses:
                    ta = ET.SubElement(dip, "translated-address")
                    for addr in nat_pol.src_translated_addresses:
                        ET.SubElement(ta, "member").text = addr
                else:
                    ET.SubElement(dip, "interface-address")
            elif nat_pol.src_translated_type == "static-ip":
                sip = ET.SubElement(src_trans, "static-ip")
                if nat_pol.src_translated_addresses:
                    ET.SubElement(sip, "translated-address").text = nat_pol.src_translated_addresses[0]

        if nat_pol.description:
            ET.SubElement(entry, "description").text = nat_pol.description


def _emit_interfaces(parent: ET.Element, config: PanoConfig):
    """Emit network interfaces."""
    if not config.interfaces:
        return
    iface_el = ET.SubElement(parent, "interface")
    ethernet_el = ET.SubElement(iface_el, "ethernet")

    for iface in config.interfaces:
        panos_name = iface.panos_name or iface.fg_name
        if not panos_name.startswith("ethernet"):
            continue  # skip non-ethernet interfaces for now

        entry = ET.SubElement(ethernet_el, "entry", name=panos_name)
        layer3 = ET.SubElement(entry, "layer3")

        if iface.ip_address:
            ip_el = ET.SubElement(layer3, "ip")
            ET.SubElement(ip_el, "entry", name=iface.ip_address)

        if iface.mtu:
            ET.SubElement(layer3, "mtu").text = str(iface.mtu)

    # Tunnel interfaces
    tunnel_intfs = [i for i in config.interfaces if (i.panos_name or "").startswith("tunnel.")]
    # Also add tunnel interfaces from VPN phase1
    vpn_tunnels = set()
    for p1 in config.phase1_list:
        if p1.interface_panos and p1.interface_panos.startswith("tunnel."):
            vpn_tunnels.add(p1.interface_panos)

    if tunnel_intfs or vpn_tunnels:
        tunnel_el = ET.SubElement(iface_el, "tunnel")
        units = ET.SubElement(tunnel_el, "units")
        seen = set()
        for ti in tunnel_intfs:
            name = ti.panos_name or ti.fg_name
            if name not in seen:
                ET.SubElement(units, "entry", name=name)
                seen.add(name)
        for tn in vpn_tunnels:
            if tn not in seen:
                ET.SubElement(units, "entry", name=tn)
                seen.add(tn)

    # Loopback interfaces
    loop_intfs = [i for i in config.interfaces if (i.panos_name or "").startswith("loopback.")]
    if loop_intfs:
        loop_el = ET.SubElement(iface_el, "loopback")
        units = ET.SubElement(loop_el, "units")
        for li in loop_intfs:
            name = li.panos_name or li.fg_name
            entry = ET.SubElement(units, "entry", name=name)
            if li.ip_address:
                ip_el = ET.SubElement(entry, "ip")
                ET.SubElement(ip_el, "entry", name=li.ip_address)


def _emit_virtual_router(parent: ET.Element, config: PanoConfig):
    """Emit virtual router with static routes."""
    vr_el = ET.SubElement(parent, "virtual-router")
    vr_entry = ET.SubElement(vr_el, "entry", name=config.virtual_router)

    # Add interfaces to virtual router
    all_intfs = []
    for iface in config.interfaces:
        name = iface.panos_name or iface.fg_name
        all_intfs.append(name)
    # Add tunnel interfaces from VPN
    for p1 in config.phase1_list:
        if p1.interface_panos:
            all_intfs.append(p1.interface_panos)

    if all_intfs:
        intf_el = ET.SubElement(vr_entry, "interface")
        for name in all_intfs:
            ET.SubElement(intf_el, "member").text = name

    if config.static_routes:
        rt = ET.SubElement(vr_entry, "routing-table")
        ip_rt = ET.SubElement(rt, "ip")
        static = ET.SubElement(ip_rt, "static-route")

        for route in config.static_routes:
            entry = ET.SubElement(static, "entry", name=route.name)
            ET.SubElement(entry, "destination").text = route.destination
            if route.nexthop:
                nexthop = ET.SubElement(entry, "nexthop")
                ET.SubElement(nexthop, "ip-address").text = route.nexthop
            intf = route.interface_panos or route.interface_fg
            if intf:
                ET.SubElement(entry, "interface").text = intf
            if route.distance != 10:
                ET.SubElement(entry, "metric").text = str(route.distance)


def _emit_ike_crypto_profiles(parent: ET.Element, config: PanoConfig):
    if not config.ike_crypto_profiles:
        return
    # network > ike > crypto-profiles > ike-crypto-profiles
    ike_el = _get_or_create(parent, "ike")
    cp_el = _get_or_create(ike_el, "crypto-profiles")
    profiles = ET.SubElement(cp_el, "ike-crypto-profiles")

    for prof in config.ike_crypto_profiles:
        entry = ET.SubElement(profiles, "entry", name=prof.name)
        _add_member_list(entry, "encryption", prof.encryption or ["aes-256-cbc"])
        _add_member_list(entry, "hash", prof.authentication or ["sha256"])
        _add_member_list(entry, "dh-group", prof.dh_group or ["group14"])
        lifetime = ET.SubElement(entry, "lifetime")
        ET.SubElement(lifetime, "seconds").text = str(prof.lifetime_seconds)


def _emit_ipsec_crypto_profiles(parent: ET.Element, config: PanoConfig):
    if not config.ipsec_crypto_profiles:
        return
    ike_el = _get_or_create(parent, "ike")
    cp_el = _get_or_create(ike_el, "crypto-profiles")
    profiles = ET.SubElement(cp_el, "ipsec-crypto-profiles")

    for prof in config.ipsec_crypto_profiles:
        entry = ET.SubElement(profiles, "entry", name=prof.name)
        esp_el = ET.SubElement(entry, "esp")
        _add_member_list(esp_el, "encryption", prof.encryption or ["aes-256-cbc"])
        _add_member_list(esp_el, "authentication", prof.authentication or ["sha256"])
        if prof.dh_group and prof.dh_group != "no-pfs":
            ET.SubElement(entry, "dh-group").text = prof.dh_group
        lifetime = ET.SubElement(entry, "lifetime")
        ET.SubElement(lifetime, "seconds").text = str(prof.lifetime_seconds)


def _emit_ike_gateways(parent: ET.Element, config: PanoConfig):
    if not config.ike_gateways:
        return
    ike_el = _get_or_create(parent, "ike")
    gw_el = ET.SubElement(ike_el, "gateway")

    for gw in config.ike_gateways:
        entry = ET.SubElement(gw_el, "entry", name=gw.name)
        ET.SubElement(entry, "protocol-common").text = ""

        # Peer address
        peer = ET.SubElement(entry, "peer-address")
        ET.SubElement(peer, "ip").text = gw.peer_address

        # Local interface
        if gw.interface:
            local_addr = ET.SubElement(entry, "local-address")
            ET.SubElement(local_addr, "interface").text = gw.interface

        # Authentication
        auth = ET.SubElement(entry, "authentication")
        psk_el = ET.SubElement(auth, "pre-shared-key")
        ET.SubElement(psk_el, "key").text = gw.psk

        # Crypto profile
        ET.SubElement(entry, "protocol").text = ""
        proto = entry.find("protocol")
        if proto is not None:
            proto.text = None
            ikev1 = ET.SubElement(proto, "ikev1")
            ET.SubElement(ikev1, "ike-crypto-profile").text = gw.crypto_profile

        # IKE version
        ver = ET.SubElement(entry, "protocol-common")
        ET.SubElement(ver, "fragmentation").text = ""

        # NAT traversal
        if gw.nat_traversal:
            ET.SubElement(entry, "nat-traversal").text = "yes"


def _emit_ipsec_tunnels(parent: ET.Element, config: PanoConfig):
    if not config.ipsec_tunnels:
        return
    tunnel_el = ET.SubElement(parent, "tunnel")
    ipsec_el = ET.SubElement(tunnel_el, "ipsec")

    for tun in config.ipsec_tunnels:
        entry = ET.SubElement(ipsec_el, "entry", name=tun.name)
        ET.SubElement(entry, "auto-key").text = ""
        ak = entry.find("auto-key")
        if ak is not None:
            ak.text = None
            # IKE gateway reference
            gw_list = ET.SubElement(ak, "ike-gateway")
            ET.SubElement(gw_list, "entry", name=tun.ike_gateway)
            # Crypto profile
            ET.SubElement(ak, "ipsec-crypto-profile").text = tun.crypto_profile

            # Proxy IDs
            if tun.proxy_ids:
                for pid in tun.proxy_ids:
                    pid_entry = ET.SubElement(ak, "proxy-id")
                    p = ET.SubElement(pid_entry, "entry", name=pid.get("name", "proxy-1"))
                    if pid.get("local"):
                        ET.SubElement(p, "local").text = pid["local"]
                    if pid.get("remote"):
                        ET.SubElement(p, "remote").text = pid["remote"]

        # Tunnel interface
        if tun.tunnel_interface:
            ET.SubElement(entry, "tunnel-interface").text = tun.tunnel_interface


def _get_or_create(parent: ET.Element, tag: str) -> ET.Element:
    """Get existing child element or create it."""
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    return el
