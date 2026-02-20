"""Section-specific extractors that read the parsed tree and produce model objects."""

import logging
from typing import Dict, Any, List

from ..model.config import PanoConfig
from ..model.network import Interface, Zone, StaticRoute
from ..model.objects import AddressObject, AddressGroup, AddressType, ServiceObject, ServiceGroup
from ..model.policy import SecurityPolicy, VIP, IPPool
from ..model.vpn import Phase1, Phase2
from ..util import fg_ip_mask_to_host_cidr, fg_subnet_to_cidr, sanitize_name, parse_fg_port_range, parse_fg_port_range_src
from ..defaults import FG_ACTION_TO_PANOS, FG_LOG_TO_PANOS
from .tree import get_section, get_entries, get_prop, get_prop_list

log = logging.getLogger(__name__)


def extract_addresses(tree: Dict[str, Any]) -> List[AddressObject]:
    """Extract from 'firewall address' section."""
    results = []
    section = get_section(tree, "firewall address")
    for name, entry in get_entries(section).items():
        addr_type_str = get_prop(entry, "type", "ipmask")
        obj = AddressObject(
            name=sanitize_name(name),
            fg_original_name=name,
        )

        if addr_type_str in ("ipmask", ""):
            subnet_vals = get_prop_list(entry, "subnet")
            if len(subnet_vals) >= 2:
                obj.addr_type = AddressType.IP_NETMASK
                obj.value = fg_ip_mask_to_host_cidr(subnet_vals[0], subnet_vals[1])
            else:
                # Some entries use 'set subnet' with CIDR directly
                ip = get_prop(entry, "ip")
                mask = get_prop(entry, "subnet")
                if ip and mask:
                    obj.addr_type = AddressType.IP_NETMASK
                    obj.value = fg_ip_mask_to_host_cidr(ip, mask)
                else:
                    log.warning(f"Address '{name}': cannot parse subnet, skipping")
                    continue

        elif addr_type_str == "iprange":
            start_ip = get_prop(entry, "start-ip")
            end_ip = get_prop(entry, "end-ip")
            if start_ip and end_ip:
                obj.addr_type = AddressType.IP_RANGE
                obj.value = f"{start_ip}-{end_ip}"
            else:
                log.warning(f"Address '{name}': iprange missing start/end, skipping")
                continue

        elif addr_type_str == "fqdn":
            fqdn = get_prop(entry, "fqdn")
            if fqdn:
                obj.addr_type = AddressType.FQDN
                obj.value = fqdn
            else:
                log.warning(f"Address '{name}': fqdn type but no fqdn value, skipping")
                continue

        elif addr_type_str == "geography":
            country = get_prop(entry, "country")
            if country:
                obj.addr_type = AddressType.GEOGRAPHY
                obj.value = country
            else:
                log.warning(f"Address '{name}': geography type but no country, skipping")
                continue

        elif addr_type_str == "wildcard":
            subnet_vals = get_prop_list(entry, "wildcard")
            if len(subnet_vals) >= 2:
                obj.addr_type = AddressType.IP_WILDCARD
                obj.value = f"{subnet_vals[0]}/{subnet_vals[1]}"
            else:
                log.warning(f"Address '{name}': wildcard type but no wildcard value, skipping")
                continue
        else:
            log.warning(f"Address '{name}': unknown type '{addr_type_str}', skipping")
            continue

        obj.description = get_prop(entry, "comment")
        obj.associated_interface = get_prop(entry, "associated-interface") or None
        results.append(obj)

    return results


def extract_address_groups(tree: Dict[str, Any]) -> List[AddressGroup]:
    """Extract from 'firewall addrgrp' section."""
    results = []
    section = get_section(tree, "firewall addrgrp")
    for name, entry in get_entries(section).items():
        members = [sanitize_name(m) for m in get_prop_list(entry, "member")]
        grp = AddressGroup(
            name=sanitize_name(name),
            members=members,
            description=get_prop(entry, "comment"),
        )
        results.append(grp)
    return results


def extract_services(tree: Dict[str, Any]) -> List[ServiceObject]:
    """Extract from 'firewall service custom' section."""
    results = []
    section = get_section(tree, "firewall service custom")
    for name, entry in get_entries(section).items():
        protocol = get_prop(entry, "protocol", "TCP/UDP/SCTP")

        if protocol in ("TCP/UDP/SCTP", ""):
            # Could have tcp-portrange, udp-portrange, or both
            tcp_range = get_prop(entry, "tcp-portrange")
            udp_range = get_prop(entry, "udp-portrange")

            if tcp_range and udp_range:
                # Create two service objects (TCP and UDP)
                svc_tcp = ServiceObject(
                    name=sanitize_name(f"{name}_tcp"),
                    protocol="tcp",
                    dst_port=parse_fg_port_range(tcp_range),
                    src_port=parse_fg_port_range_src(tcp_range),
                    description=get_prop(entry, "comment"),
                )
                svc_udp = ServiceObject(
                    name=sanitize_name(f"{name}_udp"),
                    protocol="udp",
                    dst_port=parse_fg_port_range(udp_range),
                    src_port=parse_fg_port_range_src(udp_range),
                    description=get_prop(entry, "comment"),
                )
                results.append(svc_tcp)
                results.append(svc_udp)
                continue
            elif tcp_range:
                svc = ServiceObject(
                    name=sanitize_name(name),
                    protocol="tcp",
                    dst_port=parse_fg_port_range(tcp_range),
                    src_port=parse_fg_port_range_src(tcp_range),
                    description=get_prop(entry, "comment"),
                )
            elif udp_range:
                svc = ServiceObject(
                    name=sanitize_name(name),
                    protocol="udp",
                    dst_port=parse_fg_port_range(udp_range),
                    src_port=parse_fg_port_range_src(udp_range),
                    description=get_prop(entry, "comment"),
                )
            else:
                # No port ranges defined, might be a catch-all
                svc = ServiceObject(
                    name=sanitize_name(name),
                    protocol="tcp",
                    description=get_prop(entry, "comment"),
                )
                log.warning(f"Service '{name}': no port range defined")

        elif protocol == "ICMP":
            svc = ServiceObject(
                name=sanitize_name(name),
                protocol="icmp",
                description=get_prop(entry, "comment"),
            )
            icmp_type = get_prop(entry, "icmptype")
            icmp_code = get_prop(entry, "icmpcode")
            if icmp_type:
                try:
                    svc.icmp_type = int(icmp_type)
                except ValueError:
                    pass
            if icmp_code:
                try:
                    svc.icmp_code = int(icmp_code)
                except ValueError:
                    pass

        elif protocol == "IP":
            proto_num = get_prop(entry, "protocol-number")
            svc = ServiceObject(
                name=sanitize_name(name),
                protocol="ip",
                description=get_prop(entry, "comment"),
            )
            if proto_num:
                try:
                    svc.protocol_number = int(proto_num)
                except ValueError:
                    pass
        else:
            log.warning(f"Service '{name}': unknown protocol '{protocol}', skipping")
            continue

        results.append(svc)

    return results


def extract_service_groups(tree: Dict[str, Any]) -> List[ServiceGroup]:
    """Extract from 'firewall service group' section."""
    results = []
    section = get_section(tree, "firewall service group")
    for name, entry in get_entries(section).items():
        members = [sanitize_name(m) for m in get_prop_list(entry, "member")]
        grp = ServiceGroup(
            name=sanitize_name(name),
            members=members,
        )
        results.append(grp)
    return results


def extract_interfaces(tree: Dict[str, Any]) -> List[Interface]:
    """Extract from 'system interface' section."""
    results = []
    section = get_section(tree, "system interface")
    for name, entry in get_entries(section).items():
        iface = Interface(fg_name=name)
        iface.vdom = get_prop(entry, "vdom", "root")
        iface.alias = get_prop(entry, "alias")
        iface.interface_type = get_prop(entry, "type", "physical")
        iface.description = get_prop(entry, "description")

        # IP address: 'set ip 10.0.1.1 255.255.255.0'
        ip_vals = get_prop_list(entry, "ip")
        if len(ip_vals) >= 2 and ip_vals[0] != "0.0.0.0":
            from ..util import fg_mask_to_cidr
            iface.ip_address = fg_mask_to_cidr(ip_vals[0], ip_vals[1])

        # VLAN ID
        vlanid = get_prop(entry, "vlanid")
        if vlanid:
            try:
                iface.vlan_id = int(vlanid)
            except ValueError:
                pass

        # MTU
        mtu = get_prop(entry, "mtu")
        if mtu:
            try:
                iface.mtu = int(mtu)
            except ValueError:
                pass

        results.append(iface)

    return results


def extract_zones(tree: Dict[str, Any]) -> List[Zone]:
    """Extract from 'system zone' section."""
    results = []
    section = get_section(tree, "system zone")
    for name, entry in get_entries(section).items():
        interfaces = get_prop_list(entry, "interface")
        zone = Zone(
            name=name,
            interfaces_fg=interfaces,
        )
        results.append(zone)
    return results


def extract_static_routes(tree: Dict[str, Any]) -> List[StaticRoute]:
    """Extract from 'router static' section."""
    results = []
    section = get_section(tree, "router static")
    for edit_id, entry in get_entries(section).items():
        route = StaticRoute(name=f"route-{edit_id}")

        # Destination: 'set dst 10.0.2.0 255.255.255.0'
        dst_vals = get_prop_list(entry, "dst")
        if len(dst_vals) >= 2:
            route.destination = fg_subnet_to_cidr(dst_vals[0], dst_vals[1])
        else:
            route.destination = "0.0.0.0/0"

        # Gateway
        gateway = get_prop(entry, "gateway")
        if gateway:
            route.nexthop = gateway

        # Device (interface)
        device = get_prop(entry, "device")
        if device:
            route.interface_fg = device

        # Distance
        distance = get_prop(entry, "distance")
        if distance:
            try:
                route.distance = int(distance)
            except ValueError:
                pass

        # Priority
        priority = get_prop(entry, "priority")
        if priority:
            try:
                route.priority = int(priority)
            except ValueError:
                pass

        results.append(route)

    return results


def extract_policies(tree: Dict[str, Any]) -> List[SecurityPolicy]:
    """Extract from 'firewall policy' section."""
    results = []
    section = get_section(tree, "firewall policy")
    for edit_id, entry in get_entries(section).items():
        try:
            fg_id = int(edit_id)
        except ValueError:
            fg_id = 0

        pol = SecurityPolicy(
            name=f"Rule-{edit_id}",
            fg_id=fg_id,
        )

        # Source/dest interfaces
        pol.fg_srcintf = get_prop_list(entry, "srcintf")
        pol.fg_dstintf = get_prop_list(entry, "dstintf")

        # Source/dest addresses
        pol.source_addresses = [sanitize_name(a) for a in get_prop_list(entry, "srcaddr")]
        pol.dest_addresses = [sanitize_name(a) for a in get_prop_list(entry, "dstaddr")]

        # Negate
        pol.source_negate = get_prop(entry, "srcaddr-negate") == "enable"
        pol.dest_negate = get_prop(entry, "dstaddr-negate") == "enable"

        # Services
        pol.services = get_prop_list(entry, "service")

        # Action
        fg_action = get_prop(entry, "action", "accept")
        pol.action = FG_ACTION_TO_PANOS.get(fg_action, "allow")

        # Schedule
        pol.schedule = get_prop(entry, "schedule", "always")

        # Logging
        logtraffic = get_prop(entry, "logtraffic", "utm")
        log_start, log_end = FG_LOG_TO_PANOS.get(logtraffic, ("no", "yes"))
        pol.log_start = log_start == "yes"
        pol.log_end = log_end == "yes"

        # Status
        pol.enabled = get_prop(entry, "status", "enable") == "enable"

        # Description / comments
        pol.description = get_prop(entry, "comments")
        if not pol.description:
            pol.description = get_prop(entry, "name")

        # Security profiles
        pol.av_profile = get_prop(entry, "av-profile") or None
        pol.ips_profile = get_prop(entry, "ips-sensor") or None
        pol.url_filter_profile = get_prop(entry, "webfilter-profile") or None
        pol.file_blocking_profile = get_prop(entry, "file-filter-profile") or None
        pol.spyware_profile = get_prop(entry, "spamfilter-profile") or None
        pol.wildfire_profile = get_prop(entry, "waf-profile") or None
        pol.profile_group = get_prop(entry, "profile-group") or None

        # Application list (FortiGate app control)
        app_list = get_prop(entry, "application-list")
        if app_list:
            pol.application = [app_list]

        # NAT
        pol.nat = get_prop(entry, "nat") == "enable"
        pol.ippool = get_prop(entry, "ippool") == "enable"
        pol.poolname = get_prop_list(entry, "poolname")

        results.append(pol)

    return results


def extract_vips(tree: Dict[str, Any]) -> List[VIP]:
    """Extract from 'firewall vip' section."""
    results = []
    section = get_section(tree, "firewall vip")
    for name, entry in get_entries(section).items():
        vip = VIP(name=sanitize_name(name))

        vip.ext_ip = get_prop(entry, "extip")
        # mappedip can be a range: "10.0.1.100" or "10.0.1.100-10.0.1.105"
        mapped_vals = get_prop_list(entry, "mappedip")
        if mapped_vals:
            vip.mapped_ip = mapped_vals[0].strip('"')

        vip.ext_interface_fg = get_prop(entry, "extintf") or None
        vip.port_forward = get_prop(entry, "portforward") == "enable"

        if vip.port_forward:
            vip.ext_port = get_prop(entry, "extport")
            vip.mapped_port = get_prop(entry, "mappedport")
            protocol = get_prop(entry, "protocol")
            if protocol:
                # FortiGate protocol numbers: 6=tcp, 17=udp
                if protocol == "6" or protocol.lower() == "tcp":
                    vip.protocol = "tcp"
                elif protocol == "17" or protocol.lower() == "udp":
                    vip.protocol = "udp"

        vip.nat_type = get_prop(entry, "type", "static-nat")
        results.append(vip)

    return results


def extract_ip_pools(tree: Dict[str, Any]) -> List[IPPool]:
    """Extract from 'firewall ippool' section."""
    results = []
    section = get_section(tree, "firewall ippool")
    for name, entry in get_entries(section).items():
        pool = IPPool(name=sanitize_name(name))
        pool.start_ip = get_prop(entry, "startip")
        pool.end_ip = get_prop(entry, "endip")
        pool.pool_type = get_prop(entry, "type", "overload")

        src_start = get_prop(entry, "source-startip")
        src_end = get_prop(entry, "source-endip")
        if src_start:
            pool.source_start_ip = src_start
        if src_end:
            pool.source_end_ip = src_end

        results.append(pool)

    return results


def extract_phase1(tree: Dict[str, Any]) -> List[Phase1]:
    """Extract from 'vpn ipsec phase1-interface' section."""
    results = []
    section = get_section(tree, "vpn ipsec phase1-interface")
    for name, entry in get_entries(section).items():
        p1 = Phase1(name=name)
        p1.interface_fg = get_prop(entry, "interface")
        p1.remote_gw = get_prop(entry, "remote-gw")
        p1.peer_type = get_prop(entry, "peertype", "any")

        # Proposals: can be space-separated list
        proposals = get_prop_list(entry, "proposal")
        if proposals:
            p1.proposals = proposals

        # IKE version
        ike_ver = get_prop(entry, "ike-version")
        if ike_ver:
            try:
                p1.ike_version = int(ike_ver)
            except ValueError:
                pass

        # Mode
        p1.mode = get_prop(entry, "mode", "main")

        # DH groups
        dhgrp = get_prop_list(entry, "dhgrp")
        if dhgrp:
            p1.dhgrp = []
            for g in dhgrp:
                try:
                    p1.dhgrp.append(int(g))
                except ValueError:
                    pass

        # Keylife
        keylife = get_prop(entry, "keylife")
        if keylife:
            try:
                p1.keylife = int(keylife)
            except ValueError:
                pass

        # PSK - will be encrypted in config, store as placeholder
        psk = get_prop(entry, "psksecret")
        if psk:
            if psk.startswith("ENC"):
                p1.psk = "CHANGE_ME"
            else:
                p1.psk = psk

        # Local ID
        p1.local_id = get_prop(entry, "localid")

        # DPD
        p1.dpd = get_prop(entry, "dpd", "on-demand")

        # NAT traversal
        p1.nattraversal = get_prop(entry, "nattraversal", "enable")

        results.append(p1)

    return results


def extract_phase2(tree: Dict[str, Any]) -> List[Phase2]:
    """Extract from 'vpn ipsec phase2-interface' section."""
    results = []
    section = get_section(tree, "vpn ipsec phase2-interface")
    for name, entry in get_entries(section).items():
        p2 = Phase2(name=name)
        p2.phase1name = get_prop(entry, "phase1name")

        proposals = get_prop_list(entry, "proposal")
        if proposals:
            p2.proposals = proposals

        # DH groups
        dhgrp = get_prop_list(entry, "dhgrp")
        if dhgrp:
            p2.dhgrp = []
            for g in dhgrp:
                try:
                    p2.dhgrp.append(int(g))
                except ValueError:
                    pass

        # Subnets
        src_vals = get_prop_list(entry, "src-subnet")
        if len(src_vals) >= 2:
            p2.src_subnet = fg_subnet_to_cidr(src_vals[0], src_vals[1])

        dst_vals = get_prop_list(entry, "dst-subnet")
        if len(dst_vals) >= 2:
            p2.dst_subnet = fg_subnet_to_cidr(dst_vals[0], dst_vals[1])

        # Keylife
        keylife = get_prop(entry, "keylifeseconds")
        if keylife:
            try:
                p2.keylife_seconds = int(keylife)
            except ValueError:
                pass

        # PFS
        pfs = get_prop(entry, "pfs")
        p2.pfs = pfs != "disable"

        results.append(p2)

    return results


def extract_hostname(tree: Dict[str, Any]) -> str:
    """Extract hostname from 'system global' or 'system settings'."""
    # config system global (no edit, just set statements)
    section = get_section(tree, "system global")
    props = section.get("_props", {})
    hostname_vals = props.get("hostname", [])
    if hostname_vals:
        return hostname_vals[0]
    return ""


def extract_all(tree: Dict[str, Any]) -> PanoConfig:
    """Run all extractors and return a populated PanoConfig."""
    config = PanoConfig()

    config.hostname = extract_hostname(tree)
    config.addresses = extract_addresses(tree)
    config.address_groups = extract_address_groups(tree)
    config.services = extract_services(tree)
    config.service_groups = extract_service_groups(tree)
    config.interfaces = extract_interfaces(tree)
    config.zones = extract_zones(tree)
    config.static_routes = extract_static_routes(tree)
    config.security_policies = extract_policies(tree)
    config.vips = extract_vips(tree)
    config.ip_pools = extract_ip_pools(tree)
    config.phase1_list = extract_phase1(tree)
    config.phase2_list = extract_phase2(tree)

    # Assign interfaces to zones based on zone membership
    _resolve_interface_zones(config)

    log.info(
        f"Extracted: {len(config.addresses)} addresses, "
        f"{len(config.address_groups)} address groups, "
        f"{len(config.services)} services, "
        f"{len(config.service_groups)} service groups, "
        f"{len(config.interfaces)} interfaces, "
        f"{len(config.zones)} zones, "
        f"{len(config.static_routes)} routes, "
        f"{len(config.security_policies)} policies, "
        f"{len(config.vips)} VIPs, "
        f"{len(config.ip_pools)} IP pools, "
        f"{len(config.phase1_list)} VPN phase1, "
        f"{len(config.phase2_list)} VPN phase2"
    )

    return config


def _resolve_interface_zones(config: PanoConfig):
    """Set the zone field on each Interface based on zone membership."""
    # Build a lookup: fg_interface_name -> zone_name
    intf_to_zone = {}
    for zone in config.zones:
        for intf_name in zone.interfaces_fg:
            intf_to_zone[intf_name] = zone.name

    for iface in config.interfaces:
        if iface.fg_name in intf_to_zone:
            iface.zone = intf_to_zone[iface.fg_name]
