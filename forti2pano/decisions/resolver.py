"""Apply user decisions back into the intermediate model."""

import logging
from typing import Dict

from ..model.config import PanoConfig
from .schema import DecisionForm, DecisionItem

log = logging.getLogger(__name__)


def apply_decisions(config: PanoConfig, form: DecisionForm) -> PanoConfig:
    """Apply resolved decisions to the model, updating interface names,
    zone assignments, profile mappings, and VPN tunnel interfaces."""

    decisions: Dict[str, DecisionItem] = {item.id: item for item in form.items}

    _apply_interface_mappings(config, decisions)
    _apply_zone_decisions(config, decisions)
    _apply_route_interfaces(config, decisions)
    _apply_policy_zones(config, decisions)
    _apply_security_profiles(config, decisions)
    _apply_vip_interfaces(config, decisions)
    _apply_vpn_decisions(config, decisions)

    return config


def _get_resolved(decisions: Dict[str, DecisionItem], key: str) -> str:
    """Get the resolved value for a decision key, or empty string."""
    item = decisions.get(key)
    if item is None:
        return ""
    return item.resolved_value() or ""


def _apply_interface_mappings(config: PanoConfig, decisions: Dict[str, DecisionItem]):
    """Apply interface name mappings from decisions."""
    intf_map: Dict[str, str] = {}

    for iface in config.interfaces:
        key = f"intf_{iface.fg_name}"
        panos_name = _get_resolved(decisions, key)
        if panos_name:
            iface.panos_name = panos_name
            intf_map[iface.fg_name] = panos_name

    # Store the mapping for use by other resolvers
    config._intf_map = intf_map  # type: ignore


def _apply_zone_decisions(config: PanoConfig, decisions: Dict[str, DecisionItem]):
    """Apply zone name decisions and resolve PAN-OS interface names in zones."""
    intf_map = getattr(config, '_intf_map', {})

    for zone in config.zones:
        key = f"zone_{zone.name}"
        zone_name = _get_resolved(decisions, key)
        if zone_name:
            zone.name = zone_name
        # Resolve PAN-OS interface names
        zone.interfaces_panos = [
            intf_map.get(fg, fg) for fg in zone.interfaces_fg
        ]

    # Handle synthetic zones for interfaces not in any zone
    for iface in config.interfaces:
        key = f"zone_synth_{iface.fg_name}"
        zone_name = _get_resolved(decisions, key)
        if zone_name:
            iface.zone = zone_name
            # Also create the zone in the config if it doesn't exist
            existing_names = {z.name for z in config.zones}
            if zone_name not in existing_names:
                from ..model.network import Zone
                panos_name = intf_map.get(iface.fg_name, iface.fg_name)
                config.zones.append(Zone(
                    name=zone_name,
                    interfaces_fg=[iface.fg_name],
                    interfaces_panos=[panos_name],
                ))

    # Rebuild interface zone assignments
    for zone in config.zones:
        for fg_intf in zone.interfaces_fg:
            for iface in config.interfaces:
                if iface.fg_name == fg_intf:
                    iface.zone = zone.name


def _apply_route_interfaces(config: PanoConfig, decisions: Dict[str, DecisionItem]):
    """Resolve PAN-OS interface names in static routes."""
    intf_map = getattr(config, '_intf_map', {})
    for route in config.static_routes:
        if route.interface_fg:
            route.interface_panos = intf_map.get(route.interface_fg, route.interface_fg)


def _apply_policy_zones(config: PanoConfig, decisions: Dict[str, DecisionItem]):
    """Resolve zones in security policies from interface names."""
    # Build interface-to-zone lookup
    intf_to_zone: Dict[str, str] = {}
    for zone in config.zones:
        for fg_intf in zone.interfaces_fg:
            intf_to_zone[fg_intf] = zone.name

    # Also check per-interface zone from synthetic zone decisions
    for iface in config.interfaces:
        if iface.zone and iface.fg_name not in intf_to_zone:
            intf_to_zone[iface.fg_name] = iface.zone

    for pol in config.security_policies:
        # Resolve source zones
        pol.source_zones = []
        for fg_intf in pol.fg_srcintf:
            if fg_intf == "any":
                pol.source_zones.append("any")
            elif fg_intf in intf_to_zone:
                zone_name = intf_to_zone[fg_intf]
                if zone_name not in pol.source_zones:
                    pol.source_zones.append(zone_name)
            else:
                # Interface not in any zone - use interface name as zone
                log.warning(f"Policy '{pol.name}': srcintf '{fg_intf}' has no zone, using as-is")
                pol.source_zones.append(fg_intf)

        # Resolve dest zones
        pol.dest_zones = []
        for fg_intf in pol.fg_dstintf:
            if fg_intf == "any":
                pol.dest_zones.append("any")
            elif fg_intf in intf_to_zone:
                zone_name = intf_to_zone[fg_intf]
                if zone_name not in pol.dest_zones:
                    pol.dest_zones.append(zone_name)
            else:
                log.warning(f"Policy '{pol.name}': dstintf '{fg_intf}' has no zone, using as-is")
                pol.dest_zones.append(fg_intf)

        if not pol.source_zones:
            pol.source_zones = ["any"]
        if not pol.dest_zones:
            pol.dest_zones = ["any"]


def _apply_security_profiles(config: PanoConfig, decisions: Dict[str, DecisionItem]):
    """Map FortiGate security profiles to PAN-OS profile names."""
    # Build profile mappings from decisions
    av_map: Dict[str, str] = {}
    ips_map: Dict[str, str] = {}
    url_map: Dict[str, str] = {}
    group_map: Dict[str, str] = {}

    for item in decisions.values():
        if item.category != "security_profile":
            continue
        val = item.resolved_value()
        if not val:
            continue
        if item.id.startswith("profile_av_"):
            fg_name = item.fg_value
            av_map[fg_name] = val
        elif item.id.startswith("profile_ips_"):
            fg_name = item.fg_value
            ips_map[fg_name] = val
        elif item.id.startswith("profile_url_"):
            fg_name = item.fg_value
            url_map[fg_name] = val
        elif item.id.startswith("profile_group_"):
            fg_name = item.fg_value
            group_map[fg_name] = val

    for pol in config.security_policies:
        if pol.av_profile:
            pol.av_profile = av_map.get(pol.av_profile, pol.av_profile)
        if pol.ips_profile:
            mapped = ips_map.get(pol.ips_profile)
            if mapped:
                pol.vulnerability_profile = mapped
            pol.ips_profile = None  # PAN-OS uses vulnerability_profile
        if pol.url_filter_profile:
            pol.url_filter_profile = url_map.get(pol.url_filter_profile, pol.url_filter_profile)
        if pol.profile_group:
            pol.profile_group = group_map.get(pol.profile_group, pol.profile_group)


def _apply_vip_interfaces(config: PanoConfig, decisions: Dict[str, DecisionItem]):
    """Resolve PAN-OS interface names in VIPs."""
    intf_map = getattr(config, '_intf_map', {})
    for vip in config.vips:
        if vip.ext_interface_fg:
            vip.ext_interface_panos = intf_map.get(vip.ext_interface_fg, vip.ext_interface_fg)


def _apply_vpn_decisions(config: PanoConfig, decisions: Dict[str, DecisionItem]):
    """Apply VPN tunnel interface and PSK decisions."""
    intf_map = getattr(config, '_intf_map', {})

    for p1 in config.phase1_list:
        # Tunnel interface
        key = f"vpn_tunnel_intf_{p1.name}"
        tunnel_intf = _get_resolved(decisions, key)
        if tunnel_intf:
            p1.interface_panos = tunnel_intf

        # PSK
        key = f"vpn_psk_{p1.name}"
        psk = _get_resolved(decisions, key)
        if psk and psk != "CHANGE_ME":
            p1.psk = psk

        # Also map the WAN interface
        if p1.interface_fg:
            p1.interface_panos = p1.interface_panos or intf_map.get(p1.interface_fg, p1.interface_fg)
