"""Analyze parsed config and generate decision items for untranslatable elements."""

import datetime
import logging
from typing import Set

from ..model.config import PanoConfig
from ..mappings.interfaces import suggest_panos_interface
from ..mappings.services import is_predefined_fg_service, FG_TO_PANOS_SERVICE
from .schema import DecisionForm, DecisionItem

log = logging.getLogger(__name__)


def generate_decisions(config: PanoConfig, source_file: str = "") -> DecisionForm:
    """Analyze the parsed config and produce decision items for the user."""
    form = DecisionForm()
    form.metadata = {
        "source_file": source_file,
        "generated_at": datetime.datetime.now().isoformat(),
        "forti2pano_version": "0.1.0",
    }

    _gen_interface_decisions(config, form)
    _gen_zone_decisions(config, form)
    _gen_policy_zone_decisions(config, form)
    _gen_security_profile_decisions(config, form)
    _gen_vpn_tunnel_decisions(config, form)
    _gen_service_ambiguity_decisions(config, form)

    log.info(f"Generated {len(form.items)} decision items")
    return form


def _gen_interface_decisions(config: PanoConfig, form: DecisionForm):
    """Generate decisions for FortiGate -> PAN-OS interface name mapping."""
    for iface in config.interfaces:
        if iface.panos_name is not None:
            continue

        suggestion = suggest_panos_interface(iface.fg_name, iface.interface_type)

        desc_parts = [f"Map FortiGate interface '{iface.fg_name}'"]
        if iface.alias:
            desc_parts.append(f"(alias='{iface.alias}')")
        if iface.ip_address:
            desc_parts.append(f"ip={iface.ip_address}")
        desc_parts.append(f"type={iface.interface_type}")
        desc_parts.append(f"to a PAN-OS interface name.")

        form.items.append(DecisionItem(
            id=f"intf_{iface.fg_name}",
            category="interface_mapping",
            description=" ".join(desc_parts),
            fg_value=iface.fg_name,
            suggested_value=suggestion,
            required=True,
        ))


def _gen_zone_decisions(config: PanoConfig, form: DecisionForm):
    """Generate decisions for zone name confirmation."""
    for zone in config.zones:
        intf_list = ", ".join(zone.interfaces_fg)
        form.items.append(DecisionItem(
            id=f"zone_{zone.name}",
            category="zone_confirmation",
            description=(
                f"FortiGate zone '{zone.name}' contains interfaces [{intf_list}]. "
                f"Confirm the PAN-OS zone name to use."
            ),
            fg_value=f"{zone.name} [{intf_list}]",
            suggested_value=zone.name,
            required=False,
        ))

    # Check for interfaces that are NOT in any zone - they need synthetic zones
    zone_intfs: Set[str] = set()
    for zone in config.zones:
        zone_intfs.update(zone.interfaces_fg)

    for iface in config.interfaces:
        if iface.fg_name not in zone_intfs:
            # Check if this interface is actually referenced in policies
            referenced = False
            for pol in config.security_policies:
                if iface.fg_name in pol.fg_srcintf or iface.fg_name in pol.fg_dstintf:
                    referenced = True
                    break
            if not referenced:
                continue

            zone_name = iface.alias if iface.alias else iface.fg_name
            form.items.append(DecisionItem(
                id=f"zone_synth_{iface.fg_name}",
                category="zone_confirmation",
                description=(
                    f"Interface '{iface.fg_name}' is used in policies but not assigned "
                    f"to any FortiGate zone. Provide a PAN-OS zone name for it."
                ),
                fg_value=iface.fg_name,
                suggested_value=zone_name,
                required=True,
            ))


def _gen_policy_zone_decisions(config: PanoConfig, form: DecisionForm):
    """Check for 'any' interface in policies which needs zone mapping."""
    has_any_src = any("any" in p.fg_srcintf for p in config.security_policies)
    has_any_dst = any("any" in p.fg_dstintf for p in config.security_policies)

    if has_any_src or has_any_dst:
        form.items.append(DecisionItem(
            id="zone_any_interface",
            category="zone_confirmation",
            description=(
                "Some policies use 'any' as source/destination interface. "
                "In PAN-OS, this maps to 'any' zone. Confirm this is correct, "
                "or provide a specific zone name."
            ),
            fg_value="any",
            suggested_value="any",
            required=False,
        ))


def _gen_security_profile_decisions(config: PanoConfig, form: DecisionForm):
    """Generate decisions for security profile mapping."""
    # Collect unique profiles referenced across all policies
    seen_av = set()
    seen_ips = set()
    seen_url = set()
    seen_groups = set()

    for pol in config.security_policies:
        if pol.av_profile and pol.av_profile not in seen_av:
            seen_av.add(pol.av_profile)
            form.items.append(DecisionItem(
                id=f"profile_av_{pol.av_profile}",
                category="security_profile",
                description=(
                    f"FortiGate AV profile '{pol.av_profile}' is referenced in policies. "
                    f"Provide the PAN-OS Antivirus profile name to map to, "
                    f"or leave blank to omit."
                ),
                fg_value=pol.av_profile,
                suggested_value="default",
                required=False,
            ))

        if pol.ips_profile and pol.ips_profile not in seen_ips:
            seen_ips.add(pol.ips_profile)
            form.items.append(DecisionItem(
                id=f"profile_ips_{pol.ips_profile}",
                category="security_profile",
                description=(
                    f"FortiGate IPS sensor '{pol.ips_profile}' is referenced in policies. "
                    f"Provide the PAN-OS Vulnerability Protection profile name, "
                    f"or leave blank to omit."
                ),
                fg_value=pol.ips_profile,
                suggested_value="strict",
                required=False,
            ))

        if pol.url_filter_profile and pol.url_filter_profile not in seen_url:
            seen_url.add(pol.url_filter_profile)
            form.items.append(DecisionItem(
                id=f"profile_url_{pol.url_filter_profile}",
                category="security_profile",
                description=(
                    f"FortiGate web filter profile '{pol.url_filter_profile}' is referenced. "
                    f"Provide the PAN-OS URL Filtering profile name, "
                    f"or leave blank to omit."
                ),
                fg_value=pol.url_filter_profile,
                suggested_value="default",
                required=False,
            ))

        if pol.profile_group and pol.profile_group not in seen_groups:
            seen_groups.add(pol.profile_group)
            form.items.append(DecisionItem(
                id=f"profile_group_{pol.profile_group}",
                category="security_profile",
                description=(
                    f"FortiGate profile group '{pol.profile_group}' is referenced. "
                    f"Provide the PAN-OS security profile group name, "
                    f"or leave blank to use individual profiles."
                ),
                fg_value=pol.profile_group,
                suggested_value=pol.profile_group,
                required=False,
            ))


def _gen_vpn_tunnel_decisions(config: PanoConfig, form: DecisionForm):
    """Generate decisions for VPN tunnel interface assignment."""
    for i, p1 in enumerate(config.phase1_list):
        form.items.append(DecisionItem(
            id=f"vpn_tunnel_intf_{p1.name}",
            category="vpn_tunnel_interface",
            description=(
                f"VPN '{p1.name}' (remote-gw={p1.remote_gw}, "
                f"interface={p1.interface_fg}) needs a PAN-OS tunnel interface."
            ),
            fg_value=p1.name,
            suggested_value=f"tunnel.{i + 1}",
            required=True,
        ))

    # PSK warning - not a decision, but add an informational item
    for p1 in config.phase1_list:
        if p1.psk == "CHANGE_ME":
            form.items.append(DecisionItem(
                id=f"vpn_psk_{p1.name}",
                category="vpn_tunnel_interface",
                description=(
                    f"VPN '{p1.name}' pre-shared key is encrypted in the FortiGate config "
                    f"and cannot be extracted. Enter the PSK here or change it on the "
                    f"PAN-OS device after import."
                ),
                fg_value="(encrypted)",
                suggested_value="CHANGE_ME",
                required=False,
            ))


def _gen_service_ambiguity_decisions(config: PanoConfig, form: DecisionForm):
    """Generate decisions for ambiguous service objects."""
    for svc in config.services:
        if svc.protocol == "ip" and svc.protocol_number is not None:
            form.items.append(DecisionItem(
                id=f"svc_proto_{svc.name}",
                category="service_ambiguity",
                description=(
                    f"Service '{svc.name}' uses IP protocol number {svc.protocol_number}. "
                    f"PAN-OS does not directly support protocol-number service objects. "
                    f"Provide an application name or use 'any'."
                ),
                fg_value=f"protocol-number {svc.protocol_number}",
                suggested_value="any",
                required=False,
            ))

    # Check for predefined FortiGate services used in policies that
    # don't have a direct PAN-OS mapping
    seen = set()
    for pol in config.security_policies:
        for svc_name in pol.services:
            if svc_name in seen:
                continue
            seen.add(svc_name)
            if is_predefined_fg_service(svc_name):
                panos_mapping = FG_TO_PANOS_SERVICE.get(svc_name)
                if panos_mapping is None:
                    # Will auto-create a custom service, but flag it
                    from ..mappings.services import get_predefined_service_def
                    defn = get_predefined_service_def(svc_name)
                    if defn is None:
                        form.items.append(DecisionItem(
                            id=f"svc_predef_{svc_name}",
                            category="service_ambiguity",
                            description=(
                                f"FortiGate predefined service '{svc_name}' has no known "
                                f"PAN-OS equivalent and no port definition available. "
                                f"Provide port info (e.g., 'tcp/443') or use 'any'."
                            ),
                            fg_value=svc_name,
                            suggested_value="any",
                            required=False,
                        ))
