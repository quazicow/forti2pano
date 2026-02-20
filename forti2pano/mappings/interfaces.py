"""Heuristic mapping of FortiGate interface names to PAN-OS interface names."""

import re


def suggest_panos_interface(fg_name: str, iface_type: str = "physical") -> str:
    """Generate a best-effort PAN-OS interface name suggestion.

    These are always sent to the decision form for user confirmation.

    Heuristics:
        port1       -> ethernet1/1
        port2       -> ethernet1/2
        wan1        -> ethernet1/1
        wan2        -> ethernet1/2
        lan         -> ethernet1/3
        dmz         -> ethernet1/4
        internal    -> ethernet1/3
        vlan100     -> ethernet1/1.100  (subinterface)
        loopback0   -> loopback.1
        tunnel0     -> tunnel.1
        agg0        -> ae1
    """
    fg_lower = fg_name.lower()

    # portN -> ethernet1/N
    m = re.match(r'^port(\d+)$', fg_lower)
    if m:
        return f"ethernet1/{m.group(1)}"

    # wanN -> ethernet1/N
    m = re.match(r'^wan(\d+)$', fg_lower)
    if m:
        return f"ethernet1/{m.group(1)}"

    # lanN or lan -> ethernet1/N+2 (offset to not conflict with wan)
    m = re.match(r'^lan(\d+)?$', fg_lower)
    if m:
        num = int(m.group(1)) if m.group(1) else 1
        return f"ethernet1/{num + 2}"

    # internal -> ethernet1/3
    if fg_lower in ("internal", "internal0"):
        return "ethernet1/3"

    # dmz -> ethernet1/4
    if fg_lower in ("dmz", "dmz0"):
        return "ethernet1/4"

    # VLAN interfaces: vlanNNN or vlan-NNN or vlan_NNN
    m = re.match(r'^vlan[_\-]?(\d+)$', fg_lower)
    if m:
        return f"ethernet1/1.{m.group(1)}"

    # Loopback interfaces
    m = re.match(r'^(?:lo|loopback)(\d*)$', fg_lower)
    if m:
        num = int(m.group(1)) + 1 if m.group(1) else 1
        return f"loopback.{num}"

    # Tunnel interfaces
    m = re.match(r'^tunnel(\d*)$', fg_lower)
    if m:
        num = int(m.group(1)) + 1 if m.group(1) else 1
        return f"tunnel.{num}"

    # Aggregate interfaces
    m = re.match(r'^(?:agg|bond|ae)(\d+)$', fg_lower)
    if m:
        return f"ae{m.group(1)}"

    # No match - return placeholder
    return fg_name
