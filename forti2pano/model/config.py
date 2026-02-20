"""Top-level configuration container."""

from dataclasses import dataclass, field
from typing import List

from . import network, objects, policy, vpn


@dataclass
class PanoConfig:
    """Holds everything extracted from a FortiGate config, ready for emission."""

    # Objects
    addresses: List[objects.AddressObject] = field(default_factory=list)
    address_groups: List[objects.AddressGroup] = field(default_factory=list)
    services: List[objects.ServiceObject] = field(default_factory=list)
    service_groups: List[objects.ServiceGroup] = field(default_factory=list)

    # Network
    interfaces: List[network.Interface] = field(default_factory=list)
    zones: List[network.Zone] = field(default_factory=list)
    static_routes: List[network.StaticRoute] = field(default_factory=list)

    # Policy
    security_policies: List[policy.SecurityPolicy] = field(default_factory=list)
    vips: List[policy.VIP] = field(default_factory=list)
    ip_pools: List[policy.IPPool] = field(default_factory=list)
    nat_policies: List[policy.NATPolicy] = field(default_factory=list)

    # VPN
    phase1_list: List[vpn.Phase1] = field(default_factory=list)
    phase2_list: List[vpn.Phase2] = field(default_factory=list)
    ike_crypto_profiles: List[vpn.IKECryptoProfile] = field(default_factory=list)
    ipsec_crypto_profiles: List[vpn.IPSecCryptoProfile] = field(default_factory=list)
    ike_gateways: List[vpn.IKEGateway] = field(default_factory=list)
    ipsec_tunnels: List[vpn.IPSecTunnel] = field(default_factory=list)

    # Metadata
    vsys: str = "vsys1"
    virtual_router: str = "default"
    device_name: str = "localhost.localdomain"
    hostname: str = ""
    vdom: str = "root"
