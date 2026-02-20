"""VPN data models: IKE, IPSec, crypto profiles."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Phase1:
    """FortiGate phase1-interface parsed data."""
    name: str
    interface_fg: str = ""
    interface_panos: Optional[str] = None
    remote_gw: str = ""
    psk: str = "CHANGE_ME"
    proposals: List[str] = field(default_factory=list)   # ["aes256-sha256"]
    ike_version: int = 1
    mode: str = "main"
    dpd: str = "on-demand"
    dhgrp: List[int] = field(default_factory=lambda: [14])
    keylife: int = 86400
    local_id: str = ""
    peer_type: str = "any"
    nattraversal: str = "enable"


@dataclass
class Phase2:
    """FortiGate phase2-interface parsed data."""
    name: str
    phase1name: str = ""
    proposals: List[str] = field(default_factory=list)
    dhgrp: List[int] = field(default_factory=lambda: [14])
    src_subnet: Optional[str] = None
    dst_subnet: Optional[str] = None
    keylife_seconds: int = 43200
    pfs: bool = True


@dataclass
class IKECryptoProfile:
    """PAN-OS IKE Crypto Profile."""
    name: str
    encryption: List[str] = field(default_factory=list)
    authentication: List[str] = field(default_factory=list)
    dh_group: List[str] = field(default_factory=list)
    lifetime_seconds: int = 28800


@dataclass
class IPSecCryptoProfile:
    """PAN-OS IPSec Crypto Profile."""
    name: str
    encryption: List[str] = field(default_factory=list)
    authentication: List[str] = field(default_factory=list)
    dh_group: str = "group14"
    lifetime_seconds: int = 3600


@dataclass
class IKEGateway:
    """PAN-OS IKE Gateway."""
    name: str
    interface: str = ""
    peer_address: str = ""
    psk: str = "CHANGE_ME"
    crypto_profile: str = ""
    ike_version: str = "ikev1"
    local_id_type: Optional[str] = None
    local_id_value: Optional[str] = None
    nat_traversal: bool = True


@dataclass
class IPSecTunnel:
    """PAN-OS IPSec Tunnel."""
    name: str
    ike_gateway: str = ""
    crypto_profile: str = ""
    tunnel_interface: Optional[str] = None
    proxy_ids: List[dict] = field(default_factory=list)
