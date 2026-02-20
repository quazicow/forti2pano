"""Policy and NAT data models."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional


@dataclass
class SecurityPolicy:
    name: str
    fg_id: int = 0
    source_zones: List[str] = field(default_factory=list)
    dest_zones: List[str] = field(default_factory=list)
    source_addresses: List[str] = field(default_factory=list)
    dest_addresses: List[str] = field(default_factory=list)
    source_negate: bool = False
    dest_negate: bool = False
    services: List[str] = field(default_factory=list)
    action: str = "allow"
    log_start: bool = False
    log_end: bool = True
    application: List[str] = field(default_factory=lambda: ["any"])
    av_profile: Optional[str] = None
    ips_profile: Optional[str] = None
    url_filter_profile: Optional[str] = None
    file_blocking_profile: Optional[str] = None
    spyware_profile: Optional[str] = None
    vulnerability_profile: Optional[str] = None
    wildfire_profile: Optional[str] = None
    profile_group: Optional[str] = None
    schedule: str = ""
    enabled: bool = True
    description: str = ""
    # Original FortiGate interface references (before zone resolution)
    fg_srcintf: List[str] = field(default_factory=list)
    fg_dstintf: List[str] = field(default_factory=list)
    # NAT fields from FortiGate policy
    nat: bool = False
    ippool: bool = False
    poolname: List[str] = field(default_factory=list)


class NATType(Enum):
    DNAT = auto()
    DNAT_PORT_FORWARD = auto()
    SNAT_DYNAMIC = auto()
    SNAT_STATIC = auto()
    SNAT_INTERFACE = auto()


@dataclass
class VIP:
    name: str
    ext_ip: str = ""
    mapped_ip: str = ""
    ext_interface_fg: Optional[str] = None
    ext_interface_panos: Optional[str] = None
    port_forward: bool = False
    ext_port: Optional[str] = None
    mapped_port: Optional[str] = None
    protocol: str = "tcp"
    nat_type: str = "static-nat"


@dataclass
class IPPool:
    name: str
    start_ip: str = ""
    end_ip: str = ""
    pool_type: str = "overload"             # overload, one-to-one, fixed-port-range
    source_start_ip: Optional[str] = None
    source_end_ip: Optional[str] = None


@dataclass
class NATPolicy:
    """Resolved PAN-OS NAT rule."""
    name: str
    nat_type: NATType = NATType.DNAT
    from_zones: List[str] = field(default_factory=list)
    to_zones: List[str] = field(default_factory=list)
    source: List[str] = field(default_factory=lambda: ["any"])
    destination: List[str] = field(default_factory=list)
    service: str = "any"
    # DNAT fields
    dest_translated_address: Optional[str] = None
    dest_translated_port: Optional[str] = None
    # SNAT fields
    src_translated_type: Optional[str] = None
    src_translated_addresses: List[str] = field(default_factory=list)
    description: str = ""
