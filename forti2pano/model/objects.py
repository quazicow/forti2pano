"""Address and service object data models."""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional


class AddressType(Enum):
    IP_NETMASK = auto()
    IP_RANGE = auto()
    FQDN = auto()
    IP_WILDCARD = auto()
    GEOGRAPHY = auto()


@dataclass
class AddressObject:
    name: str
    addr_type: AddressType = AddressType.IP_NETMASK
    value: str = ""                         # "10.0.1.100/32" or "1.1.1.1-2.2.2.2" or "example.com"
    description: str = ""
    associated_interface: Optional[str] = None
    fg_original_name: str = ""


@dataclass
class AddressGroup:
    name: str
    members: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class ServiceObject:
    name: str
    protocol: str = "tcp"                   # "tcp", "udp", "tcp-udp", "icmp", "ip"
    dst_port: str = ""                      # "443" or "8000-8100"
    src_port: str = ""
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    protocol_number: Optional[int] = None   # for IP protocol services
    description: str = ""


@dataclass
class ServiceGroup:
    name: str
    members: List[str] = field(default_factory=list)
