"""Network object data models: interfaces, zones, routes."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Interface:
    fg_name: str
    panos_name: Optional[str] = None
    ip_address: Optional[str] = None        # CIDR: "10.0.1.1/24"
    vdom: str = "root"
    interface_type: str = "physical"        # physical, vlan, loopback, aggregate, tunnel
    alias: str = ""
    vlan_id: Optional[int] = None
    zone: Optional[str] = None
    description: str = ""
    mtu: Optional[int] = None


@dataclass
class Zone:
    name: str
    interfaces_fg: List[str] = field(default_factory=list)
    interfaces_panos: List[str] = field(default_factory=list)


@dataclass
class StaticRoute:
    name: str
    destination: str = "0.0.0.0/0"
    nexthop: Optional[str] = None
    interface_fg: Optional[str] = None
    interface_panos: Optional[str] = None
    distance: int = 10
    priority: int = 0
    virtual_router: str = "default"
