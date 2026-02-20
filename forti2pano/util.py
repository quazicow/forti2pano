"""Utility functions for IP conversion, name sanitization, and logging."""

import ipaddress
import logging
import re


class FortiParseError(Exception):
    """Raised for unrecoverable FortiGate parsing errors."""

    def __init__(self, message: str, line_num: int = 0):
        self.line_num = line_num
        super().__init__(f"Line {line_num}: {message}" if line_num else message)


class DecisionValidationError(Exception):
    """Raised when required decisions are missing or invalid."""

    def __init__(self, errors: list):
        self.errors = errors
        super().__init__(f"{len(errors)} decision validation error(s)")


def fg_mask_to_cidr(ip_str: str, mask_str: str) -> str:
    """Convert FortiGate 'IP MASK' to CIDR notation.

    Example: fg_mask_to_cidr('10.0.1.1', '255.255.255.0') -> '10.0.1.1/24'
    """
    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
    return f"{ip_str}/{net.prefixlen}"


def fg_subnet_to_cidr(ip_str: str, mask_str: str) -> str:
    """Convert FortiGate subnet to network CIDR.

    Example: fg_subnet_to_cidr('10.0.1.0', '255.255.255.0') -> '10.0.1.0/24'
    """
    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
    return str(net)


def fg_ip_mask_to_host_cidr(ip_str: str, mask_str: str) -> str:
    """Convert FortiGate address entry to CIDR.

    For host addresses (255.255.255.255), returns /32.
    For subnets, returns the network address with prefix.
    """
    if mask_str == "255.255.255.255":
        return f"{ip_str}/32"
    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
    return str(net)


def sanitize_name(name: str, max_len: int = 63) -> str:
    """Ensure name is valid for PAN-OS.

    PAN-OS object names: max 63 chars, alphanumeric plus - _ .
    Spaces and other special chars replaced with underscores.
    """
    name = re.sub(r'[^\w\-.]', '_', name)
    if name and name[0].isdigit():
        name = f"obj_{name}"
    return name[:max_len]


def setup_logging(verbose: bool = False):
    """Configure logging for the converter."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def parse_fg_port_range(port_str: str) -> str:
    """Parse FortiGate port range notation to PAN-OS format.

    FortiGate: '8443' or '8000-8100' or '8443:0-65535' (dst:src)
    PAN-OS: '8443' or '8000-8100'
    """
    if ':' in port_str:
        # dst:src format, take the dst part
        dst_part = port_str.split(':')[0]
        return dst_part
    return port_str


def parse_fg_port_range_src(port_str: str) -> str:
    """Extract source port from FortiGate dst:src notation.

    Returns empty string if no source port specified.
    """
    if ':' in port_str:
        parts = port_str.split(':')
        if len(parts) > 1 and parts[1] != '0-65535':
            return parts[1]
    return ""
