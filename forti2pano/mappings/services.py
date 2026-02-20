"""FortiGate predefined service to PAN-OS service mapping."""

# FortiGate has ~200 predefined services. PAN-OS has its own set.
# This maps the common ones. Custom services defined in
# 'config firewall service custom' are converted directly as objects.
#
# Value meanings:
#   "service-http"       -> PAN-OS predefined service name
#   "application-default"-> use PAN-OS App-ID with default ports
#   None                 -> needs a custom service object (will be created)

FG_TO_PANOS_SERVICE = {
    # Web
    "HTTP": "service-http",
    "HTTPS": "service-https",
    "HTTP-8080": None,  # custom, tcp/8080

    # Email
    "SMTP": None,       # tcp/25
    "SMTPS": None,      # tcp/465
    "POP3": None,       # tcp/110
    "POP3S": None,      # tcp/995
    "IMAP": None,       # tcp/143
    "IMAPS": None,      # tcp/993

    # File transfer
    "FTP": None,        # tcp/21
    "TFTP": None,       # udp/69
    "FTP_GET": None,
    "FTP_PUT": None,

    # Remote access
    "SSH": None,        # tcp/22
    "TELNET": None,     # tcp/23
    "RDP": None,        # tcp/3389

    # DNS
    "DNS": None,        # tcp+udp/53

    # Network services
    "PING": None,       # icmp
    "PING6": None,      # icmpv6
    "TRACEROUTE": None,
    "NTP": None,        # udp/123
    "SNMP": None,       # udp/161
    "SNMP_trap": None,  # udp/162
    "SYSLOG": None,     # udp/514
    "DHCP": None,       # udp/67-68
    "LDAP": None,       # tcp/389
    "LDAPS": None,      # tcp/636
    "RADIUS": None,     # udp/1812
    "KERBEROS": None,   # tcp+udp/88

    # Database
    "MYSQL": None,      # tcp/3306
    "MSSQL": None,      # tcp/1433

    # VPN
    "IKE": None,        # udp/500
    "L2TP": None,       # udp/1701

    # Catch-all
    "ALL": "any",
    "ALL_TCP": "any",
    "ALL_UDP": "any",
    "ALL_ICMP": "any",
    "ALL_ICMP6": "any",
}

# FortiGate predefined services that we can auto-create as PAN-OS custom objects
# format: {fg_name: (protocol, port)}
FG_SERVICE_DEFINITIONS = {
    "HTTP-8080": ("tcp", "8080"),
    "SMTP": ("tcp", "25"),
    "SMTPS": ("tcp", "465"),
    "POP3": ("tcp", "110"),
    "POP3S": ("tcp", "995"),
    "IMAP": ("tcp", "143"),
    "IMAPS": ("tcp", "993"),
    "FTP": ("tcp", "21"),
    "TFTP": ("udp", "69"),
    "SSH": ("tcp", "22"),
    "TELNET": ("tcp", "23"),
    "RDP": ("tcp", "3389"),
    "DNS": ("tcp", "53"),
    "NTP": ("udp", "123"),
    "SNMP": ("udp", "161"),
    "SNMP_trap": ("udp", "162"),
    "SYSLOG": ("udp", "514"),
    "LDAP": ("tcp", "389"),
    "LDAPS": ("tcp", "636"),
    "RADIUS": ("udp", "1812"),
    "KERBEROS": ("tcp", "88"),
    "MYSQL": ("tcp", "3306"),
    "MSSQL": ("tcp", "1433"),
    "IKE": ("udp", "500"),
    "L2TP": ("udp", "1701"),
}


def map_service(fg_service: str) -> str:
    """Map a FortiGate service name to PAN-OS equivalent.

    Returns the PAN-OS predefined name if one exists,
    or returns the input name (assuming it's a custom service object).
    """
    panos = FG_TO_PANOS_SERVICE.get(fg_service)
    if panos is not None:
        return panos
    # Not in the predefined mapping - return as-is (custom service)
    return fg_service


def is_predefined_fg_service(name: str) -> bool:
    """Check if a service name is a FortiGate predefined service."""
    return name in FG_TO_PANOS_SERVICE


def get_predefined_service_def(name: str):
    """Get the protocol/port definition for a FortiGate predefined service.

    Returns (protocol, port) or None.
    """
    return FG_SERVICE_DEFINITIONS.get(name)
