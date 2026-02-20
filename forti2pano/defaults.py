"""Default values and constants for PAN-OS configuration."""

# PAN-OS device defaults
DEFAULT_VSYS = "vsys1"
DEFAULT_VIRTUAL_ROUTER = "default"
DEFAULT_DEVICE_NAME = "localhost.localdomain"

# FortiGate defaults
DEFAULT_VDOM = "root"

# PAN-OS predefined address objects
PANOS_PREDEFINED_ADDRESSES = {"any"}

# PAN-OS predefined service objects
PANOS_PREDEFINED_SERVICES = {
    "any",
    "application-default",
    "service-http",
    "service-https",
}

# FortiGate schedule "always" maps to no schedule constraint in PAN-OS
FG_SCHEDULE_ALWAYS = "always"

# PAN-OS max name length
PANOS_MAX_NAME_LEN = 63

# FortiGate action to PAN-OS action mapping
FG_ACTION_TO_PANOS = {
    "accept": "allow",
    "deny": "deny",
    "drop": "drop",
    "reject": "reset-both",
}

# Log traffic mapping
FG_LOG_TO_PANOS = {
    "all": ("yes", "yes"),       # (log-start, log-end)
    "utm": ("no", "yes"),
    "disable": ("no", "no"),
}
