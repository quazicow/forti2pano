# forti2pano

Convert FortiGate firewall configurations into Palo Alto Networks PAN-OS format.

Parses a FortiGate flat-text config (`show full-configuration` or `.conf` backup), translates all major elements, and outputs both PAN-OS XML (for API/Panorama import) and CLI set commands.

When the converter encounters vendor mismatches that can't be automatically resolved, it generates a YAML decision form for you to fill out before producing the final output.

## Quick Start

```bash
pip install PyYAML

# Pass 1 — parse and generate decisions form
python -m forti2pano firewall.conf -o output/

# Edit output/decisions.yaml (fill in user_value fields)

# Pass 2 — apply decisions, produce PAN-OS config
python -m forti2pano firewall.conf -d output/decisions.yaml -o output/
```

If all required decisions have reasonable defaults (e.g. `port1` → `ethernet1/1`), pass 1 will produce output directly and you can skip pass 2.

### Output Files

| File | Description |
|------|-------------|
| `decisions.yaml` | YAML form for items needing your input (interface mapping, profiles, VPN tunnels) |
| `panos_config.xml` | PAN-OS XML configuration — import via API or Panorama |
| `panos_set_commands.txt` | PAN-OS CLI set commands — paste into the device CLI |

## What Gets Converted

| FortiGate Element | PAN-OS Equivalent |
|---|---|
| `config firewall address` (subnet, FQDN, iprange, wildcard, geography) | Address objects |
| `config firewall addrgrp` | Address groups |
| `config firewall service custom` (TCP, UDP, ICMP, IP protocol) | Service objects |
| `config firewall service group` | Service groups |
| `config system zone` | Zones (with interface resolution) |
| `config system interface` | Ethernet, loopback, and tunnel interfaces with IP addresses |
| `config router static` | Static routes in the virtual router |
| `config firewall policy` | Security rules (zones, addresses, services, action, logging, security profiles) |
| `config firewall vip` | DNAT rules (with port forwarding support) |
| `config firewall ippool` + policy NAT | SNAT rules (dynamic IP/port or interface-based) |
| `config vpn ipsec phase1-interface` | IKE crypto profiles + IKE gateways |
| `config vpn ipsec phase2-interface` | IPSec crypto profiles + IPSec tunnels with proxy IDs |

### Key Translation Details

- **Interfaces:** FortiGate interface names (e.g. `port1`, `wan1`, `loopback0`) are mapped to PAN-OS names (`ethernet1/1`, `loopback.1`) via heuristics, confirmed through the decision form.
- **Zones:** Policies reference FortiGate interfaces, which are resolved to zones. Interfaces not in any zone get synthetic zones via the decision form.
- **Services:** ~25 FortiGate predefined services (HTTP, HTTPS, DNS, SSH, etc.) are auto-mapped. Custom services are converted directly.
- **Security Profiles:** FortiGate AV profiles, IPS sensors, and web filter profiles are mapped to PAN-OS equivalents via the decision form.
- **NAT:** VIPs become DNAT rules with auto-generated address objects for external and mapped IPs. IP pools become SNAT rules. Policies with `set nat enable` without a pool generate interface-based SNAT.
- **VPN Crypto:** FortiGate proposal strings (e.g. `aes256-sha256`) are split into separate encryption and authentication algorithms for PAN-OS crypto profiles.
- **PSK:** Encrypted pre-shared keys (`ENC ...`) cannot be extracted — the converter emits `CHANGE_ME` and flags this in the decision form.

## Decision Form

The YAML decision form is generated when the converter encounters items that require human judgment. Each item includes a description, the original FortiGate value, and a suggested PAN-OS value:

```yaml
decisions:
  - id: intf_port1
    category: interface_mapping
    description: >
      Map FortiGate interface 'port1' (alias='WAN') ip=203.0.113.10/24
      type=physical to a PAN-OS interface name.
    fg_value: port1
    suggested_value: ethernet1/1
    user_value:              # <-- fill this in
    required: true

  - id: profile_av_default
    category: security_profile
    description: >
      FortiGate AV profile 'default' is referenced in policies.
      Provide the PAN-OS Antivirus profile name to map to,
      or leave blank to omit.
    fg_value: default
    suggested_value: default
    user_value:
    required: false
```

**Decision categories:**

| Category | What It Covers |
|---|---|
| `interface_mapping` | FortiGate interface → PAN-OS interface name |
| `zone_confirmation` | Zone names and interface-to-zone assignments |
| `security_profile` | AV, IPS, URL filtering, profile group mapping |
| `vpn_tunnel_interface` | Tunnel interface assignment and PSK entry |
| `service_ambiguity` | IP protocol numbers or unmapped predefined services |

If `user_value` is left empty, the `suggested_value` is used. Required items must have at least a suggested value to proceed.

## CLI Reference

```
usage: forti2pano [-h] [-d DECISIONS] [-o OUTPUT_DIR] [--xml-only]
                  [--set-only] [--vsys VSYS] [--virtual-router VR]
                  [--vdom VDOM] [-v] [--version]
                  input
```

| Argument | Description |
|---|---|
| `input` | Path to FortiGate config file |
| `-d, --decisions` | Path to filled-in decisions YAML (pass 2) |
| `-o, --output-dir` | Output directory (default: current directory) |
| `--xml-only` | Output only PAN-OS XML |
| `--set-only` | Output only set commands |
| `--vsys` | PAN-OS vsys name (default: `vsys1`) |
| `--virtual-router` | Virtual router name (default: `default`) |
| `--vdom` | FortiGate VDOM to process (default: `root`) |
| `-v, --verbose` | Enable debug logging |

## Project Structure

```
forti2pano/
  parser/
    tokenizer.py          Line-level FortiGate config tokenizer
    tree.py               Stack-based parser → nested dict tree
    extractors.py         Section-specific extractors → model objects
  model/
    objects.py            Address and service dataclasses
    network.py            Interface, zone, route dataclasses
    policy.py             Security policy, VIP, IP pool, NAT dataclasses
    vpn.py                Phase1/2, IKE/IPSec crypto, gateway, tunnel dataclasses
    config.py             Top-level PanoConfig container
  decisions/
    schema.py             Decision form schema and YAML serialization
    generator.py          Analyzes config, produces decision items
    resolver.py           Applies user decisions back into the model
  emitters/
    panos_xml.py          PAN-OS XML emitter (xml.etree.ElementTree)
    panos_set.py          PAN-OS set command emitter
  mappings/
    crypto.py             FortiGate → PAN-OS crypto proposal mapping
    services.py           Predefined service mapping table
    interfaces.py         Interface name heuristic suggestions
  cli.py                  CLI entry point and orchestration
  util.py                 IP/mask conversion, name sanitization
  defaults.py             PAN-OS default values and constants
```

## Requirements

- Python 3.7+
- PyYAML >= 6.0

No other dependencies. Everything else uses the Python standard library.

## Limitations

- **VDOM support is basic** — processes one VDOM at a time (default: `root`). Multi-VDOM configs should specify `--vdom`.
- **Encrypted PSKs** cannot be decrypted — VPN pre-shared keys must be re-entered manually.
- **Application control** — FortiGate application lists are noted but not mapped to PAN-OS App-ID (this requires policy-by-policy review).
- **Schedules** — FortiGate schedules other than `always` are not converted (noted in policy descriptions).
- **ICMP services** — PAN-OS handles ICMP differently (via application, not service objects). ICMP services are flagged with a comment.
- **SD-WAN, SSL VPN, user/group references, and dynamic routing** are not currently handled.

## License

MIT
