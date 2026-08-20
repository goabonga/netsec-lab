# netsec-lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![uv](https://img.shields.io/badge/managed%20by-uv-de5fe9.svg)](https://github.com/astral-sh/uv)

Hands-on **network security** training. Each topic is a self-contained proof of
concept that walks the same three steps - **attack → detect → defend** - and
ships as an independent `netlab-*` package in a single uv workspace. Every PoC
runs inside an isolated network-namespace lab: no hardware, and no traffic ever
leaves the host.

> Offensive PoC refuse to run without `--i-own-this-network`. Use them only on
> networks you own, for defense and authorized testing.

## Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv)
- Linux with `ip netns` (for the veth lab) and root for packet injection

## Getting started

```bash
uv sync
uv run netlab-dhcp brief      # what a module teaches (no privileges needed)
uv run netlab-dhcp defend     # DHCP snooping simulator (no root)
```

See the [lab setup](docs/lab-setup.md) to build the isolated segment, and the
[methodology](docs/methodology.md) for the attack/detect/defend model.

## Packages

Modules are grouped by network layer - 46 PoC plus the shared foundation. Attack modules are red-team; detection and defense modules are blue-team.

| Package | Layer | Topic |
| --- | --- | --- |
| `netlab-core` | - | Shared foundation (consent, lab, capture, bindings) |
| `netlab-wifi-recon` | L1 | 802.11 passive reconnaissance |
| `netlab-wifi-deauth` | L1 | 802.11 deauthentication |
| `netlab-evil-twin` | L1 | Evil twin / rogue AP |
| `netlab-wpa-crack` | L1 | WPA/WPA2 handshake & PMKID crack |
| `netlab-wps-brute` | L1 | WPS PIN brute force |
| `netlab-tap` | L1 | Passive network tapping |
| `netlab-tempest` | L1 | TEMPEST / Van Eck emanations |
| `netlab-hw-implant` | L1 | Rogue hardware implant |
| `netlab-dhcp` | L2 | DHCP snooping |
| `netlab-arp` | L2 | ARP spoofing |
| `netlab-macflood` | L2 | MAC flooding (CAM overflow) |
| `netlab-stp` | L2 | STP root takeover |
| `netlab-vlan` | L2 | VLAN hopping |
| `netlab-ipv6-ra` | L2 | Rogue Router Advertisement (IPv6) |
| `netlab-discovery` | L2 | CDP/LLDP enumeration |
| `netlab-lldp-med` | L2 | LLDP-MED abuse |
| `netlab-8021x` | L2 | NAC bypass (802.1X) |
| `netlab-macsec` | L2 | MACsec / MKA |
| `netlab-ipspoof` | L3 | IP spoofing |
| `netlab-icmp` | L3 | ICMP redirect & tunneling |
| `netlab-frag` | L3 | Fragmentation & IDS evasion |
| `netlab-routing` | L3 | Routing injection (RIP/OSPF) |
| `netlab-igmp` | L3 | IGMP snooping / spoofing |
| `netlab-bgp` | L3 | BGP hijack (simulated) (flagship) |
| `netlab-vrrp-hsrp` | L3 | FHRP takeover (VRRP/HSRP) |
| `netlab-portscan` | L4 | Port scanning & fingerprinting |
| `netlab-synflood` | L4 | TCP SYN flood |
| `netlab-tcphijack` | L4 | TCP session hijacking |
| `netlab-amplif` | L4 | Reflection & amplification |
| `netlab-ids-evasion` | L4 | NIDS evasion (insertion/evasion) (flagship) |
| `netlab-covert` | L4 | Covert channels |
| `netlab-dns` | Svc | DNS spoofing / cache poisoning |
| `netlab-dnstunnel` | Svc | DNS tunneling |
| `netlab-icmptunnel` | Svc | ICMP tunneling |
| `netlab-tls` | Svc | TLS downgrade / MITM |
| `netlab-snmp` | Svc | SNMP enumeration |
| `netlab-ntp` | Svc | NTP time-shift MITM |

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md). Commits follow
[Conventional Commits](https://www.conventionalcommits.org/); releases are
driven per-package by [multicz](https://github.com/goabonga/multicz).

## License

[MIT](LICENSE) © Chris
