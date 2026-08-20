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

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md). Commits follow
[Conventional Commits](https://www.conventionalcommits.org/); releases are
driven per-package by [multicz](https://github.com/goabonga/multicz).

## License

[MIT](LICENSE) © Chris
