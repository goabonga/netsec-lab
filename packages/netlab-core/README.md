# netlab-core

Shared foundation for the [netsec-lab](../../README.md) PoC. Does nothing on
its own: it provides the building blocks reused by every PoC module.

- `consent` - mandatory `--i-own-this-network` guardrail for offensive tools.
- `lab` - `VethLab`, an isolated L2 segment (netns + veth) to replay the PoC.
- `sniffing` - lazy scapy capture (no scapy required at import time).
- `binding` - `BindingTable` (DHCP snooping, DAI, IP Source Guard).
- `lesson` - teaching brief, printable even while a PoC is a stub.
- `log` - normalized verdicts (FORWARD / DROP / LEARN / ALERT).
