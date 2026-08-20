# Defensive Tooling

The defender's toolbox. Detection rules, firewalling, flow analysis and forensics - used to catch, block and reconstruct the attacks from the other sections.

## Modules

- [IDS rule harness](ids.md) - Write Snort/Suricata rules and trigger them with the PoC traffic. (`netlab-ids`)
- [Firewall policy](firewall.md) - nftables/iptables policy and validation that it blocks the PoC. (`netlab-firewall`)
- [NetFlow / IPFIX analysis](netflow.md) - Generate and analyze flows for behavioural detection. (`netlab-netflow`)
- [PCAP forensics](pcap-forensics.md) - Reconstruct an attack from a capture (blue-team exercise). (`netlab-pcap-forensics`)
- [TLS inspection proxy](tls-inspect.md) - Defensive TLS inspection proxy (SNI filtering, enterprise MITM). (`netlab-tls-inspect`)
- [MACsec posture check](macsec-monitor.md) - Audit MACsec posture (encrypted vs cleartext links) on a segment. (`netlab-macsec-monitor`)
