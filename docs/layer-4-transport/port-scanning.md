# Port scanning & fingerprinting

## 1. Context & stakes

Scanning techniques and TCP/IP stack fingerprinting.

Scanning enumerates which ports respond and, from subtle TCP/IP stack differences, fingerprints the OS and services behind them - the reconnaissance that precedes targeted exploitation. Response patterns of SYN/ACK, RST or silence, plus timing, reveal the network's shape. Rate-based detection and default-deny firewalls raise the cost and lower the yield of the scan.

## 2. Theory

A scan probes ports to find which are open. A **SYN** scan sends SYN and reads SYN/ACK (open) vs RST (closed) without finishing the handshake; **FIN/NULL/Xmas** scans use the RFC-793 rule that closed ports RST an out-of-state segment while open ports stay silent. Response timing and TCP options also **fingerprint** the OS.

## 3. Attack (PoC)

```bash
netlab-portscan attack --i-own-this-network --iface veth-host
```

1. SYN/FIN/NULL/Xmas scans
2. OS fingerprint (TCP options, TTL)

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-portscan detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Scan detection, rate-limit
- Drop stealth scans

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [Nmap Network Scanning](https://nmap.org/book/); [RFC 793](https://www.rfc-editor.org/rfc/rfc793) (TCP)
- [p0f - passive OS fingerprinting](https://lcamtuf.coredump.cx/p0f3/)
