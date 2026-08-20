# Layer 4 - Transport

The transport layer. TCP and UDP carry the sessions; their state machines and the absence of authentication enable scanning, flooding, hijacking and evasion of the sensors watching them.

## Modules

- [Port scanning & fingerprinting](port-scanning.md) - Scanning techniques and TCP/IP stack fingerprinting. (`netlab-portscan`)
- [TCP SYN flood](syn-flood.md) - Exhaust the connection table with half-open connections. (`netlab-synflood`)
- [TCP session hijacking](tcp-hijacking.md) - Inject into / reset an established TCP session. (`netlab-tcphijack`)
- [Reflection & amplification](amplification.md) - Measure the amplification factor (DNS/NTP/memcached) in-lab. (`netlab-amplif`)
- [NIDS evasion (insertion/evasion)](ids-evasion.md) ⭐ - Ptacek-Newsham techniques: insertion/evasion, TCP desync - flagship. (`netlab-ids-evasion`)
- [Covert channels](covert-channels.md) - Generic covert channels in header fields and timing. (`netlab-covert`)
