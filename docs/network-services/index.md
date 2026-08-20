# Network Services

The protocols that make the network usable - name resolution, time, management, transport security. Seen here on the wire, where they can be spoofed, downgraded or tunnelled through.

## Modules

- [DNS spoofing / cache poisoning](dns-spoofing.md) - Poison a resolver to hijack a name resolution. (`netlab-dns`)
- [DNS tunneling](dns-tunneling.md) - Exfiltrate data encoded in DNS queries. (`netlab-dnstunnel`)
- [ICMP tunneling](icmp-tunneling.md) - Exfiltrate in ICMP echo payloads (companion to the DNS tunnel). (`netlab-icmptunnel`)
- [TLS downgrade / MITM](tls.md) - SSL stripping, downgrade and proxy MITM. (`netlab-tls`)
- [SNMP enumeration](snmp.md) - Enumerate via weak community strings. (`netlab-snmp`)
- [NTP time-shift MITM](ntp.md) - Shift the clock to invalidate TLS/Kerberos. (`netlab-ntp`)
- [mDNS/LLMNR/NBT-NS poisoning](mdns-llmnr.md) - Poison LAN name resolution (network dimension, on the wire). (`netlab-mdns-llmnr`)
- [Kerberos on the wire](kerberos-net.md) - Capture/relay Kerberos tickets at the network level. (`netlab-kerberos-net`)
- [QUIC / HTTP3 fingerprinting](quic.md) - Recon and inspection challenges of an encrypted UDP transport. (`netlab-quic`)
