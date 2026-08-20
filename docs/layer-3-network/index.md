# Layer 3 - Network

Routing and reachability. Layer 3 decides where packets go; forging source addresses or poisoning routing state lets an attacker redirect, blackhole or intercept traffic across segments.

## Modules

- [IP spoofing](ip-spoofing.md) - Forge the source IP; foundation of many L3/L4 attacks. (`netlab-ipspoof`)
- [ICMP redirect & tunneling](icmp.md) - Hijack routing via ICMP redirect; covert ICMP channel. (`netlab-icmp`)
- [Fragmentation & IDS evasion](fragmentation.md) - Overlapping fragments to defeat IDS reassembly. (`netlab-frag`)
- [Routing injection (RIP/OSPF)](routing.md) - Inject bogus routes into an unauthenticated IGP. (`netlab-routing`)
- [IGMP snooping / spoofing](igmp-multicast.md) - Manipulate multicast membership (forged join/leave). (`netlab-igmp`)
- [BGP hijack (simulated)](bgp-hijack.md) ⭐ - Hijack a prefix in a lab AS mesh - flagship module. (`netlab-bgp`)
- [FHRP takeover (VRRP/HSRP)](vrrp-hsrp.md) - Seize the master role of a redundant gateway. (`netlab-vrrp-hsrp`)
