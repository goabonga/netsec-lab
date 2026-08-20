# Layer 2 - Data Link

The switch edge. Layer 2 has no built-in authentication: a station trusts what it hears on the wire, which is why the data-link layer carries so much of the LAN attack surface - and why the switch is where most of the defense lives.

## Modules

- [DHCP snooping](dhcp.md) - Rogue DHCP server (MITM) and DHCP starvation against a pool. (`netlab-dhcp`)
- [ARP spoofing](arp.md) - Poison the ARP cache to intercept LAN traffic. (`netlab-arp`)
- [MAC flooding (CAM overflow)](mac-flooding.md) - Saturate the switch CAM table to force fail-open (hub) behaviour. (`netlab-macflood`)
- [STP root takeover](stp.md) - Forge BPDUs to become root bridge and reroute traffic. (`netlab-stp`)
- [VLAN hopping](vlan-hopping.md) - Escape your VLAN via DTP negotiation or 802.1Q double tagging. (`netlab-vlan`)
- [Rogue Router Advertisement (IPv6)](ipv6-ra.md) - The IPv6 equivalent of rogue DHCP: forge RA/SLAAC messages. (`netlab-ipv6-ra`)
- [CDP/LLDP enumeration](discovery-cdp-lldp.md) - Map and spoof topology via CDP/LLDP. (`netlab-discovery`)
- [LLDP-MED abuse](lldp-med.md) - Abuse LLDP-MED to spoof the voice VLAN / PoE policy. (`netlab-lldp-med`)
- [NAC bypass (802.1X)](8021x.md) - Bypass 802.1X network access control. (`netlab-8021x`)
- [MACsec / MKA](macsec.md) - The "TLS of Layer 2": point-to-point encryption + integrity. (`netlab-macsec`)
