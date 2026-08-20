# netsec-lab

Hands-on **network security** training. Each topic is a self-contained proof
of concept that walks the same three steps - **attack → detect → defend** -
and ships as an independent `netlab-*` uv package. Most modules run inside an
isolated network-namespace lab where no traffic ever leaves the host; the
Layer 1 modules are the exception - they need real radio or physical hardware
and are documented for awareness.

## How it is organized

The curriculum follows the network stack, layer by layer:

- **[Layer 1 - Physical](layer-1-physical/index.md)** - media, radio and
  hardware: Wi-Fi recon/deauth, evil twin, WPA/WPS cracking, tapping, TEMPEST,
  rogue implants. Hardware-bound, so not replayable in the netns lab.
- **[Layer 2 - Data Link](layer-2-link/index.md)** - the switch edge: DHCP,
  ARP, MAC/CAM, STP, VLANs, 802.1X, MACsec.
- **[Layer 3 - Network](layer-3-network/index.md)** - routing and reachability:
  IP spoofing, ICMP, fragmentation, IGP injection, BGP, FHRP.
- **[Layer 4 - Transport](layer-4-transport/index.md)** - TCP/UDP: scanning,
  SYN flood, hijacking, amplification, IDS evasion, covert channels.
- **[Network services](network-services/index.md)** - DNS, TLS, SNMP, NTP,
  QUIC and LAN name resolution, viewed on the wire.
- **[Defensive tooling](defensive-tooling/index.md)** - IDS rules, firewalling,
  NetFlow, PCAP forensics, TLS inspection.

## Before you start

1. Read **[Lab setup](lab-setup.md)** to build the isolated netns/veth segment.
2. Read the **[Methodology](methodology.md)** - the attack/detect/defend model
   every module follows.
3. Pick a layer and work through its modules in order.

> Every offensive PoC refuses to run without `--i-own-this-network`. Use these
> tools only on networks you own. This material is for defenders and for
> authorized testing.
