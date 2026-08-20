# Rogue Router Advertisement (IPv6)

## 1. Context & stakes

The IPv6 equivalent of rogue DHCP: forge RA/SLAAC messages.

IPv6 hosts autoconfigure from Router Advertisements, which are unauthenticated by default - the L3 twin of rogue DHCP. A forged RA makes every host on the link install the attacker as its default router and DNS, even on IPv4-only networks where IPv6 is merely enabled and unmonitored. RA Guard on switch ports is the countermeasure.

## 2. Theory

IPv6 hosts autoconfigure from **Router Advertisement** messages announcing the prefix, default gateway and (RDNSS) DNS. Like DHCP, RAs are unauthenticated, so a rogue RA makes the attacker the default router/DNS for the segment - the IPv6 twin of a rogue DHCP server. Even IPv4-only networks are exposed if hosts have IPv6 enabled.

## 3. Attack (PoC)

```bash
netlab-ipv6-ra attack --i-own-this-network --iface veth-host
```

1. Emit forged RAs -> attacker gateway/DNS
2. Malicious RDNSS option

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-ipv6-ra detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- RA Guard on access ports
- SEND (Secure Neighbor Discovery)

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) (ND), [RFC 4862](https://www.rfc-editor.org/rfc/rfc4862) (SLAAC), [RFC 8106](https://www.rfc-editor.org/rfc/rfc8106) (RDNSS)
- [RFC 6105](https://www.rfc-editor.org/rfc/rfc6105) (RA-Guard), [RFC 7113](https://www.rfc-editor.org/rfc/rfc7113) (RA-Guard evasion)
- [RFC 3971](https://www.rfc-editor.org/rfc/rfc3971) (SEND)
