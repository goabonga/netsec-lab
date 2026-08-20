# Routing injection (RIP/OSPF)

## 1. Context & stakes

Inject bogus routes into an unauthenticated IGP.

Interior gateway protocols such as RIP and OSPF exchange routes, and run without authentication a router believes any peer's advertisement. Injecting bogus routes blackholes traffic or pulls it through the attacker for MITM. Unauthenticated IGPs have caused real outages from a single rogue speaker; cryptographic neighbour authentication and passive interfaces contain it.

## 2. Theory

Interior gateway protocols (RIP, OSPF) build the routing table from advertisements exchanged between routers. Without neighbour **authentication**, an attacker injects routes to blackhole or reroute traffic - RIP via crafted responses, OSPF by forming an adjacency and flooding bogus LSAs.

## 3. Attack (PoC)

```bash
netlab-routing attack --i-own-this-network --iface veth-host
```

1. Advertise RIP/OSPF routes
2. Blackhole / reroute

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-routing detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Neighbour authentication (MD5/SHA)
- Passive interfaces

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 2453](https://www.rfc-editor.org/rfc/rfc2453) (RIPv2), [RFC 2328](https://www.rfc-editor.org/rfc/rfc2328) (OSPFv2), [RFC 5709](https://www.rfc-editor.org/rfc/rfc5709) (OSPF auth)
- G. Nakibly et al., OSPF routing attacks
