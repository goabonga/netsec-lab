# ICMP redirect & tunneling

## 1. Context & stakes

Hijack routing via ICMP redirect; covert ICMP channel.

ICMP redirect messages let a router tell a host of a better next hop, and hosts historically obey them without authentication, so a forged redirect reroutes a victim's traffic through the attacker. ICMP echo payloads also carry arbitrary bytes, turning ping into a covert tunnel. Ignoring ICMP redirects and inspecting echo payloads counter the two abuses.

## 2. Theory

ICMP carries control messages. A **redirect** (type 5) tells a host of a 'better' next-hop, so a forged one reroutes a victim through the attacker. And because the echo (ping) payload is arbitrary and rarely inspected, ICMP also serves as a **covert tunnel** - data smuggled in echo request/reply bodies.

## 3. Attack (PoC)

```bash
netlab-icmp attack --i-own-this-network --iface veth-host
```

1. ICMP redirect -> MITM
2. Tunnel data in the ICMP payload

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-icmp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Ignore redirects (sysctl)
- DPI / payload inspection

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 792](https://www.rfc-editor.org/rfc/rfc792) (ICMP), [RFC 1122](https://www.rfc-editor.org/rfc/rfc1122) (host requirements, redirects)
- [daemon9, Project Loki (Phrack 49)](http://phrack.org/issues/49/6.html)
