# ICMP tunneling

## 1. Context & stakes

Exfiltrate in ICMP echo payloads (companion to the DNS tunnel).

ICMP echo payloads are arbitrary and rarely inspected, so an attacker can carry a data channel inside ping traffic that many networks permit unconditionally. Like DNS tunneling it defeats port-based firewalls by hiding in an allowed protocol. Inspecting or rate-limiting echo payloads, and treating large or patterned pings as suspicious, are the countermeasures.

## 2. Theory

ICMP echo request/reply carry an arbitrary payload that is rarely inspected, so a client and server exchange data by stuffing it into ping packets - an exfiltration/C2 tunnel that looks like ordinary ping. Defence inspects or blocks outbound echo and flags oversized/high-rate ICMP.

## 3. Attack (PoC)

```bash
netlab-icmptunnel attack --i-own-this-network --iface veth-host
```

1. Encode exfil in the echo payload

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-icmptunnel detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Payload inspection, block outbound echo

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [daemon9, Project Loki (Phrack 49)](http://phrack.org/issues/49/6.html); [ptunnel-ng](https://github.com/utoni/ptunnel-ng)
- [RFC 792](https://www.rfc-editor.org/rfc/rfc792) (ICMP)
