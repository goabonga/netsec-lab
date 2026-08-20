# IP spoofing

## 1. Context & stakes

Forge the source IP; foundation of many L3/L4 attacks.

Nothing in IP forces the source address to be truthful, so a host can forge it freely. Spoofing is the foundation of reflection and amplification DDoS, blind session attacks and audit evasion, and it works wherever ingress filtering is absent. BCP 38 source-address validation at the network edge is the decades-old fix that remains unevenly deployed.

## 2. Theory

IP has no source-address authentication: a host may write any address in the source field. Spoofing underpins reflection/amplification, blind attacks and source-ACL evasion. It is contained at the edge by **BCP38** ingress filtering / uRPF, which drops packets whose source could not legitimately arrive on that interface.

## 3. Attack (PoC)

```bash
netlab-ipspoof attack --i-own-this-network --iface veth-host
```

1. Forge the source IP
2. Blind spoofing / reflection

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-ipspoof detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- BCP38 ingress/egress filtering
- Strict uRPF

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 2827](https://www.rfc-editor.org/rfc/rfc2827) / BCP38 (ingress filtering), [RFC 3704](https://www.rfc-editor.org/rfc/rfc3704) / BCP84 (uRPF)
- Ferguson & Senie, Network Ingress Filtering
