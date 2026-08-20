# STP root takeover

## 1. Context & stakes

Forge BPDUs to become root bridge and reroute traffic.

Spanning Tree elects a root bridge by lowest priority and by default trusts any BPDU on any port. An attacker sending superior BPDUs becomes root, so inter-switch traffic reroutes through their machine for MITM, or flaps endlessly for denial of service. BPDU Guard and Root Guard on edge ports are the standard containment.

## 2. Theory

Spanning Tree prevents L2 loops by electing a **root bridge** (lowest bridge-ID) and blocking redundant links, bridges exchanging BPDUs with no authentication. An attacker emitting a **superior BPDU** (lower priority) becomes root, forcing traffic to reconverge through its port - a MITM or DoS via topology change.

## 3. Attack (PoC)

```bash
netlab-stp attack --i-own-this-network --iface veth-host
```

1. Emit a superior BPDU
2. Take the root role, reroute flows

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-stp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- BPDU Guard, Root Guard
- PortFast limited to access ports

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- IEEE 802.1D / 802.1w (RSTP)
- BPDU Guard, Root Guard
- [Yersinia](https://github.com/tomac/yersinia)
