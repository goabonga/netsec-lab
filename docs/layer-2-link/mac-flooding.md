# MAC flooding (CAM overflow)

## 1. Context & stakes

Saturate the switch CAM table to force fail-open (hub) behaviour.

A switch learns MAC-to-port mappings in a fixed-size CAM table; flooding it with thousands of bogus source MACs fills that table so the switch fails open and floods every frame out every port, degrading to a hub. The attacker then sniffs traffic that switching was supposed to isolate. Port security, limiting MACs per port, is the direct defence.

## 2. Theory

A switch forwards using its **CAM/MAC table** (MAC -> port), learned from source addresses, and the table is finite. Flooding frames with thousands of random source MACs fills it; once full the switch **fails open** and floods every frame out all ports like a hub - so the attacker sees traffic meant for others.

## 3. Attack (PoC)

```bash
netlab-macflood attack --i-own-this-network --iface veth-host
```

1. Flood frames with random source MACs
2. Sniff the fail-open traffic

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-macflood detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Port security: per-port MAC limit
- Sticky MAC, shutdown on violation

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- IEEE 802.1D (MAC learning / forwarding)
- Port security (per-port MAC limits)
- [dsniff](https://www.monkey.org/~dugsong/dsniff/) (`macof`)
