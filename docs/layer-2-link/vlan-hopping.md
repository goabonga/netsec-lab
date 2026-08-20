# VLAN hopping

## 1. Context & stakes

Escape your VLAN via DTP negotiation or 802.1Q double tagging.

VLANs isolate broadcast domains, but that isolation breaks if an access port auto-negotiates a trunk via DTP, or if the attacker double-tags 802.1Q so the outer tag is stripped and the inner tag lands the frame in another VLAN. Either path reaches a VLAN the attacker was segmented out of. Disabling DTP and pruning the native VLAN closes both.

## 2. Theory

802.1Q tags frames with a VLAN id and trunk ports carry many VLANs. **Switch spoofing** abuses DTP to negotiate a trunk from an access port, exposing every VLAN. **Double tagging** stacks two 802.1Q tags: the first switch strips the outer tag and forwards the inner-tagged frame onto the target VLAN (only from the native VLAN).

## 3. Attack (PoC)

```bash
netlab-vlan attack --i-own-this-network --iface veth-host
```

1. Switch spoofing via DTP
2. 802.1Q double tagging into a target VLAN

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-vlan detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Disable DTP (nonegotiate)
- Dedicated, unused native VLAN

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- IEEE 802.1Q (VLAN tagging)
- [SANS - Virtual LAN security](https://www.sans.org/white-papers/1090/)
- Disable DTP; dedicated native VLAN
