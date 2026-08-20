# LLDP-MED abuse

## 1. Context & stakes

Abuse LLDP-MED to spoof the voice VLAN / PoE policy.

LLDP-MED lets a switch tell an IP phone which voice VLAN and PoE policy to use, and because the phone trusts the advertisement a spoofed TLV can move an attacker's port into the voice VLAN or manipulate power policy. It is a targeted form of VLAN hopping against converged voice and data networks. Restricting LLDP-MED to known phone ports contains it.

## 2. Theory

LLDP-MED extends LLDP for IP phones: the switch advertises the **voice VLAN** and PoE policy, and the phone tags itself accordingly. Forging LLDP-MED lets a rogue device claim the voice VLAN (segmentation bypass) or negotiate an undue PoE class.

## 3. Attack (PoC)

```bash
netlab-lldp-med attack --i-own-this-network --iface veth-host
```

1. Advertise a bogus voice VLAN
2. Negotiate an undue PoE class

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-lldp-med detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Authenticated provisioning
- Static per-port voice VLAN

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- ANSI/TIA-1057 (LLDP-MED)
- Voice VLAN and PoE provisioning security
