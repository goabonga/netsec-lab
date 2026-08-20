# CDP/LLDP enumeration

## 1. Context & stakes

Map and spoof topology via CDP/LLDP.

CDP and LLDP advertise device model, software version, VLAN, native VLAN and port identity in cleartext to any neighbour to ease management. On an access port that is free reconnaissance for an attacker, and forged advertisements can mislead NMS tooling or a VoIP phone. Disabling discovery on edge ports is the usual hardening step.

## 2. Theory

CDP (Cisco) and LLDP advertise device identity, model, software, VLAN, port and management IP to directly-connected neighbours, in the clear, for topology discovery. An attacker sniffs them to map the network, or forges them to inject false neighbour data - reconnaissance that needs only a port.

## 3. Attack (PoC)

```bash
netlab-discovery attack --i-own-this-network --iface veth-host
```

1. Harvest neighbours, VLANs, models
2. Spoof a neighbour

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-discovery detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Disable CDP/LLDP on access ports

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- IEEE 802.1AB (LLDP); Cisco Discovery Protocol
- Disable CDP/LLDP on access ports
