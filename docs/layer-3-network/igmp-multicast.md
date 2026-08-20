# IGMP snooping / spoofing

## 1. Context & stakes

Manipulate multicast membership (forged join/leave).

Switches use IGMP snooping to forward multicast only to interested ports, but membership reports are unauthenticated: forged joins pull streams to the attacker's port and forged leaves cut delivery to legitimate receivers. In IPTV, market-data and industrial-control networks that ride multicast this is both eavesdropping and targeted DoS. A validating IGMP querier limits it.

## 2. Theory

IGMP manages IPv4 multicast membership: hosts join/leave, the querier tracks groups, and switches use **IGMP snooping** to forward multicast only to interested ports. Forged joins make a switch flood a group to the attacker (eavesdrop); forged leaves or a rogue querier disrupt delivery (DoS).

## 3. Attack (PoC)

```bash
netlab-igmp attack --i-own-this-network --iface veth-host
```

1. Forge IGMP joins/leaves
2. Multicast eavesdrop / DoS

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-igmp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- IGMP snooping, querier control

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 2236](https://www.rfc-editor.org/rfc/rfc2236) (IGMPv2), [RFC 3376](https://www.rfc-editor.org/rfc/rfc3376) (IGMPv3), [RFC 4541](https://www.rfc-editor.org/rfc/rfc4541) (snooping)
