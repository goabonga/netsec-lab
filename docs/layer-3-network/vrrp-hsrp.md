# FHRP takeover (VRRP/HSRP)

## 1. Context & stakes

Seize the master role of a redundant gateway.

FHRP protocols like VRRP and HSRP present a virtual gateway IP shared by redundant routers, electing a master by priority. With weak or default authentication an attacker advertises the highest priority, becomes master, and every host sends its off-subnet traffic through them. That is a clean gateway MITM; strong FHRP authentication and control-plane ACLs are the countermeasures.

## 2. Theory

VRRP/HSRP give a subnet a virtual gateway IP shared by several routers; the highest-**priority** router is master and answers for the virtual IP/MAC. An attacker joining with a higher priority (VRRP is unauthenticated by default) becomes master and receives the segment's outbound traffic - a gateway takeover.

## 3. Attack (PoC)

```bash
netlab-vrrp-hsrp attack --i-own-this-network --iface veth-host
```

1. Advertise a higher VRRP/HSRP priority
2. Become master -> MITM

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-vrrp-hsrp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- FHRP authentication
- Priority hardening

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 5798](https://www.rfc-editor.org/rfc/rfc5798) (VRRPv3), [RFC 2281](https://www.rfc-editor.org/rfc/rfc2281) (HSRP)
- FHRP attacks ([Yersinia](https://github.com/tomac/yersinia), Loki)
