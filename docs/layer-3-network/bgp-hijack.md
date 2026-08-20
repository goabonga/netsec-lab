# BGP hijack (simulated)

> ⭐ Flagship module.

## 1. Context & stakes

Hijack a prefix in a lab AS mesh - flagship module.

BGP routes the Internet on trust: a router accepts a neighbour's claim to originate a prefix with no built-in proof of ownership. By announcing someone else's prefix, or a more specific one, an AS attracts their traffic and can inspect, drop or reroute it. Real hijacks have blackholed YouTube and rerouted crypto and DNS traffic; RPKI origin validation is the deployed mitigation.

## 2. Theory

BGP glues the Internet together: each Autonomous System advertises the prefixes it originates, and routers prefer the most specific / shortest AS-path. With no built-in origin authentication, an AS that announces a prefix it doesn't own - or a **more specific** sub-prefix - draws that traffic to itself. RPKI/ROA validates origin to contain it.

## 3. Attack (PoC)

```bash
netlab-bgp attack --i-own-this-network --iface veth-host
```

1. Prefix / subprefix hijack
2. Route leak between ASes

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-bgp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- RPKI / ROA origin validation
- max-prefix, AS-path filters

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 4271](https://www.rfc-editor.org/rfc/rfc4271) (BGP-4), [RFC 7454](https://www.rfc-editor.org/rfc/rfc7454) / BCP194 (BGP ops security)
- [RFC 6480](https://www.rfc-editor.org/rfc/rfc6480), [RFC 6482](https://www.rfc-editor.org/rfc/rfc6482) (RPKI/ROA), [RFC 8205](https://www.rfc-editor.org/rfc/rfc8205) (BGPsec)
- Pilosov & Kapela, Stealing the Internet (DEFCON 16, 2008)
