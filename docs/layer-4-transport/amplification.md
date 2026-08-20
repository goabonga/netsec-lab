# Reflection & amplification

## 1. Context & stakes

Measure the amplification factor (DNS/NTP/memcached) in-lab.

Reflection abuses UDP services - DNS, NTP, memcached, SSDP - that answer a small spoofed request with a large response; the attacker forges the victim as source, and the service floods the victim. Amplification factors reach roughly 50x for DNS and thousands for memcached, letting a modest attacker generate terabit floods. Source-address validation and closing open reflectors are the fixes.

## 2. Theory

Reflection abuses a UDP service that answers a small **spoofed** request with a large reply aimed at the victim (DNS ANY, NTP monlist, memcached). The **amplification factor** (reply/request size) multiplies the attacker's bandwidth. This module measures that factor in-lab; the fix is source anti-spoofing (BCP38) and disabling the abusable commands.

## 3. Attack (PoC)

```bash
netlab-amplif attack --i-own-this-network --iface veth-host
```

1. Spoofed request -> amplified reply toward the victim (lab-measured)

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-amplif detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Source anti-spoofing (BCP38)
- Disable recursion / monlist

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 5358](https://www.rfc-editor.org/rfc/rfc5358) / BCP140 (preventing reflector attacks)
- [US-CERT TA14-017A - UDP amplification](https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks)
