# Covert channels

## 1. Context & stakes

Generic covert channels in header fields and timing.

Protocol headers and packet timing carry spare capacity - IP ID, TCP sequence, TTL, inter-packet gaps - that can smuggle data past controls which only inspect payloads. Because the traffic looks ordinary, covert channels slip past DLP and firewalls and are a hallmark of stealthy exfiltration and C2. Normalising header fields and analysing timing statistically are what detect them.

## 2. Theory

A covert channel smuggles data where none is meant to exist: unused/reusable header fields (IP ID, TCP urgent pointer, sequence numbers, ToS) carry bits, or a **timing** channel encodes data in inter-packet delays. Low-bandwidth but content-inspection-proof; detection is statistical (field entropy, timing regularity).

## 3. Attack (PoC)

```bash
netlab-covert attack --i-own-this-network --iface veth-host
```

1. Unused TCP/IP fields
2. Timing channels

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-covert detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Statistical detection
- Header normalization

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [C. Rowland, Covert Channels in the TCP/IP Protocol Suite (1997)](https://firstmonday.org/ojs/index.php/fm/article/view/528)
- Handel & Sandford; NIST covert-channel analysis
