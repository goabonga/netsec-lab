# DNS tunneling

## 1. Context & stakes

Exfiltrate data encoded in DNS queries.

Because DNS is almost always allowed outbound and its responses are relayed by trusted resolvers, data can be encoded into query labels and answers to build a bidirectional channel that bypasses firewalls and captive portals. It is a standard exfiltration and C2 path for malware and paywall evasion. Detecting it means flagging abnormal query length, entropy and volume per domain.

## 2. Theory

DNS is almost always allowed out, and recursive resolvers relay queries to an authoritative server the attacker controls. Data is **encoded in query names** (subdomains) and answers (TXT/CNAME) - a slow but reliable exfiltration/C2 channel. Detection watches query volume, long/high-entropy labels and odd record types.

## 3. Attack (PoC)

```bash
netlab-dnstunnel attack --i-own-this-network --iface veth-host
```

1. Encode exfil in subdomains / TXT

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-dnstunnel detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- DNS entropy and volume detection

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [iodine](https://github.com/yarrick/iodine), [dnscat2](https://github.com/iagox86/dnscat2)
- Born & Gustafson, detecting DNS tunnels (entropy/volume)
