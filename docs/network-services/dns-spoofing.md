# DNS spoofing / cache poisoning

## 1. Context & stakes

Poison a resolver to hijack a name resolution.

A resolver caches the first answer that matches its query's transaction ID and source port, so an attacker who guesses or races those before the real server gets the forged record cached and every client silently redirected. Kaminsky showed in 2008 how practical this is. Source-port randomisation, 0x20 encoding and DNSSEC validation are the layered defences.

## 2. Theory

A resolver caches answers keyed by (name, type) and matches replies by source port + 16-bit transaction ID. Forging a reply **before** the real server answers (matching port+ID) poisons the cache with attacker records. Source-port randomisation raises the entropy; DNSSEC signs records so forgeries fail validation.

## 3. Attack (PoC)

```bash
netlab-dns attack --i-own-this-network --iface veth-host
```

1. Race the resolver
2. Inject a forged answer

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-dns detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- DNSSEC
- Source-port + QID randomization

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034), [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) (DNS), [RFC 5452](https://www.rfc-editor.org/rfc/rfc5452) (forged-answer resilience)
- D. Kaminsky, DNS cache poisoning (2008); [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) (DNSSEC)
