# mDNS/LLMNR/NBT-NS poisoning

> Scope: Network dimension only (the wire) - no AD/application exploitation.

## 1. Context & stakes

Poison LAN name resolution (network dimension, on the wire).

When DNS has no answer, Windows and macOS fall back to LLMNR, mDNS and NBT-NS, broadcasting who is NAME to the whole segment - and any host may answer. An attacker replies first, so the victim connects to them, purely at the network layer. This is one of the most reliable LAN footholds, and disabling the fallbacks removes it entirely.

## 2. Theory

When DNS fails, Windows/macOS fall back to link-local name resolution - **mDNS, LLMNR, NBT-NS** - multicasting/broadcasting 'who is NAME?' on the LAN. Any host may answer, so an attacker replies first, pointing the victim at itself (credential capture, redirection). Seen here on the wire only; the fix is disabling LLMNR/NBT-NS.

## 3. Attack (PoC)

```bash
netlab-mdns-llmnr attack --i-own-this-network --iface veth-host
```

1. Answer mDNS/LLMNR/NBT-NS queries

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-mdns-llmnr detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Disable LLMNR and NBT-NS
- Segmentation

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) (mDNS), [RFC 4795](https://www.rfc-editor.org/rfc/rfc4795) (LLMNR), [RFC 1002](https://www.rfc-editor.org/rfc/rfc1002) (NBT)
- [Responder](https://github.com/lgandx/Responder); disable LLMNR/NBT-NS
