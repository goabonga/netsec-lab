# Fragmentation & IDS evasion

## 1. Context & stakes

Overlapping fragments to defeat IDS reassembly.

IP fragmentation lets a packet be split and reassembled, but endpoints and IDS can disagree on how to reassemble overlapping fragments. An attacker crafts overlaps so the IDS sees benign data while the target reassembles the attack, slipping past inspection. This is a core Ptacek-Newsham evasion, and RFC-consistent reassembly enforced by the IDS is the fix.

## 2. Theory

IP fragments are reassembled by the destination via offset/ID/MF fields. An IDS must reassemble too; if it does so **differently** from the host (overlapping fragments, divergent timeouts/TTL) the attacker shows the IDS one stream and the host another - the classic Ptacek-Newsham insertion/evasion.

## 3. Attack (PoC)

```bash
netlab-frag attack --i-own-this-network --iface veth-host
```

1. Overlapping fragments
2. Divergent order/TTL host vs IDS

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-frag detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Full reassembly on the IDS
- Drop overlaps

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 791](https://www.rfc-editor.org/rfc/rfc791) (IP fragmentation), [RFC 1858](https://www.rfc-editor.org/rfc/rfc1858) (fragmentation attacks)
- [Ptacek & Newsham, Insertion, Evasion, and DoS (1998)](https://insecure.org/stf/secnet_ids/secnet_ids.html)
