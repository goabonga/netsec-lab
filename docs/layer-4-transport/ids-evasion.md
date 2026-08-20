# NIDS evasion (insertion/evasion)

> ⭐ Flagship module.

## 1. Context & stakes

Ptacek-Newsham techniques: insertion/evasion, TCP desync - flagship.

Insertion and evasion exploit the gap between what an IDS thinks the target will accept and what it actually accepts: crafted TTLs, checksums, overlaps and TCP desync make sensor and endpoint see different byte streams. The attack reaches the target while the IDS logs something benign. Ptacek and Newsham's 1998 paper defined the class, and target-aware normalising reassembly is the defence.

## 2. Theory

A network IDS must reconstruct exactly what the endpoint will see. **Insertion** feeds it packets the host will drop (bad checksum, a TTL that expires first); **evasion** hides packets the host accepts. Manipulating TTL, fragmentation and TCP state desynchronises IDS and host (Ptacek-Newsham). Flow **normalization** removes the ambiguity.

## 3. Attack (PoC)

```bash
netlab-ids-evasion attack --i-own-this-network --iface veth-host
```

1. Manipulate TTL/fragmentation (insertion vs evasion)
2. Desynchronize TCP state

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-ids-evasion detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Flow normalization (traffic scrubbing)
- Host-state-aware IDS

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [Ptacek & Newsham, Insertion, Evasion, and DoS (1998)](https://insecure.org/stf/secnet_ids/secnet_ids.html)
- [Handley, Paxson, Kreibich, NIDS evasion & normalization (2001)](https://www.icir.org/vern/papers/norm-usenix-sec-01.pdf)
