# IDS rule harness

## 1. Context & stakes

Write Snort/Suricata rules and trigger them with the PoC traffic.

A signature IDS such as Snort or Suricata reassembles flows and matches rules against them, so its value is bounded by rule quality: too loose and it drowns analysts in false positives, too tight and it misses the attack. This harness fires each PoC at a rule set and scores detections against false positives to make that trade-off measurable. Real SOCs live or die by it - alert fatigue from noisy rules is a documented cause of missed breaches.

## 2. How it works

A signature IDS (Snort/Suricata) reassembles flows and matches rules (headers, content, PCRE) to flag known-bad traffic. This module ships `netlab_ids.rules.CATALOGUE` - one reference Suricata rule per offensive PoC in this repo - plus a small content-match engine and a scorer that replays labelled traffic to report detections and false positives.

## 3. Commands

```bash
netlab-ids brief                    # teaching brief
netlab-ids detect --iface veth-host # run the content rules over live traffic
netlab-ids defend                   # score the catalogue against labelled traffic
```

Inspect the rule catalogue directly:

```python
from netlab_ids.rules import CATALOGUE, for_poc, covered_pocs

len(covered_pocs())  # every offensive PoC is covered
for_poc("dnstunnel")  # the rule(s) for one PoC
```

## 4. What it detects

`detect` loads the payload-matchable subset (`content_ruleset()`) and alerts on
any packet whose payload matches a signature. `defend` scores the same rules
against a labelled sample and prints the confusion matrix plus catalogue
coverage:

```
[!!] ALERT     sid 2150004: cleartext login after HTTPS
[!!] ALERT     sid 2150005: SNMP community brute force
[..] INFO      detections=2 misses=0 false-positives=0
[..] INFO      catalogue: 40 PoC covered (24 wire rules, 16 WIDS/physical notes)
```

The catalogue carries real Suricata rules for the on-wire attacks (Layers 2-4
and services) and a note for wireless / physical PoC, which a wired IDS cannot
see - use a WIDS there instead.

## 5. Operating it

- Export `CATALOGUE` rules into a `.rules` file and load them in Suricata/Snort.
- Replay each PoC's traffic (or a captured pcap) through the sensor and tune
  thresholds until detections stay high and false positives stay low.
- Feed the same capture to [`netlab-pcap-forensics`](pcap-forensics.md) to
  correlate a signature hit with the reconstructed timeline.

## 6. Further reading

- [Suricata documentation](https://docs.suricata.io/), [Snort](https://www.snort.org/)
- M. Roesch, Snort - Lightweight Intrusion Detection (LISA 1999)
