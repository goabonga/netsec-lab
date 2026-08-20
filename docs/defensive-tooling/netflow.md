# NetFlow / IPFIX analysis

## 1. Context & stakes

Generate and analyze flows for behavioural detection.

NetFlow and IPFIX export connection metadata - the 5-tuple with byte and packet counts - without payload, giving cheap visibility across an entire network. Behavioural detection then works on shape rather than content: a host fanning out to hundreds of destinations is a scan or a worm even over TLS. This is how large networks catch lateral movement and C2 beacons that a payload-blind signature IDS never sees.

## 2. How it works

NetFlow/IPFIX exports per-flow records (tuple, bytes, packets, flags, duration) instead of payload, giving a scalable behavioural view. Scans, exfiltration and beaconing show up as flow patterns (fan-out, long low-rate flows, periodicity) even when the content is encrypted. This module aggregates packets into 5-tuple flows and flags a source that reaches too many distinct destinations.

## 3. Commands

```bash
netlab-netflow brief                                    # teaching brief
netlab-netflow detect --iface veth-host --threshold 10  # build flows, flag fan-out
netlab-netflow defend                                   # analyse a synthetic trace
```

## 4. What it detects

`detect` builds a flow table from live traffic and alerts once a source reaches
`--threshold` distinct destinations. `defend` feeds a synthetic trace where one
host sweeps a /24:

```
[!!] ALERT     10.0.0.66 reached 20 distinct hosts -> scan
[OK] FORWARD   10.0.0.5 fan-out within normal range
```

High fan-out is a horizontal scan or worm; a long low-rate flow with fixed
periodicity is a beacon. Both are visible in metadata alone, even over TLS.

## 5. Operating it

- Export flows from switches/routers (NetFlow v9, IPFIX) or a probe, and store
  them in a collector such as SiLK or nfdump.
- Alert on fan-out, long low-rate flows and periodic beaconing rather than on
  payload - this is the detection that survives end-to-end encryption.
- Tune `--threshold` to the segment: a scanner and a busy proxy both fan out, so
  baseline first.

## 6. Further reading

- [RFC 3954](https://www.rfc-editor.org/rfc/rfc3954) (NetFlow v9), [RFC 7011](https://www.rfc-editor.org/rfc/rfc7011) (IPFIX)
- [SiLK](https://tools.netsa.cert.org/silk/), [nfdump](https://github.com/phaag/nfdump)
