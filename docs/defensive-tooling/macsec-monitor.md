# MACsec posture check

## 1. Context & stakes

Audit MACsec posture (encrypted vs cleartext links) on a segment.

MACsec (802.1AE) encrypts and authenticates each L2 hop, but only while it is actually negotiated; a link that silently falls back to cleartext, or agrees a NULL cipher, still reports as up while being fully readable. This monitor audits per-port posture and flags any protected link that has lost its SecTAG. An attacker who forces a downgrade before tapping the wire depends on exactly this blind spot.

## 2. How it works

MACsec protects a link only if it is actually enabled on both ends. This module inventories a segment's links - which carry 802.1AE-protected traffic vs cleartext - and alerts on any port that is unprotected or negotiated a cipher outside the approved set, so the positive control from `netlab-macsec` can be verified at scale.

## 3. Commands

```bash
netlab-macsec-monitor brief                    # teaching brief
netlab-macsec-monitor detect --iface veth-host # watch a link for loss of MACsec
netlab-macsec-monitor defend                   # report per-port posture on a sample segment
```

## 4. What it detects

`detect` watches a link and alerts on any cleartext frame where a SecTAG
(ethertype `0x88e5`) was expected. `defend` audits a sample segment:

```
[OK] FORWARD   Gi0/1: MACsec GCM-AES-256
[!!] ALERT     Gi0/2: cleartext -> link no longer trustworthy
[!!] ALERT     Gi0/3: weak -> link no longer trustworthy
```

A port is `cleartext` when MACsec is not active and `weak` when the cipher is
outside the approved set (only `GCM-AES-128/256`, incl. XPN, are accepted).

## 5. Operating it

- Poll each port's MACsec state (SecTAG present, cipher suite) and alert on any
  protected link that drops to cleartext or a NULL/weak cipher.
- Treat a silent downgrade as an incident: it is the precondition for tapping an
  otherwise-encrypted link.
- Pair with [`netlab-macsec`](../layer-2-link/macsec.md), which provides the
  positive control this monitor verifies at scale.

## 6. Further reading

- [IEEE 802.1AE (MACsec)](https://1.ieee802.org/security/802-1ae/), IEEE 802.1X-2010 (MKA)
- MACsec posture and deployment guides
