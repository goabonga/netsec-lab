# MACsec / MKA

## 1. Context & stakes

The "TLS of Layer 2": point-to-point encryption + integrity.

MACsec (802.1AE) provides line-rate encryption and integrity for each Ethernet hop - the TLS of Layer 2 - defeating tapping, injection and MITM on the wire itself. Its security rests on MKA key agreement and on links never silently downgrading to cleartext. Where it is deployed, physical-layer attacks such as tapping and ARP or DHCP spoofing lose their payoff.

## 2. Theory

MACsec (802.1AE) encrypts and integrity-protects Ethernet **frame by frame** between two peers, keys negotiated by MKA (802.1X). It is the 'TLS of layer 2': a tap or rogue device sees only ciphertext, and injected/replayed frames fail the integrity check. This module studies the MKA session and what breaks it.

## 3. Attack (PoC)

```bash
netlab-macsec attack --i-own-this-network --iface veth-host
```

1. Attempt to replay/hijack an MKA session

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-macsec detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- 802.1AE: per-link confidentiality and integrity
- MKA key rotation

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [IEEE 802.1AE (MACsec)](https://1.ieee802.org/security/802-1ae/), IEEE 802.1X-2010 (MKA)
- MACsec deployment and key-agreement guides
