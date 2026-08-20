# Kerberos on the wire

> Scope: Network dimension only - not application-level ticket exploitation.

## 1. Context & stakes

Capture/relay Kerberos tickets at the network level.

Kerberos AS and TGS exchanges cross the wire, and whether captured material helps an attacker depends on the encryption type: legacy RC4 and DES tickets are brute-forceable offline, AES tickets are not. Purely at the network layer an eavesdropper harvests roastable material from weak enctypes and pre-auth. Enforcing AES enctypes and PKINIT removes the offline-crack payoff.

## 2. Theory

Kerberos authenticates via tickets from a KDC (AS-REQ/REP, TGS-REQ/REP) carried over the network. At the **wire** level the exposure is capture and relay of those exchanges/tickets, and pre-auth material usable for offline guessing. This module stays at the network dimension, not application-level ticket abuse.

## 3. Attack (PoC)

```bash
netlab-kerberos-net attack --i-own-this-network --iface veth-host
```

1. Capture AS/TGS exchanges on the wire
2. Ticket relay

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-kerberos-net detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- PKINIT, channel binding
- Strong encryption, relay protection

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) (Kerberos v5), [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) (PKINIT)
- [Impacket](https://github.com/fortra/impacket)
