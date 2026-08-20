# QUIC / HTTP3 fingerprinting

## 1. Context & stakes

Recon and inspection challenges of an encrypted UDP transport.

QUIC carries HTTP/3 over UDP with almost everything encrypted; only the Initial packet's long header exposes the version and a partly-visible ClientHello with the SNI, while established short-header packets are opaque. Middleboxes that relied on inspecting TCP and TLS lose visibility, so both recon and policy enforcement move to that one Initial. Knowing what stays visible is the basis for any QUIC-aware control.

## 2. Theory

QUIC runs an encrypted transport over UDP: after the first **Initial** packet (whose header/SNI is partly visible) everything - including the handshake - is encrypted and multiplexed. That defeats classic TCP/TLS middlebox inspection, so recon fingerprints the Initial and flow behaviour rather than reading the stream.

## 3. Attack (PoC)

QUIC fingerprinting is passive, so the lab needs QUIC on the wire: `attack` emits it (a long-header Initial carrying a stand-in ClientHello with the SNI, and an opaque short-header packet) and `detect` classifies it. Run the observer first, then emit from the attacker namespace:

```bash
# terminal 1 - observer on the host side
netlab-quic detect --iface veth-host
```

```bash
# terminal 2 - emitter in the attacker namespace
sudo ip netns exec attacker netlab-quic attack --i-own-this-network --iface veth-ns --sni example.com
```

The observer classifies each packet on UDP/443:

```
[..] INFO      long header (Initial/Handshake): version + SNI fingerprintable
[..] INFO      short header: fully encrypted, opaque to inspection
```

The Initial's long header exposes the version and SNI - the recon and filtering hook - while short-header packets stay opaque.

## 4. Detection

```bash
netlab-quic detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- SNI from the Initial packet
- Flow heuristics

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) (QUIC), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) (QUIC-TLS)
- QUIC fingerprinting and Initial-packet analysis research
