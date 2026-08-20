# TCP session hijacking

## 1. Context & stakes

Inject into / reset an established TCP session.

A TCP session is authenticated only by its 4-tuple and sequence numbers, so an attacker who can observe or predict them injects data or a forged RST into an established connection. On-path this is trivial and enables command injection or teardown of unencrypted sessions. End-to-end encryption such as TLS or SSH, plus randomised sequence numbers, is why this is far harder than it once was.

## 2. Theory

A TCP connection is identified by its 4-tuple and trusted by **sequence numbers**. An on-path attacker (or one who predicts the sequence) injects a forged segment - a RST to tear the connection down, or data spliced into the stream. Randomised ISNs and TCP-AO raise the bar.

## 3. Attack (PoC)

```bash
netlab-tcphijack attack --i-own-this-network --iface veth-host
```

1. RST injection
2. Sequence-number prediction, hijack

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-tcphijack detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- ISN randomization
- TCP-AO / integrity

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 793](https://www.rfc-editor.org/rfc/rfc793); [RFC 6528](https://www.rfc-editor.org/rfc/rfc6528) (ISN randomization), [RFC 5925](https://www.rfc-editor.org/rfc/rfc5925) (TCP-AO)
- R. Morris, A weakness in the 4.2BSD TCP/IP (1985); [RFC 1948](https://www.rfc-editor.org/rfc/rfc1948)
