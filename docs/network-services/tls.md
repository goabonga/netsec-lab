# TLS downgrade / MITM

## 1. Context & stakes

SSL stripping, downgrade and proxy MITM.

TLS protects data in transit, but the jump from an initial cleartext HTTP request to HTTPS is a seam: SSL stripping keeps the victim on HTTP while the attacker speaks HTTPS upstream, and downgrade tricks force weaker parameters. The user sees a working page while credentials cross in the clear. Preloaded HSTS and encrypted-by-default origins remove the stripping window.

## 2. Theory

TLS protects a session once established, but the *bootstrap* is attackable on-path: **SSL stripping** keeps the victim on HTTP by rewriting HTTPS links, **downgrade** forces weaker versions/ciphers, and a **MITM proxy** presents a forged certificate. Defences: HSTS (preload), strict validation/pinning and modern TLS that removes downgrade vectors.

## 3. Attack (PoC)

```bash
netlab-tls attack --i-own-this-network --iface veth-host
```

1. SSL strip (HTTP<->HTTPS)
2. Version downgrade, bogus cert

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-tls detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- HSTS (preload)
- Pinning, strict chain validation

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3), [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) (HSTS)
- M. Marlinspike, sslstrip (2009); [POODLE (CVE-2014-3566)](https://nvd.nist.gov/vuln/detail/CVE-2014-3566)
