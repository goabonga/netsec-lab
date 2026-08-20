# TLS inspection proxy

## 1. Context & stakes

Defensive TLS inspection proxy (SNI filtering, enterprise MITM).

Enterprises inspect TLS either passively, by reading the cleartext SNI in the ClientHello, or actively, by terminating TLS with a trusted CA to see plaintext. Passive SNI filtering enforces egress policy without breaking end-to-end encryption, while active MITM sees everything but turns the proxy into a high-value target. Getting it wrong - a leaked inspection CA key - converts a security control into a universal decryption backdoor.

## 2. How it works

Enterprise TLS inspection terminates TLS at a proxy (its CA trusted by managed hosts), inspects the plaintext, then re-encrypts onward - or filters passively by the **SNI** in the ClientHello without decrypting. This module implements the passive path: read the SNI from a ClientHello and apply an allowlist egress policy, with no MITM and no decryption.

## 3. Commands

```bash
netlab-tls-inspect brief   # teaching brief
netlab-tls-inspect detect --iface veth-host --allow updates.example.com docs.example.com
netlab-tls-inspect defend  # enforce an SNI allowlist over sample handshakes
```

## 4. What it detects

`detect` extracts the SNI from each live ClientHello and applies the `--allow`
list, forwarding allowed names and dropping the rest. `defend` runs the policy
over sample handshakes:

```
[OK] FORWARD   SNI docs.example.com (TLS 1.3) = allow
[XX] DROP      SNI evil-exfil.example.net (TLS 1.3) = block
```

This is passive metadata filtering: the SNI is cleartext in the ClientHello, so
egress policy is enforced without breaking end-to-end encryption.

## 5. Operating it

- Prefer passive SNI filtering where it suffices - it needs no CA and cannot
  leak plaintext.
- If active interception is required, protect the inspection CA key as a
  crown-jewel secret and expect pinning/HSTS breakage.
- Note the blind spot: Encrypted Client Hello (ECH) hides the SNI, so plan for
  it before relying on SNI-only controls.

## 6. Further reading

- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3), [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) (SNI)
- [Durumeric et al., The Security Impact of HTTPS Interception (2017)](https://zakird.com/papers/https_interception.pdf)
