# WPA/WPA2 handshake & PMKID crack

## 1. Context & stakes

Capture the 4-way handshake or PMKID and crack the PSK offline.

WPA2-PSK derives every session key from one passphrase, so capturing the 4-way handshake, or even a single PMKID from the AP, gives an attacker everything needed to brute-force that passphrase offline at full GPU speed, with the AP never involved again. Weak or reused PSKs fall in seconds. This is why WPA3-SAE and long random passphrases matter for any shared-key network.

## 2. Theory

WPA2-PSK derives session keys from a **4-way handshake** (ANonce, SNonce, MICs), all keyed by PMK = PBKDF2(passphrase, SSID). The handshake travels in the clear, so capturing it - or the **PMKID** the AP places in message 1 - lets an attacker test passphrases offline: recompute the PMK per candidate and check the MIC. WPA3-SAE replaces this with a PAKE that resists offline guessing.

## 3. Attack (PoC)

```bash
netlab-wpa-crack attack --i-own-this-network --iface veth-host
```

1. Capture handshake (deauth-assisted) or PMKID
2. Offline dictionary / GPU crack

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-wpa-crack detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Long random passphrase or WPA3-SAE
- Enterprise auth (no shared PSK)

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

This module is **not** replayable in the netns/veth lab - it needs real radio hardware. Build a wireless bench you fully own:

- A Wi-Fi adapter that supports **monitor mode + injection** (e.g. Atheros AR9271, MediaTek MT7612U); enable it with `sudo airmon-ng start wlan0`.
- A **dedicated victim AP you own** (a spare router, or a `hostapd` soft-AP) plus a throwaway client - never a third party's network.
- Run the bench in a shielded / low-traffic area; attacking any network you do not own is illegal.

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- IEEE 802.11i (4-way handshake); WPA3-SAE in IEEE 802.11-2020
- [hashcat](https://hashcat.net/hashcat/) (mode 22000); [clientless PMKID attack](https://hashcat.net/forum/thread-7717.html)
- [RFC 7664](https://www.rfc-editor.org/rfc/rfc7664) - Dragonfly (SAE) key exchange
