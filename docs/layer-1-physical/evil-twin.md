# Evil twin / rogue AP

## 1. Context & stakes

Clone an AP (SSID/BSSID) to MITM associating clients.

Wi-Fi clients identify an access point by its SSID and roam to the strongest signal, with no mutual authentication on open or PSK networks. An attacker clones the SSID and BSSID with a stronger signal so victims associate to the rogue AP and route all their traffic through it. Captive-portal clones and free-Wi-Fi twins are a staple of credential theft in airports, hotels and conferences.

## 2. Theory

Clients roam by SSID, not BSSID, and many probe for known networks. An attacker raises an AP with the **same SSID** (often a stronger signal); with *karma* it answers every probe, so clients auto-associate. Traffic then flows through the attacker (DNS/HTTP MITM, captive portal) - the victim sees the expected name and never notices the BSSID changed.

## 3. Attack (PoC)

```bash
netlab-evil-twin attack --i-own-this-network --iface veth-host
```

1. Karma / known-beacon responses
2. Captive-portal credential capture, MITM

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-evil-twin detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- 802.1X/EAP-TLS with server-cert validation
- WIPS rogue-AP detection

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

This module is **not** replayable in the netns/veth lab - it needs real radio hardware. Build a wireless bench you fully own:

- A Wi-Fi adapter that supports **monitor mode + injection** (e.g. Atheros AR9271, MediaTek MT7612U); enable it with `sudo airmon-ng start wlan0`.
- A **dedicated victim AP you own** (a spare router, or a `hostapd` soft-AP) plus a throwaway client - never a third party's network.
- Run the bench in a shielded / low-traffic area; attacking any network you do not own is illegal.

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- Dai Zovi & Macaulay, KARMA attacks (2005)
- [hostapd-wpe](https://github.com/OpenSecurityResearch/hostapd-wpe), [wifiphisher](https://github.com/wifiphisher/wifiphisher)
- [RFC 8952](https://www.rfc-editor.org/rfc/rfc8952) - Captive Portal Architecture
