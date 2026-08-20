# WPS PIN brute force

## 1. Context & stakes

Recover the WPA PSK via the WPS PIN (online brute or Pixie-Dust).

WPS was meant to simplify onboarding with an 8-digit PIN, but the protocol checks the PIN in two halves and reveals which half is wrong, collapsing the search space from 100 million to about 11000; Pixie-Dust reduces many APs to an offline computation. A recovered PIN yields the full WPA PSK no matter how strong it is. WPS shipped on by default on millions of consumer routers and remains a one-command compromise.

## 2. Theory

Wi-Fi Protected Setup joins a client with an 8-digit PIN validated in **two halves**, and the registrar reveals which half is wrong - cutting the search from 10^8 to ~11000. *Pixie-Dust* is worse: weak nonces/PRNG in some chipsets recover the PIN offline from a single exchange. A recovered PIN yields the full WPA passphrase.

## 3. Attack (PoC)

```bash
netlab-wps-brute attack --i-own-this-network --iface veth-host
```

1. Online PIN brute (reaver)
2. Pixie-Dust offline PIN recovery

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-wps-brute detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Disable WPS
- PIN lockout / rate-limit

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

This module is **not** replayable in the netns/veth lab - it needs real radio hardware. Build a wireless bench you fully own:

- A Wi-Fi adapter that supports **monitor mode + injection** (e.g. Atheros AR9271, MediaTek MT7612U); enable it with `sudo airmon-ng start wlan0`.
- A **dedicated victim AP you own** (a spare router, or a `hostapd` soft-AP) plus a throwaway client - never a third party's network.
- Run the bench in a shielded / low-traffic area; attacking any network you do not own is illegal.

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [S. Viehboeck, Brute forcing WPS (2011)](https://sviehb.files.wordpress.com/2011/12/viehboeck_wps.pdf)
- D. Bongard, Pixie-Dust offline PIN recovery (2014)
- [reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x)
