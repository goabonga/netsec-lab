# 802.11 deauthentication

## 1. Context & stakes

Forge deauth/disassoc frames to drop clients or force handshakes.

Pre-802.11w management frames are unauthenticated, so anyone can forge a deauth or disassoc frame that both client and AP obey. That is a trivial denial of service, and it doubles as the trigger that forces a client to reconnect and emit a crackable handshake. Deauth floods knock cameras and IoT devices offline and are the standard first step of WPA capture attacks; 802.11w (PMF) is the fix.

## 2. Theory

In the original 802.11 standard, management frames (deauthentication, disassociation) are **unauthenticated and unencrypted**. Anyone who knows a client/AP MAC pair can forge a deauth (reason code 7) and the association is torn down. Looping them denies service; a single well-timed one forces a client to re-associate, replaying the 4-way handshake an attacker wants.

## 3. Attack (PoC)

```bash
netlab-wifi-deauth attack --i-own-this-network --iface veth-host
```

1. Spoofed deauth flood -> DoS
2. Force a client to re-handshake for capture

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-wifi-deauth detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- 802.11w Protected Management Frames
- WIPS deauth detection

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

This module is **not** replayable in the netns/veth lab - it needs real radio hardware. Build a wireless bench you fully own:

- A Wi-Fi adapter that supports **monitor mode + injection** (e.g. Atheros AR9271, MediaTek MT7612U); enable it with `sudo airmon-ng start wlan0`.
- A **dedicated victim AP you own** (a spare router, or a `hostapd` soft-AP) plus a throwaway client - never a third party's network.
- Run the bench in a shielded / low-traffic area; attacking any network you do not own is illegal.

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- IEEE 802.11w-2009 - Protected Management Frames (the fix)
- [Aircrack-ng](https://www.aircrack-ng.org/): `aireplay-ng --deauth`
- [M. Vanhoef - Wi-Fi security research](https://www.mathyvanhoef.com/)
