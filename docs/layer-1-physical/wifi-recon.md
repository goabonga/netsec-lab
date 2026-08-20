# 802.11 passive reconnaissance

## 1. Context & stakes

Harvest SSIDs, BSSIDs and clients from the air, passively.

802.11 beacons and probe requests are broadcast in the clear, so SSIDs, BSSIDs, client MACs and vendor fingerprints can be harvested purely by listening, with no association and no trace. This passive map is the reconnaissance that precedes every active Wi-Fi attack. Logging probe requests also enables physical tracking of individuals through their devices' MAC history.

## 2. Theory

802.11 stations announce themselves continuously. Access points broadcast **beacon** frames (SSID, BSSID, channel, rates, security) ~10x/s, and clients emit **probe requests** naming networks they have joined before. A NIC in monitor mode captures all of it passively - no association, nothing sent - so the airspace (APs, clients, even hidden SSIDs) is mapped from radio alone.

## 3. Attack (PoC)

```bash
netlab-wifi-recon attack --i-own-this-network --iface veth-host
```

1. Sniff beacons/probe requests in monitor mode
2. Map APs, clients and hidden SSIDs

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-wifi-recon detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Minimise beacon info; treat SSID hiding as weak
- WIDS/WIPS airspace monitoring

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

This module is **not** replayable in the netns/veth lab - it needs real radio hardware. Build a wireless bench you fully own:

- A Wi-Fi adapter that supports **monitor mode + injection** (e.g. Atheros AR9271, MediaTek MT7612U); enable it with `sudo airmon-ng start wlan0`.
- A **dedicated victim AP you own** (a spare router, or a `hostapd` soft-AP) plus a throwaway client - never a third party's network.
- Run the bench in a shielded / low-traffic area; attacking any network you do not own is illegal.

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- IEEE 802.11-2020, clause 11 (beacon and probe management frames)
- [Aircrack-ng](https://www.aircrack-ng.org/) (`airodump-ng`), [Kismet](https://www.kismetwireless.net/)
