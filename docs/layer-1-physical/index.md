# Layer 1 - Physical

The physical layer: media, radio and hardware. These attacks need physical access or radio gear, so - unlike every other module - they are NOT replayable in the netns/veth lab. They are documented for awareness, with the countermeasures that contain them.

## Modules

- [802.11 passive reconnaissance](wifi-recon.md) - Harvest SSIDs, BSSIDs and clients from the air, passively. (`netlab-wifi-recon`)
- [802.11 deauthentication](wifi-deauth.md) - Forge deauth/disassoc frames to drop clients or force handshakes. (`netlab-wifi-deauth`)
- [Evil twin / rogue AP](evil-twin.md) - Clone an AP (SSID/BSSID) to MITM associating clients. (`netlab-evil-twin`)
- [WPA/WPA2 handshake & PMKID crack](wpa-crack.md) - Capture the 4-way handshake or PMKID and crack the PSK offline. (`netlab-wpa-crack`)
- [WPS PIN brute force](wps-brute.md) - Recover the WPA PSK via the WPS PIN (online brute or Pixie-Dust). (`netlab-wps-brute`)
- [Passive network tapping](network-tapping.md) - Intercept traffic by tapping the physical medium (copper or fibre). (`netlab-tap`)
- [TEMPEST / Van Eck emanations](tempest.md) - Reconstruct data from unintended electromagnetic emanations. (`netlab-tempest`)
- [Rogue hardware implant](hardware-implant.md) - Drop a covert network device (implant / BadUSB) onto the wire. (`netlab-hw-implant`)
