# netlab-wifi-deauth

Forge deauth/disassoc frames to drop clients or force handshakes.

> Scope: Requires a Wi-Fi NIC in monitor mode - not replayable in the netns lab.

Layer **L1** - part of [netsec-lab](../../README.md).

```bash
netlab-wifi-deauth brief     # what this module teaches
netlab-wifi-deauth attack --i-own-this-network   # lab only
netlab-wifi-deauth detect
netlab-wifi-deauth defend
```

Full lesson: see the [documentation](layer-1-physical/wifi-deauth.md).
