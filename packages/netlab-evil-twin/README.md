# netlab-evil-twin

Clone an AP (SSID/BSSID) to MITM associating clients.

> Scope: Requires a Wi-Fi NIC in monitor mode - not replayable in the netns lab.

Layer **L1** - part of [netsec-lab](../../README.md).

```bash
netlab-evil-twin brief     # what this module teaches
netlab-evil-twin attack --i-own-this-network   # lab only
netlab-evil-twin detect
netlab-evil-twin defend
```

Full lesson: see the [documentation](https://goabonga.github.io/netsec-lab/layer-1-physical/evil-twin/).
