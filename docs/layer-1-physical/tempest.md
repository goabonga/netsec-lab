# TEMPEST / Van Eck emanations

## 1. Context & stakes

Reconstruct data from unintended electromagnetic emanations.

Every wire and display radiates unintended electromagnetic emanations correlated with the data it handles, and with a receiver and some signal processing an eavesdropper can reconstruct that data at a distance with no network access at all. This is the threat that TEMPEST shielding standards exist to counter. Van Eck publicly reconstructed screen contents in 1985, and the technique still drives shielding requirements for classified facilities.

## 2. Theory

Digital circuits (video cables, keyboards, CPUs) radiate unintended **electromagnetic emanations** correlated with the data they process - the classic *Van Eck* screen reconstruction. With an antenna and an SDR tuned to the right harmonic, an eavesdropper rebuilds the signal from a distance, with no network access at all. The defence is physical: shielding, zoning, TEMPEST-rated gear.

## 3. Attack (PoC)

```bash
netlab-tempest attack --i-own-this-network --iface veth-host
```

1. Capture EM emanations (screen/cable)
2. Reconstruct the leaked signal

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-tempest detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Shielding (Faraday), EMSEC zoning
- TEMPEST-rated equipment

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

This module is **not** replayable in the netns/veth lab - it is a physical attack. Study it only on equipment you own, isolated from production and from other people's wiring/signals:

- Assemble the gear named in the scope note above (e.g. an inline network TAP or a switch mirror port; an SDR such as an RTL-SDR/HackRF with an antenna; or a spare single-board computer as a drop box).
- Keep the bench air-gapped or on an isolated switch.
- Only tap, capture emanations from, or implant onto hardware you own.

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [M. Kuhn, Compromising emanations (Cambridge, 2003)](https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-577.pdf)
- W. van Eck, Electromagnetic Radiation from Video Display Units (1985)
- NATO SDIP-27 / NSTISSAM TEMPEST/1-92
