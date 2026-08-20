# Rogue hardware implant

## 1. Context & stakes

Drop a covert network device (implant / BadUSB) onto the wire.

A physical port with no network access control trusts whatever is plugged in, so a covert implant - a small Linux device, a malicious dock, a BadUSB NIC - joins the network as a legitimate host. Because it lives below anything an endpoint agent can see, it survives reimaging and endpoint cleanup. Red-team and espionage operations plant such implants behind desks, inside printers and in conference rooms.

## 2. Theory

Physical access lets an attacker insert hardware into the path: an **inline implant / drop box** (a small computer bridging a link, often with a cellular backchannel), a rogue switch, or a **BadUSB** device that enumerates as a network adapter. It operates below every software control on the host - the network only sees a new or transparently bridged device.

## 3. Attack (PoC)

```bash
netlab-hw-implant attack --i-own-this-network --iface veth-host
```

1. Inline implant / drop box (LAN tap + radio)
2. BadUSB network adapter

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-hw-implant detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- 802.1X port-based NAC, MACsec
- Physical port security and asset inventory

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

This module is **not** replayable in the netns/veth lab - it is a physical attack. Study it only on equipment you own, isolated from production and from other people's wiring/signals:

- Assemble the gear named in the scope note above (e.g. an inline network TAP or a switch mirror port; an SDR such as an RTL-SDR/HackRF with an antenna; or a spare single-board computer as a drop box).
- Keep the bench air-gapped or on an isolated switch.
- Only tap, capture emanations from, or implant onto hardware you own.

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [K. Nohl & J. Lell, BadUSB (2014)](https://srlabs.de/bites/usb-peripherals-turn/)
- NSA ANT catalog (network implants)
- IEEE 802.1X and 802.1AE as countermeasures
