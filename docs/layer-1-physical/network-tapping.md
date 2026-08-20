# Passive network tapping

## 1. Context & stakes

Intercept traffic by tapping the physical medium (copper or fibre).

Copper and fibre carry data with no built-in confidentiality, so anyone with physical access can insert an inline tap or bend a fibre to siphon a copy of every frame, passively and with no trace above the physical layer. The only real defences are physical security and end-to-end encryption such as MACsec or TLS. Cable-vault and riser taps are a classic lawful-intercept and espionage technique precisely because they leave no packet evidence.

## 2. Theory

Ethernet and fibre carry frames as electrical/optical signals on shared media. A **passive tap** copies those signals without breaking the link: a vampire/inline TAP on copper, or a bend/splitter coupler that leaks a fraction of the light on fibre. The victim sees no latency or link change; anything not end-to-end encrypted is readable - the physical analogue of a SPAN port.

## 3. Attack (PoC)

```bash
netlab-tap attack --i-own-this-network --iface veth-host
```

1. Inline TAP / vampire tap on copper
2. Fibre tapping via a bend coupler

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-tap detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- MACsec (802.1AE) link encryption
- Tamper-evident cabling and conduit

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

This module is **not** replayable in the netns/veth lab - it is a physical attack. Study it only on equipment you own, isolated from production and from other people's wiring/signals:

- Assemble the gear named in the scope note above (e.g. an inline network TAP or a switch mirror port; an SDR such as an RTL-SDR/HackRF with an antenna; or a spare single-board computer as a drop box).
- Keep the bench air-gapped or on an isolated switch.
- Only tap, capture emanations from, or implant onto hardware you own.

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [IEEE 802.1AE (MACsec)](https://1.ieee802.org/security/802-1ae/) - the encryption countermeasure
- Optical fibre tapping (bend couplers); passive network TAPs
- [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final): physical and environmental protection
