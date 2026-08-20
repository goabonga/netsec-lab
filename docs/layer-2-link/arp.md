# ARP spoofing

## 1. Context & stakes

Poison the ARP cache to intercept LAN traffic.

ARP has no authentication: a host caches whatever MAC-for-IP reply it hears, including unsolicited ones. By forging gratuitous ARP replies an attacker binds the gateway's IP to their own MAC and becomes a transparent man-in-the-middle for the whole subnet. ARP spoofing underpins most LAN MITM tooling and is countered by Dynamic ARP Inspection tied to DHCP snooping.

## 2. Theory

ARP resolves an IPv4 address to a MAC by broadcasting 'who has X?'; the owner replies 'X is at `aa:bb:cc:dd:ee:ff`'. Hosts cache replies **without checking they asked**, including unsolicited *gratuitous* ARP. An attacker forges replies mapping the gateway IP to its own MAC (and the victim's IP back to it), so both sides send their traffic through the attacker.

## 3. Attack (PoC)

```bash
netlab-arp attack --i-own-this-network --iface veth-host
```

1. Gratuitous ARP to impersonate the gateway
2. Bidirectional client<->gw MITM

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-arp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule.

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- Dynamic ARP Inspection backed by the DHCP binding
- arpwatch, static entries

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 826](https://www.rfc-editor.org/rfc/rfc826) (ARP)
- Dynamic ARP Inspection (switch config); [arpwatch](https://ee.lbl.gov/)
- [dsniff](https://www.monkey.org/~dugsong/dsniff/) (`arpspoof`), [ettercap](https://www.ettercap-project.org/)
