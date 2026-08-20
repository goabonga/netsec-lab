# SNMP enumeration

## 1. Context & stakes

Enumerate via weak community strings.

SNMP v1 and v2c authenticate with a plaintext community string that is often left at public or private, and a read community exposes the entire device configuration, routing tables and interface data. Enumerating it is a one-packet reconnaissance win and sometimes a write-access compromise. SNMPv3 with per-user auth and privacy, and removing default communities, are the fixes.

## 2. Theory

SNMP manages devices via a MIB tree, authenticated in v1/v2c only by a plaintext **community string** (often 'public'/'private'). Guessing it lets an attacker **walk** the MIB (config, ARP/routing tables, interfaces) and sometimes write. SNMPv3 adds real auth+privacy; management ACLs restrict who may ask.

## 3. Attack (PoC)

```bash
netlab-snmp attack --i-own-this-network --iface veth-host
```

1. Brute communities (public/private)
2. Walk the MIB

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-snmp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- SNMPv3 (auth+priv)
- Management ACL

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 1157](https://www.rfc-editor.org/rfc/rfc1157) (SNMPv1), [RFC 3411](https://www.rfc-editor.org/rfc/rfc3411) (SNMPv3 framework)
- [onesixtyone](https://github.com/trailofbits/onesixtyone); [net-snmp](https://www.net-snmp.org/) `snmpwalk`
