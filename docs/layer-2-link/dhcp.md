# DHCP snooping

## 1. Context & stakes

Rogue DHCP server (MITM) and DHCP starvation against a pool.

DHCP is unauthenticated, so a client simply accepts the first OFFER it sees. A rogue server can hand out its own address as the default gateway and DNS for instant MITM, while a starvation flood drains the legitimate pool so only the rogue answers. Rogue DHCP is a classic LAN foothold, and DHCP snooping on trusted ports is the standard countermeasure.

## 2. Theory

DHCP assigns addresses through the **DORA** exchange, and nothing authenticates the server, so the client trusts the first/fastest OFFER - which is exactly what a rogue server abuses to hand out its own gateway and DNS.

```
client  --DISCOVER-->  (broadcast)
client  <--OFFER----   server  (ip, mask, gw, dns)
client  --REQUEST-->  (broadcast)
client  <--ACK------   server  (lease)
```

## 3. Attack (PoC)

```bash
netlab-dhcp attack --i-own-this-network --iface veth-host
```

1. Rogue server: answer OFFER/ACK with attacker gw/DNS -> MITM
2. Starvation: flood DISCOVER with random MACs to drain the pool

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-dhcp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- DHCP snooping: trusted/untrusted ports, drop untrusted OFFER
- IP Source Guard from the binding table
- Per-port DISCOVER rate-limit

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131) (DHCP), [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132) (options), [RFC 3046](https://www.rfc-editor.org/rfc/rfc3046) (Option 82)
- DHCP snooping / IP Source Guard - switch configuration guides
