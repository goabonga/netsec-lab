# TCP SYN flood

## 1. Context & stakes

Exhaust the connection table with half-open connections.

TCP's handshake makes the server allocate state on the first SYN and wait for the final ACK, so a flood of SYNs, often spoofed, with no completion exhausts the backlog and legitimate connections are refused. It is cheap for the attacker and a classic denial of service. SYN cookies let the server stay stateless until the handshake finishes, neutralising the flood.

## 2. Theory

TCP's handshake makes the server allocate state on SYN and wait for the final ACK - a half-open connection. Flooding SYNs (often spoofed) fills the backlog so real handshakes are refused. **SYN cookies** defeat it by encoding the connection state in the SYN/ACK sequence number, allocating nothing until the ACK returns.

## 3. Attack (PoC)

```bash
netlab-synflood attack --i-own-this-network --iface veth-host
```

1. SYN flood with spoofed source
2. Backlog saturation

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-synflood detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- SYN cookies
- conntrack limits, SYN rate-limit

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 4987](https://www.rfc-editor.org/rfc/rfc4987) (TCP SYN flooding and mitigations); CERT CA-1996-21
- [D. J. Bernstein, SYN cookies](https://cr.yp.to/syncookies.html)
