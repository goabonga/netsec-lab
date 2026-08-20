# NTP time-shift MITM

## 1. Context & stakes

Shift the clock to invalidate TLS/Kerberos.

Hosts trust NTP to set their clock, and classic NTP is unauthenticated, so a man-in-the-middle can shift a victim's time arbitrarily. A wrong clock re-enables expired certificates, breaks Kerberos and TOTP, and can slip past validity windows in security tokens. Network Time Security authenticates the time source and closes the vector.

## 2. Theory

Many security checks depend on a correct clock - TLS validity windows, Kerberos ticket lifetimes, certificate expiry, TOTP. An on-path attacker who **shifts a victim's clock** via NTP can make expired certificates look valid or replayed tickets acceptable. NTS (Network Time Security) authenticates the time source.

## 3. Attack (PoC)

```bash
netlab-ntp attack --i-own-this-network --iface veth-host
```

1. NTP MITM -> clock shift
2. Break validity windows

<!-- TODO: what to observe on the wire -->

## 4. Detection

```bash
netlab-ntp detect --iface veth-host
```

Indicators to watch, and the associated IDS rule (see
[`netlab-ids`](../defensive-tooling/ids.md)).

<!-- TODO: concrete indicators + Suricata/Snort rule -->

## 5. Defense

- NTS (Network Time Security)
- Multiple authenticated sources

<!-- TODO: switch/router/host countermeasure + real config snippet -->

## 6. Exercise

Reproduce in the isolated lab (netns/veth): see [lab setup](../lab-setup.md).

<!-- TODO: step-by-step exercise -->

## 7. Further reading

- [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905) (NTPv4), [RFC 8915](https://www.rfc-editor.org/rfc/rfc8915) (Network Time Security)
- [Malhotra et al., Attacking the Network Time Protocol (2016)](https://eprint.iacr.org/2015/1020)
