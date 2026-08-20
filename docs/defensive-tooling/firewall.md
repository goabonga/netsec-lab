# Firewall policy

## 1. Context & stakes

nftables/iptables policy and validation that it blocks the PoC.

A stateful firewall filters by 5-tuple and connection state; the risk is rarely the engine and almost always the policy - a shadowed rule, an implicit allow, or a missing default-deny lets traffic through. This module treats each PoC as a test case, so a rule that a live attack still slips past is a concrete gap rather than a theoretical one. In production a single mis-ordered ACL has exposed management planes and databases to the whole Internet.

## 2. How it works

A stateful firewall (nftables/iptables) filters by tuple and connection state, default-deny with explicit allows. This module models an ordered ACL evaluated first-match over a default-deny policy, plus stateful inspection: return traffic of an established connection is allowed without an explicit rule.

## 3. Commands

```bash
netlab-firewall brief                    # teaching brief
netlab-firewall detect --iface veth-host # evaluate live traffic against the ACL
netlab-firewall defend                   # demonstrate the default-deny policy
```

## 4. What it detects

`detect` classifies each live TCP packet against the policy and reports anything
the ruleset denies. `defend` runs the reference policy (allow outbound 80/443,
allow established, default-deny) over sample packets:

```
[OK] FORWARD   tcp 10.0.0.5 -> 93.184.216.34:443 = allow
[XX] DROP      tcp 203.0.113.9 -> 10.0.0.5:22 = deny
[OK] FORWARD   tcp 93.184.216.34 -> 10.0.0.5:51000 = allow
```

The third packet is inbound but allowed because it is the return traffic of an
established connection - the point of stateful inspection.

## 5. Operating it

- Translate the reference policy into real `nft`/`iptables` rules: default-deny,
  explicit allows, `ct state established,related accept`.
- Replay each offensive PoC against the policy; a rule that still lets an attack
  through is a concrete gap, not a hypothetical one.
- Watch rule order: a broad allow above a specific deny (a shadowed rule) is the
  most common real-world mistake.

## 6. Further reading

- [nftables wiki](https://wiki.nftables.org/), [netfilter](https://www.netfilter.org/)
- Default-deny policy design
