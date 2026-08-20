# Methodology

Every module in netsec-lab is built around the same loop. Learning an attack
in isolation teaches you to break something; learning it next to its detection
and its defense teaches you to *secure* it. That pairing is the whole point.

## The attack → detect → defend loop

1. **Attack** - `netlab-<x> attack --i-own-this-network`
   Reproduce the attack on the isolated segment and watch it work on the wire.
2. **Detect** - `netlab-<x> detect`
   Observe the signature the attack leaves, and the IDS rule that catches it.
3. **Defend** - `netlab-<x> defend`
   Apply the countermeasure (switch/router/host) and confirm the attack now
   fails - then map it to the equivalent real-world device configuration.

## Every documentation page follows the same template

1. **Context & stakes** - the protocol and why it is exploitable.
2. **Theory** - the mechanism (exchange diagram, frame format).
3. **Attack (PoC)** - the command and what to observe.
4. **Detection** - indicators and the associated IDS rule.
5. **Defense** - the countermeasure and its real configuration.
6. **Exercise** - reproduce it yourself in the lab.
7. **Further reading** - RFCs, CVEs, papers.

## Brief-driven docs

Each package carries a structured `Lesson` (title, layer, summary, attack,
defense). Run `netlab-<x> brief` to print it - the first five sections of each
doc page are seeded from that same object, so **code and docs never drift**.
