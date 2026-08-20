# Lab setup

Every PoC is designed to run on an **isolated Layer-2 segment** built from a
Linux network namespace and a `veth` pair. Nothing leaves your host.

## Install

```bash
git clone https://github.com/goabonga/netsec-lab
cd netsec-lab
uv sync                       # workspace + all packages + scapy
```

## Build the isolated segment

The `netlab-core` package ships `VethLab`, but you can also do it by hand:

```bash
sudo ip netns add attacker
sudo ip link add veth-host type veth peer name veth-ns
sudo ip link set veth-ns netns attacker
sudo ip link set veth-host up
sudo ip netns exec attacker ip link set veth-ns up
```

- `veth-host` stays on the host - run detectors and defenders here.
- `veth-ns` lives in the `attacker` namespace - run offensive PoC here:

```bash
sudo ip netns exec attacker netlab-dhcp attack --i-own-this-network --iface veth-ns
```

Tear everything down (also removes the veth):

```bash
sudo ip netns del attacker
```

## Consent guardrail

Offensive subcommands emit real traffic and **refuse to start** without an
explicit `--i-own-this-network` flag. This is a deliberate friction: it forces
you to acknowledge, every single run, that you own the segment.

## Privileges

Sniffing and raw packet injection need `CAP_NET_RAW` - run the offensive and
detection subcommands with `sudo` (or grant the capability). The `brief`
subcommand needs nothing and works everywhere.
