# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""IDS rule harness: a content-match engine plus a rule catalogue for every PoC.

Two layers:

* a minimal signature engine (Snort/Suricata-style ``content`` match) with a
  scorer that replays labelled traffic and reports detections / false positives;
* ``CATALOGUE`` - one reference Suricata rule per offensive PoC in this repo, so
  the harness ships blue-team coverage for the whole attack set. Wireless / RF
  PoC (Layer 1) carry a note instead of a wire rule: a wired IDS cannot see them,
  a WIDS (e.g. Kismet) is the right tool.

Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict

# ruff: noqa: E501 - Suricata rule strings in CATALOGUE are data, one signature per line.


@dataclass
class Rule:
    sid: int
    msg: str
    contains: bytes

    def matches(self, payload: bytes) -> bool:
        return self.contains in payload


@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)

    def alerts(self, payload: bytes) -> list[Rule]:
        return [r for r in self.rules if r.matches(payload)]


@dataclass
class Sample:
    payload: bytes
    malicious: bool


def score(ruleset: RuleSet, samples: list[Sample]) -> dict[str, int]:
    """Replay samples through the rule set; return a confusion matrix."""
    m = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for s in samples:
        fired = bool(ruleset.alerts(s.payload))
        if s.malicious and fired:
            m["tp"] += 1
        elif s.malicious and not fired:
            m["fn"] += 1
        elif not s.malicious and fired:
            m["fp"] += 1
        else:
            m["tn"] += 1
    return m


@dataclass(frozen=True)
class SigRule:
    """A reference detection rule attached to the PoC it covers."""

    sid: int
    poc: str
    msg: str
    rule: str  # a Suricata rule line, or a "note: ..." where no wire signature applies


# One reference rule per offensive PoC. sids are grouped by layer (21xxxxx).
CATALOGUE: tuple[SigRule, ...] = (
    # Layer 1 - Physical / wireless: invisible to a wired IDS, use a WIDS.
    SigRule(
        2110001,
        "wifi-recon",
        "802.11 passive recon",
        "note: RF layer - use a WIDS (Kismet), not a wire IDS",
    ),
    SigRule(
        2110002,
        "wifi-deauth",
        "802.11 deauth flood",
        "note: RF layer - WIDS deauth-flood detector / 802.11w PMF",
    ),
    SigRule(
        2110003,
        "evil-twin",
        "rogue AP / evil twin",
        "note: RF layer - WIDS rogue-SSID/BSSID monitor",
    ),
    SigRule(
        2110004,
        "wpa-crack",
        "WPA handshake / PMKID capture",
        "note: RF layer - WIDS EAPOL capture monitor",
    ),
    SigRule(
        2110005,
        "wps-brute",
        "WPS PIN brute force",
        "note: RF layer - WIDS WPS M-message rate monitor",
    ),
    SigRule(
        2110006,
        "tap",
        "passive network tap",
        "note: physical layer - link-integrity / TDR, no packets to match",
    ),
    SigRule(
        2110007,
        "tempest",
        "TEMPEST emanation capture",
        "note: physical layer - RF emanation, no packets to match",
    ),
    SigRule(
        2110008,
        "hw-implant",
        "rogue hardware implant",
        "note: NAC / 802.1X + switch-port inventory, not a wire signature",
    ),
    # Layer 2 - Data Link
    SigRule(
        2120001,
        "dhcp",
        "rogue DHCP server offer",
        'alert udp !$DHCP_SERVERS 67 -> any 68 (msg:"NETLAB rogue DHCP OFFER"; dhcp.type:offer; sid:2120001; rev:1;)',
    ),
    SigRule(
        2120002,
        "arp",
        "ARP spoofing / gratuitous flood",
        "note: L2 - arp-table anomaly (DAI), Suricata ARP visibility is limited",
    ),
    SigRule(
        2120003,
        "macflood",
        "CAM table overflow",
        "note: L2 - new-source-MAC rate per port (port-security), not a content rule",
    ),
    SigRule(
        2120004,
        "stp",
        "rogue BPDU / root takeover",
        "note: L2 - unexpected superior BPDU (BPDU guard), non-IP frame",
    ),
    SigRule(
        2120005,
        "vlan",
        "double-tagged 802.1Q hop",
        "note: L2 - nested 802.1Q tags on an access port, non-IP frame",
    ),
    SigRule(
        2120006,
        "ipv6-ra",
        "rogue IPv6 Router Advertisement",
        'alert ipv6 any any -> ff02::1 any (msg:"NETLAB rogue IPv6 RA"; icmpv6.mtype:134; sid:2120006; rev:1;)',
    ),
    SigRule(
        2120007,
        "discovery",
        "CDP/LLDP enumeration",
        "note: L2 - unexpected CDP/LLDP TLVs from an access port",
    ),
    SigRule(
        2120008,
        "lldp-med",
        "LLDP-MED voice-VLAN abuse",
        "note: L2 - spoofed LLDP-MED network-policy TLV",
    ),
    SigRule(
        2120009,
        "8021x",
        "802.1X / NAC bypass",
        "note: L2 - EAPOL state anomaly on a controlled port",
    ),
    SigRule(
        2120010,
        "macsec",
        "MACsec downgrade to cleartext",
        "note: L2 - SecTAG (ethertype 0x88e5) absent on a protected link",
    ),
    # Layer 3 - Network
    SigRule(
        2130001,
        "ipspoof",
        "spoofed source outside local prefix",
        'alert ip ![$HOME_NET] any -> $HOME_NET any (msg:"NETLAB spoofed source (uRPF)"; sid:2130001; rev:1;)',
    ),
    SigRule(
        2130002,
        "icmp",
        "ICMP redirect injection",
        'alert icmp any any -> any any (msg:"NETLAB ICMP redirect"; itype:5; sid:2130002; rev:1;)',
    ),
    SigRule(
        2130003,
        "frag",
        "overlapping IP fragments",
        'alert ip any any -> any any (msg:"NETLAB overlapping fragment"; fragbits:M; ip_proto:!6; sid:2130003; rev:1;)',
    ),
    SigRule(
        2130004,
        "routing",
        "unsolicited RIP route response",
        'alert udp any any -> any 520 (msg:"NETLAB unsolicited RIP response"; content:"|02 02|"; offset:0; depth:2; sid:2130004; rev:1;)',
    ),
    SigRule(
        2130005,
        "igmp",
        "forged IGMP membership report",
        'alert ip any any -> any any (msg:"NETLAB IGMP anomaly"; ip_proto:2; sid:2130005; rev:1;)',
    ),
    SigRule(
        2130006,
        "bgp",
        "unexpected BGP OPEN (hijack sim)",
        'alert tcp any any -> any 179 (msg:"NETLAB unexpected BGP OPEN"; flow:to_server,established; content:"|01|"; offset:18; depth:1; sid:2130006; rev:1;)',
    ),
    SigRule(
        2130007,
        "vrrp-hsrp",
        "FHRP takeover advertisement",
        'alert ip any any -> 224.0.0.18 any (msg:"NETLAB VRRP advertisement"; ip_proto:112; sid:2130007; rev:1;)',
    ),
    # Layer 4 - Transport
    SigRule(
        2140001,
        "portscan",
        "TCP SYN scan",
        'alert tcp any any -> $HOME_NET any (msg:"NETLAB TCP SYN scan"; flags:S,12; threshold:type both, track by_src, count 30, seconds 5; sid:2140001; rev:1;)',
    ),
    SigRule(
        2140002,
        "synflood",
        "TCP SYN flood",
        'alert tcp any any -> $HOME_NET any (msg:"NETLAB SYN flood"; flags:S,12; threshold:type threshold, track by_dst, count 100, seconds 1; sid:2140002; rev:1;)',
    ),
    SigRule(
        2140003,
        "tcphijack",
        "injected RST/data in session",
        'alert tcp any any -> any any (msg:"NETLAB TCP injected RST"; flags:R; threshold:type both, track by_dst, count 5, seconds 2; sid:2140003; rev:1;)',
    ),
    SigRule(
        2140004,
        "amplif",
        "reflection/amplification response",
        'alert udp any 53 -> $HOME_NET any (msg:"NETLAB DNS amplification (large response)"; dsize:>512; sid:2140004; rev:1;)',
    ),
    SigRule(
        2140005,
        "ids-evasion",
        "low-TTL insertion / evasion",
        'alert tcp any any -> any any (msg:"NETLAB low-TTL insertion"; ttl:<6; flow:to_server; sid:2140005; rev:1;)',
    ),
    SigRule(
        2140006,
        "covert",
        "IP ID covert channel",
        'alert ip any any -> any any (msg:"NETLAB IP ID covert channel"; ip_proto:1; itype:8; dsize:0; sid:2140006; rev:1;)',
    ),
    # Network services
    SigRule(
        2150001,
        "dns",
        "DNS cache poisoning / spoofed answer",
        'alert dns any any -> any any (msg:"NETLAB DNS spoofed answer"; dns.flags.rd; dns.answer.count:>0; sid:2150001; rev:1;)',
    ),
    SigRule(
        2150002,
        "dnstunnel",
        "DNS tunneling (long/high-entropy label)",
        'alert dns any any -> any any (msg:"NETLAB DNS tunneling"; dns.query; pcre:"/[a-f0-9]{32,}/i"; sid:2150002; rev:1;)',
    ),
    SigRule(
        2150003,
        "icmptunnel",
        "ICMP tunneling (oversized echo)",
        'alert icmp any any -> any any (msg:"NETLAB ICMP tunneling"; itype:8; dsize:>64; sid:2150003; rev:1;)',
    ),
    SigRule(
        2150004,
        "tls",
        "TLS downgrade / SSL strip",
        'alert http any any -> any any (msg:"NETLAB cleartext login after HTTPS (SSL strip)"; http.uri; content:"password="; nocase; sid:2150004; rev:1;)',
    ),
    SigRule(
        2150005,
        "snmp",
        "SNMP community brute force",
        'alert udp any any -> any 161 (msg:"NETLAB SNMP community brute force"; content:"public"; threshold:type both, track by_src, count 10, seconds 5; sid:2150005; rev:1;)',
    ),
    SigRule(
        2150006,
        "ntp",
        "NTP time-shift MITM",
        'alert udp any 123 -> any any (msg:"NETLAB NTP time-shift"; content:"|24|"; offset:0; depth:1; sid:2150006; rev:1;)',
    ),
    SigRule(
        2150007,
        "mdns-llmnr",
        "LLMNR/NBT-NS poisoning response",
        'alert udp any 5355 -> any any (msg:"NETLAB LLMNR response (poisoning)"; sid:2150007; rev:1;)',
    ),
    SigRule(
        2150008,
        "kerberos-net",
        "Kerberos RC4 downgrade",
        'alert tcp any any -> any 88 (msg:"NETLAB Kerberos RC4 enctype (roastable)"; content:"|17|"; sid:2150008; rev:1;)',
    ),
    SigRule(
        2150009,
        "quic",
        "QUIC Initial (long header)",
        'alert udp any any -> any 443 (msg:"NETLAB QUIC Initial"; content:"|c0|"; offset:0; depth:1; sid:2150009; rev:1;)',
    ),
)


def for_poc(slug: str) -> list[SigRule]:
    """Return the reference rules covering a given PoC slug."""
    return [r for r in CATALOGUE if r.poc == slug]


def covered_pocs() -> set[str]:
    """Return every PoC slug the catalogue covers."""
    return {r.poc for r in CATALOGUE}


def content_ruleset() -> RuleSet:
    """The subset of the catalogue expressible as a payload content match."""
    return RuleSet(
        [
            Rule(2130004, "unsolicited RIP response", b"\x02\x02"),
            Rule(2150002, "DNS tunneling high-entropy label", b"deadbeefdeadbeefdeadbeef"),
            Rule(2150004, "cleartext login after HTTPS", b"password="),
            Rule(2150005, "SNMP community brute force", b"public"),
            Rule(2150007, "LLMNR response", b"\x00\x01\x00\x01"),
        ]
    )


def demo() -> None:
    """Reference scenario: score the content rules, then report catalogue coverage."""
    ruleset = content_ruleset()
    samples = [
        Sample(b"GET /index.html HTTP/1.1", malicious=False),
        Sample(b"login=admin&password=hunter2", malicious=True),
        Sample(b"community=public&oid=1.3.6.1", malicious=True),
        Sample(b"POST /api/order HTTP/1.1", malicious=False),
    ]
    for s in samples:
        fired = ruleset.alerts(s.payload)
        if fired:
            verdict("ALERT", f"sid {fired[0].sid}: {fired[0].msg}")
        else:
            verdict("FORWARD", "no signature matched")
    m = score(ruleset, samples)
    verdict("INFO", f"detections={m['tp']} misses={m['fn']} false-positives={m['fp']}")
    wire = sum(1 for r in CATALOGUE if not r.rule.startswith("note:"))
    verdict(
        "INFO",
        f"catalogue: {len(CATALOGUE)} PoC covered ({wire} wire rules, {len(CATALOGUE) - wire} WIDS/physical notes)",
    )
