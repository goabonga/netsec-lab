# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the IDS rule harness: content engine and PoC catalogue."""

from __future__ import annotations

from netlab_ids.rules import (
    CATALOGUE,
    Rule,
    RuleSet,
    Sample,
    covered_pocs,
    for_poc,
    score,
)

# Every offensive PoC in the repo must carry at least one reference rule.
OFFENSIVE_POCS = {
    "wifi-recon",
    "wifi-deauth",
    "evil-twin",
    "wpa-crack",
    "wps-brute",
    "tap",
    "tempest",
    "hw-implant",
    "dhcp",
    "arp",
    "macflood",
    "stp",
    "vlan",
    "ipv6-ra",
    "discovery",
    "lldp-med",
    "8021x",
    "macsec",
    "ipspoof",
    "icmp",
    "frag",
    "routing",
    "igmp",
    "bgp",
    "vrrp-hsrp",
    "portscan",
    "synflood",
    "tcphijack",
    "amplif",
    "ids-evasion",
    "covert",
    "dns",
    "dnstunnel",
    "icmptunnel",
    "tls",
    "snmp",
    "ntp",
    "mdns-llmnr",
    "kerberos-net",
    "quic",
}


def test_rule_matches_content() -> None:
    assert Rule(1, "sh", b"/bin/sh").matches(b"x=/bin/sh -i") is True


def test_score_confusion_matrix() -> None:
    rs = RuleSet([Rule(1, "sh", b"/bin/sh")])
    m = score(rs, [Sample(b"/bin/sh", True), Sample(b"clean", False)])
    assert m == {"tp": 1, "fp": 0, "fn": 0, "tn": 1}


def test_catalogue_covers_every_offensive_poc() -> None:
    assert covered_pocs() == OFFENSIVE_POCS


def test_catalogue_sids_are_unique() -> None:
    sids = [r.sid for r in CATALOGUE]
    assert len(sids) == len(set(sids))


def test_for_poc_returns_matching_rule() -> None:
    rules = for_poc("dnstunnel")
    assert rules and all(r.poc == "dnstunnel" for r in rules)
