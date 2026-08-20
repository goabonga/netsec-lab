# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the LLDP-MED voice-VLAN policy simulator."""

from __future__ import annotations

from netlab_lldp_med.policy import VoicePolicy


def test_dynamic_policy_honours_claim() -> None:
    p = VoicePolicy(configured_voice={"Gi0/2": 100}, honor_lldp_med=True)
    assert p.assign("Gi0/2", 200) == 200


def test_static_policy_enforces_config() -> None:
    p = VoicePolicy(configured_voice={"Gi0/2": 100}, honor_lldp_med=False)
    assert p.assign("Gi0/2", 200) == 100


def test_no_voice_vlan_on_port() -> None:
    assert VoicePolicy(configured_voice={}).assign("Gi0/9", 200) is None
