# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Smoke test for netlab-pcap-forensics: the brief renders."""

from __future__ import annotations

import pytest
from netlab_pcap_forensics.cli import main
from netlab_pcap_forensics.lesson import LESSON


def test_brief_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["brief"]) == 0
    assert LESSON.title in capsys.readouterr().out
