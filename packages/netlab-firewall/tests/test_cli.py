# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Smoke test for netlab-firewall: the brief renders."""

from __future__ import annotations

import pytest
from netlab_firewall.cli import main
from netlab_firewall.lesson import LESSON


def test_brief_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["brief"]) == 0
    assert LESSON.title in capsys.readouterr().out
