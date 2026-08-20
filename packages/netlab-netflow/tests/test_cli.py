# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Smoke test for netlab-netflow: the brief renders."""

from __future__ import annotations

import pytest
from netlab_netflow.cli import main
from netlab_netflow.lesson import LESSON


def test_brief_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["brief"]) == 0
    assert LESSON.title in capsys.readouterr().out
