# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Smoke test for netlab-tls-inspect: the brief renders."""

from __future__ import annotations

import pytest
from netlab_tls_inspect.cli import main
from netlab_tls_inspect.lesson import LESSON


def test_brief_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["brief"]) == 0
    assert LESSON.title in capsys.readouterr().out
