# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Smoke tests for netlab-amplif: brief works, attack is guarded."""

from __future__ import annotations

import pytest
from netlab_amplif.cli import main
from netlab_amplif.lesson import LESSON
from netlab_core import ConsentError


def test_brief_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["brief"]) == 0
    assert LESSON.title in capsys.readouterr().out


def test_attack_requires_consent() -> None:
    with pytest.raises(ConsentError):
        main(["attack"])
