# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the SSL-strip / HSTS simulator."""

from __future__ import annotations

from netlab_tls.strip import Browser


def test_without_hsts_stripped_to_http() -> None:
    assert Browser(hsts=False).navigate("http") == "http"


def test_hsts_forces_https() -> None:
    assert Browser(hsts=True).navigate("http") == "https"
