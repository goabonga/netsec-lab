# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the pcap forensics analyser."""

from __future__ import annotations

from netlab_pcap_forensics.analysis import Record, cleartext_creds, summarize, top_talkers


def test_cleartext_creds_detected() -> None:
    recs = [Record("tcp", "a", "b", 21, b"PASS secret"), Record("tcp", "a", "b", 443, b"x")]
    assert len(cleartext_creds(recs)) == 1


def test_summary_counts() -> None:
    recs = [Record("tcp", "a", "b", 80), Record("tcp", "c", "b", 80, b"password=x")]
    assert summarize(recs) == {"packets": 2, "talkers": 2, "cleartext_creds": 1}


def test_top_talkers_ranked() -> None:
    recs = [Record("tcp", "a", "b", 80), Record("tcp", "a", "b", 80), Record("tcp", "c", "b", 80)]
    assert top_talkers(recs)[0] == ("a", 2)
