# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Offline pcap forensics: extract indicators from captured records.

Summarises a capture into top talkers, DNS queries and cleartext credentials
(FTP/HTTP Basic/plain 'password='), the kind of triage a responder runs over a
seized pcap. Pure logic over plain records - safe to run anywhere.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from netlab_core import verdict

CRED_MARKERS = (b"PASS ", b"password=", b"Authorization: Basic ")


@dataclass
class Record:
    proto: str
    src: str
    dst: str
    dport: int
    payload: bytes = b""


def top_talkers(records: list[Record], limit: int = 5) -> list[tuple[str, int]]:
    return Counter(r.src for r in records).most_common(limit)


def cleartext_creds(records: list[Record]) -> list[Record]:
    return [r for r in records if any(m in r.payload for m in CRED_MARKERS)]


def summarize(records: list[Record]) -> dict[str, int]:
    return {
        "packets": len(records),
        "talkers": len({r.src for r in records}),
        "cleartext_creds": len(cleartext_creds(records)),
    }


def demo() -> None:
    """Reference scenario: a capture leaking an FTP password in cleartext."""
    records = [
        Record("tcp", "10.0.0.5", "93.184.216.34", 443, b"<encrypted>"),
        Record("tcp", "10.0.0.5", "10.0.0.9", 21, b"USER admin\r\nPASS s3cret\r\n"),
        Record("tcp", "10.0.0.7", "10.0.0.9", 80, b"Authorization: Basic YWRtaW46cHc="),
    ]
    for leak in cleartext_creds(records):
        verdict("ALERT", f"cleartext credential {leak.src} -> {leak.dst}:{leak.dport}")
    summary = summarize(records)
    verdict(
        "INFO",
        f"packets={summary['packets']} talkers={summary['talkers']} "
        f"leaks={summary['cleartext_creds']}",
    )
