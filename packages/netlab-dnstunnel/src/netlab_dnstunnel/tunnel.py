# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""DNS-tunnel codec + detector: encode data in query names, flag it statistically.

Data is hex-encoded and split into DNS labels under an attacker-controlled
domain; the authoritative server reassembles it. Detection watches for long,
high-entropy labels and abnormal query volume. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

import math

from netlab_core import verdict

_LABEL = 30  # hex chars per label (<= 63)


def encode(data: bytes, domain: str) -> list[str]:
    """Encode data into a list of DNS query names under ``domain``."""
    hexed = data.hex()
    return [hexed[i : i + _LABEL] + "." + domain for i in range(0, len(hexed), _LABEL)]


def decode(qnames: list[str]) -> bytes:
    """Recover the data from the tunnelled query names."""
    return bytes.fromhex("".join(q.split(".", 1)[0] for q in qnames))


def label_entropy(label: str) -> float:
    """Shannon entropy (bits/char) of a DNS label - high for encoded data."""
    if not label:
        return 0.0
    freq = {c: label.count(c) / len(label) for c in set(label)}
    return -sum(p * math.log2(p) for p in freq.values())


def demo() -> None:
    """Reference scenario: exfiltrate a secret, then flag it by label entropy."""
    qnames = encode(b"TOKEN=secret", "exfil.example.com")
    verdict("ALERT", f"tunnelled in {len(qnames)} queries -> recovered {decode(qnames)!r}")
    print("\n--- detector flags high-entropy labels ---")
    label = qnames[0].split(".", 1)[0]
    ent = label_entropy(label)
    verdict("ALERT" if ent > 2.5 else "FORWARD", f"label entropy {ent:.2f} bits/char")
