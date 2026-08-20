# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Kerberos-on-the-wire simulator: encryption-type exposure (network dimension only).

Kerberos AS/TGS exchanges can be captured on the wire; whether the captured
material is crackable offline depends on the encryption type. Legacy RC4/DES
enctypes are brute-forceable; AES is not. PKINIT and channel binding harden the
exchange further. Network dimension only - no application ticket exploitation.
"""

from __future__ import annotations

from netlab_core import verdict

CRACKABLE = {"rc4-hmac", "des-cbc-md5", "des-cbc-crc", "arcfour-hmac"}


def is_crackable(enctype: str) -> bool:
    """Return True if captured material of this enctype is offline-crackable."""
    return enctype.lower() in CRACKABLE


def demo() -> None:
    """Reference scenario: a weak enctype vs AES."""
    for enctype in ("rc4-hmac", "aes256-cts-hmac-sha1-96"):
        crackable = is_crackable(enctype)
        verdict("ALERT" if crackable else "FORWARD", f"{enctype}: offline-crackable = {crackable}")
