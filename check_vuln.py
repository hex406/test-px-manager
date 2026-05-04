#!/usr/bin/env python3
"""
Probe whether the current kernel is vulnerable to CVE-2026-31431.
Checks:
  1. Kernel version is in the known-vulnerable range.
  2. authencesn AEAD is available via AF_ALG (required for the bug path).
  3. os.splice() accepts offset_src (Python 3.10+, Linux 5.17+).
"""

import os
import platform
import socket
import struct
import sys

AEAD_KEY  = bytes.fromhex("0800010000000010" + "00" * 32)
AUTH_SIZE = 4

def check_kernel_version() -> tuple[bool, str]:
    release = platform.release()          # e.g. "6.1.0-21-amd64"
    parts   = release.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return False, f"cannot parse kernel version: {release}"

    # Adjust these bounds to whatever the CTF says is patched.
    # CVE-2026-31431 is fictional here; treat anything 5.17–6.8 as suspect.
    if (major, minor) < (5, 17):
        return False, f"{release} — too old, splice offset_src not supported"
    if (major, minor) > (6, 8):
        return False, f"{release} — likely patched"
    return True, release


def check_af_alg() -> tuple[bool, str]:
    try:
        s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        s.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, AEAD_KEY)
        s.setsockopt(socket.SOL_ALG, socket.ALG_SET_AEAD_AUTHSIZE, None, AUTH_SIZE)
        s.close()
        return True, "authencesn(hmac(sha256),cbc(aes)) available"
    except OSError as e:
        return False, f"AF_ALG bind failed: {e}"


def check_setuid_target(path: str) -> tuple[bool, str]:
    try:
        st = os.stat(path)
        is_suid = bool(st.st_mode & 0o4000)
        return is_suid, f"{path}: suid={is_suid}, size={st.st_size}"
    except FileNotFoundError:
        return False, f"{path} not found"


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "/usr/bin/su"

    checks = [
        ("Kernel version",  *check_kernel_version()),
        ("AF_ALG / authencesn", *check_af_alg()),
        (f"Setuid target ({target})", *check_setuid_target(target)),
    ]

    all_pass = True
    for label, ok, detail in checks:
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {label}: {detail}")
        if not ok:
            all_pass = False

    print()
    if all_pass:
        print("VULNERABLE — run exploit.py")
        sys.exit(0)
    else:
        print("NOT vulnerable (or target missing)")
        sys.exit(1)


if __name__ == "__main__":
    main()
