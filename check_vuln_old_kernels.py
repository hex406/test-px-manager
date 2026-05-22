#!/usr/bin/env python3
from __future__ import annotations

"""
Vulnerability probe for CVE-2026-31431 (copy-fail).
Compatible with Python 3.8+.
"""

import ctypes
import ctypes.util
import errno
import os
import platform
import socket
import sys

AEAD_KEY  = bytes.fromhex("0800010000000010" + "00" * 32)
AUTH_SIZE = 4


def check_kernel_version() -> tuple[bool, str]:
    release = platform.release()
    parts   = release.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return False, f"cannot parse kernel version: {release}"

    if (major, minor) < (5, 4):
        return False, f"{release} — too old, splice loff_t offset not supported"
    if (major, minor) > (6, 8):
        return False, f"{release} — likely patched"
    return True, release


def check_af_alg() -> tuple[bool, str]:
    try:
        s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    except OSError as e:
        if e.errno == errno.ENOENT:
            if os.system("modprobe af_alg 2>/dev/null") == 0:
                try:
                    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
                except OSError as e2:
                    return False, f"af_alg unavailable after modprobe: {e2}"
            else:
                return False, "af_alg module missing (CONFIG_CRYPTO_USER_API not built) — NOT vulnerable"
        elif e.errno == errno.EAFNOSUPPORT:
            return False, "AF_ALG not supported by kernel — NOT vulnerable"
        else:
            return False, f"socket(AF_ALG) failed: {e}"

    try:
        s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        s.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, AEAD_KEY)
        s.setsockopt(socket.SOL_ALG, socket.ALG_SET_AEAD_AUTHSIZE, None, AUTH_SIZE)
        s.close()
        return True, "authencesn(hmac(sha256),cbc(aes)) available"
    except OSError as e:
        s.close()
        return False, f"authencesn not available: {e}"


def check_splice() -> tuple[bool, str]:
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return False, "libc not found via ctypes"
    libc = ctypes.CDLL(libc_name, use_errno=True)
    if not hasattr(libc, "splice"):
        return False, "splice() not found in libc"
    return True, f"splice() available via {libc_name}"


def check_setuid_target(path: str) -> tuple[bool, str]:
    try:
        st     = os.stat(path)
        is_suid = bool(st.st_mode & 0o4000)
        return is_suid, f"{path}: suid={is_suid}, size={st.st_size}"
    except FileNotFoundError:
        return False, f"{path} not found"


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "/usr/bin/su"

    checks = [
        ("Kernel version",            check_kernel_version()),
        ("AF_ALG / authencesn",       check_af_alg()),
        ("splice() via ctypes",       check_splice()),
        (f"Setuid target ({target})", check_setuid_target(target)),
    ]

    all_pass = True
    for label, (ok, detail) in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: {detail}")
        if not ok:
            all_pass = False

    print()
    if all_pass:
        print("VULNERABLE — run exploit_new.py")
        sys.exit(0)
    else:
        print("NOT vulnerable (or prerequisite missing)")
        sys.exit(1)


if __name__ == "__main__":
    main()
