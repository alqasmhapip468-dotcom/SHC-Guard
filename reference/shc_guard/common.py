# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Common helpers for the SHC-Guard v0.6 reference implementation.

Reference / تجريبي only. NOT audited, NOT production crypto.
Labels and H (SHA-512) per DESIGN_FREEZE.md §1.
"""

import hashlib
import struct

VERSION = "SHC-Guard/v0.6"


def label(name: str) -> bytes:
    """Return the v0.6 ASCII label bytes for ``name``."""
    return ("SHC-Guard/v0.6/" + name).encode("ascii")


def H(data: bytes) -> bytes:
    """H = SHA-512 everywhere (freeze §1)."""
    return hashlib.sha512(data).digest()


def u64(n: int) -> bytes:
    """Unsigned 64-bit big-endian encoding."""
    return struct.pack(">Q", n)


def u64_decode(b: bytes) -> int:
    return struct.unpack(">Q", b)[0]


def b2h(b: bytes) -> str:
    return b.hex()


def h2b(s: str) -> bytes:
    return bytes.fromhex(s)
