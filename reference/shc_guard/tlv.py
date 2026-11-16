# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Canonical TLV encoding (DESIGN_FREEZE.md §1).

TLV = type (1 byte) || len (4 bytes big-endian) || value.
Fields are encoded in the fixed order listed in the freeze/spec.
Reference / تجريبي only.
"""

import struct

from .common import H, label  # noqa: F401  (re-exported convenience)


def encode_field(field_type: int, value: bytes) -> bytes:
    """Encode one TLV field."""
    if not (0 <= field_type <= 255):
        raise ValueError("field type must fit in one byte")
    return struct.pack(">BI", field_type, len(value)) + value


def encode_fields(fields) -> bytes:
    """Encode an ordered list of (type:int, value:bytes) pairs."""
    return b"".join(encode_field(t, v) for t, v in fields)


def decode_fields(data: bytes):
    """Decode TLV bytes into a list of (type:int, value:bytes).

    Raises ValueError on truncation or trailing garbage.
    """
    out = []
    i = 0
    while i < len(data):
        if i + 5 > len(data):
            raise ValueError("truncated TLV header")
        ftype = data[i]
        (length,) = struct.unpack(">I", data[i + 1:i + 5])
        i += 5
        if i + length > len(data):
            raise ValueError("truncated TLV value")
        out.append((ftype, data[i:i + length]))
        i += length
    return out


def decode_expected(data: bytes, expected_types):
    """Decode and check the field types appear in the expected order.

    Returns a dict {type: value}. Raises ValueError on mismatch.
    """
    fields = decode_fields(data)
    got = [t for t, _ in fields]
    if got != list(expected_types):
        raise ValueError(f"unexpected TLV field order: got {got}, expected {list(expected_types)}")
    return {t: v for t, v in fields}
