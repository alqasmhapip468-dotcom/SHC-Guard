# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Chains / AEAD / TLV / identity tests."""
import hashlib

import pytest

from shc_guard import aead, pq
from shc_guard.aead import AAD
from shc_guard.chains import (
    DIRECTION_A_TO_B, make_rx_chain, make_tx_chain,
)
from shc_guard.common import H
from shc_guard.identity import Identity
from shc_guard.tlv import decode_fields, encode_fields


def test_tlv_round_trip_and_truncation():
    data = encode_fields([(0x01, b"abc"), (0x02, b"")])
    assert decode_fields(data) == [(0x01, b"abc"), (0x02, b"")]
    with pytest.raises(ValueError):
        decode_fields(data[:-1])
    with pytest.raises(ValueError):
        decode_fields(data + b"\x09")


def test_identity_fingerprint_deterministic():
    ident = Identity.from_ed_seed(
        "alice", b"A" * 32, b"\x01" * 32,
        mldsa_public_key=b"P" * 1952, mldsa_secret_key=b"S" * 4032)
    fp1 = ident.fingerprint()
    fp2 = ident.record().fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64
    # Different user → different fingerprint.
    other = Identity.from_ed_seed(
        "bob", b"A" * 32, b"\x01" * 32,
        mldsa_public_key=b"P" * 1952, mldsa_secret_key=b"S" * 4032)
    assert other.fingerprint() != fp1


def test_identity_dual_sign_verify():
    ident = Identity.generate("alice", b"A" * 32)
    msg = b"test message"
    ed, ml = ident.sign(msg)
    assert ident.record().verify_dual(msg, ed, ml)
    assert not ident.record().verify_dual(b"tampered", ed, ml)
    assert not ident.record().verify_dual(msg, bytes([ed[0] ^ 1]) + ed[1:], ml)


def test_chain_initial_value_matches_freeze():
    # v0.6 CHANGED (freeze SS2, D-18 objection 2): direction-specific
    # init -- H(label || session_id || direction || sender || "init").
    sid = b"S" * 32
    chain = make_rx_chain(sid, b"A" * 32, DIRECTION_A_TO_B)
    expected = H(b"SHC-Guard/v0.6/rx-chain" + sid + bytes([1])
                 + b"A" * 32 + b"init")
    assert chain.digest == expected
    # The other direction starts from a different value.
    other = make_rx_chain(sid, b"A" * 32, 0x02)
    assert other.digest != chain.digest


def test_chain_advance_is_order_sensitive():
    sid, dev = b"S" * 32, b"A" * 32
    c1 = make_rx_chain(sid, dev, DIRECTION_A_TO_B)
    c2 = make_rx_chain(sid, dev, DIRECTION_A_TO_B)
    c1.advance(0, 0, b"ct0")
    c1.advance(0, 1, b"ct1")
    c2.advance(0, 1, b"ct1")
    c2.advance(0, 0, b"ct0")
    assert c1.digest != c2.digest


def test_tx_chain_equals_peer_rx_chain():
    """The property §3(e) + rule 7 depend on: sender tx_digest ==
    receiver rx_digest over the same ciphertexts (see chains.py
    deviation note on the freeze §4 label conflict)."""
    sid = b"S" * 32
    tx = make_tx_chain(sid, b"A" * 32, DIRECTION_A_TO_B)
    rx = make_rx_chain(sid, b"A" * 32, DIRECTION_A_TO_B)
    for i in range(5):
        ct = ("ciphertext-%d" % i).encode()
        tx.advance(0, i, ct)
        rx.advance(0, i, ct)
        assert tx.digest == rx.digest
        assert tx.digest_at(0, i) == rx.digest_at(0, i)


def test_chain_history_retention_1000():
    chain = make_rx_chain(b"S" * 32, b"A" * 32, DIRECTION_A_TO_B)
    for i in range(1005):
        chain.advance(0, i, b"x")
    assert len(chain.history) == 1000
    assert chain.digest_at(0, 4) is None  # evicted
    assert chain.digest_at(0, 1004) is not None


def test_aead_round_trip_and_aad_binding():
    key = pq.random_bytes(32)
    aad = AAD(b"S" * 32, b"A" * 32, 1, 0, 0, 0, 0, b"D" * 64)
    pt = b"hello aead"
    nonce = aead.fresh_nonce()
    ct = aead.encrypt(key, nonce, pt, aad)
    assert aead.decrypt(key, nonce, ct, aad) == pt
    # Wrong AAD → fail.
    bad_aad = AAD(b"S" * 32, b"A" * 32, 1, 0, 1, 0, 0, b"D" * 64)
    with pytest.raises(Exception):
        aead.decrypt(key, nonce, ct, bad_aad)
    # Tampered ciphertext → fail.
    bad_ct = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(Exception):
        aead.decrypt(key, nonce, bad_ct, aad)
    # Wrong key → fail.
    with pytest.raises(Exception):
        aead.decrypt(pq.random_bytes(32), nonce, ct, aad)
