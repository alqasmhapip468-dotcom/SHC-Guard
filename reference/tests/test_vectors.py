# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Vector tests: recompute every derived value from the stored
TEST-ONLY inputs in reference/vectors/*.json and assert equality.
"""
import json
import os

import pytest

from shc_guard import aead
from shc_guard.aead import AAD
from shc_guard.chains import make_rx_chain, make_tx_chain
from shc_guard.checkpoint import Checkpoint, unpack_signed_checkpoint
from shc_guard.common import H, h2b
from shc_guard.identity import Identity
from shc_guard.transcript import Transcript

VECTORS = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "vectors")


def _load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as fh:
        return json.load(fh)


def test_vector_identity_fingerprint():
    v = _load("identity_fingerprint.json")
    ident = Identity.from_ed_seed(
        v["user_id"], h2b(v["device_id"]), h2b(v["ed_seed"]),
        h2b(v["mldsa_public_key"]), h2b(v["mldsa_secret_key"]),
        record_version=v["record_version"],
        guard_level=v["guard_level"])
    assert ident.canonical_record().hex() == v["canonical_record"]
    assert ident.fingerprint().hex() == v["fingerprint"]


def test_vector_transcript():
    v = _load("transcript.json")
    t = Transcript.parse(h2b(v["canonical"]))
    assert t.digest().hex() == v["digest"]
    assert t.handshake_id.hex() == v["parsed_handshake_id"]
    assert t.guard_level == v["guard_level"]
    assert t.timestamp == v["timestamp"]


def test_vector_handshake():
    v = _load("handshake.json")
    t = Transcript.parse(h2b(v["transcript"]))
    assert t.digest().hex() == v["transcript_digest"]
    assert H(h2b(v["transcript"]))[:32].hex() == v["session_id"]
    from shc_guard.common import label
    root = H(label("state-encryption")
             + h2b(v["x25519_shared_secret"])
             + h2b(v["kem_shared_secret"]))[:32]
    assert root.hex() == v["root_key"]
    from shc_guard.transcript import verify_key_confirmation
    shared = h2b(v["x25519_shared_secret"]) + h2b(v["kem_shared_secret"])
    assert verify_key_confirmation(shared, h2b(v["transcript"]),
                                   h2b(v["key_confirmation_mac_initiator"]))
    assert verify_key_confirmation(shared, h2b(v["transcript"]),
                                   h2b(v["key_confirmation_mac_responder"]))


def test_vector_checkpoint():
    v = _load("checkpoint.json")
    cp, blob = unpack_signed_checkpoint(h2b(v["packed"]))
    assert cp.canonical().hex() == v["canonical"]
    assert cp.digest().hex() == v["digest"]
    assert blob[:64].hex() == v["ed_sig"]
    assert blob[68:].hex() == v["mldsa_sig"]
    assert cp.cp_seq == v["cp_seq"] == 7
    assert cp.tx_ctr == v["tx_ctr"] == 41
    assert cp.rx_ctr_max == v["rx_ctr_max"] == 40
    # v0.6 fields.
    assert cp.generation == v["generation"] == 1
    assert cp.tx_epoch == v["tx_epoch"] == 0
    assert cp.rx_epoch == v["rx_epoch"] == 0
    assert cp.prev_cp_hash.hex() == v["prev_cp_hash"]
    assert cp.anchor_head.hex() == v["anchor_head"]


def test_vector_chains():
    v = _load("chains.json")
    sid = h2b(v["session_id"])
    rx = make_rx_chain(sid, h2b(v["sender_device_id"]), v["direction"])
    tx = make_tx_chain(sid, h2b(v["sender_device_id"]), v["direction"])
    assert rx.initial_digest.hex() == v["initial_rx_digest"]
    assert tx.initial_digest.hex() == v["initial_tx_digest"]
    for step in v["steps"]:
        ct = h2b(step["ciphertext"])
        assert H(ct).hex() == step["ciphertext_sha512"]
        rx.advance(0, step["ctr"], ct)
        tx.advance(0, step["ctr"], ct)
        assert rx.digest.hex() == step["rx_digest"]
        assert tx.digest.hex() == step["tx_digest"]
        assert rx.digest == tx.digest


def test_vector_aead():
    v = _load("aead.json")
    aad = AAD(h2b(v["session_id"]), b"A" * 32, v["generation"],
              v["tx_epoch"], v["tx_ctr"], v["ack_rx_epoch"], 2,
              bytes(range(64)))
    assert aad.canonical().hex() == v["aad_canonical"]
    key, nonce = h2b(v["key"]), h2b(v["nonce"])
    ct = aead.encrypt(key, nonce, h2b(v["plaintext"]), aad)
    assert ct.hex() == v["ciphertext"]
    assert aead.decrypt(key, nonce, h2b(v["ciphertext"]), aad) \
        == h2b(v["plaintext"])
    assert v["decrypts"] is True


# ---- v0.6 new vectors -------------------------------------------------------

def test_vector_split_epoch_cp():
    v = _load("split_epoch_cp.json")
    cp, blob = unpack_signed_checkpoint(h2b(v["packed"]))
    assert cp.canonical().hex() == v["canonical"]
    assert cp.digest().hex() == v["digest"]
    assert cp.tx_epoch == v["tx_epoch"] == 2
    assert cp.rx_epoch == v["rx_epoch"] == 5  # differs from tx_epoch
    assert cp.tx_ctr == v["tx_ctr"] == 9
    assert cp.rx_ctr_max == v["rx_ctr_max"] == 7
    assert cp.generation == v["generation"] == 3
    assert cp.prev_cp_hash.hex() == v["prev_cp_hash"]
    assert cp.anchor_head.hex() == v["anchor_head"]
    assert v["verifies"] is True


def test_vector_prev_cp_hash_chain():
    v = _load("prev_cp_hash_chain.json")
    prev = bytes(64)
    for entry in v["cps"]:
        assert entry["prev_cp_hash"] == prev.hex()
        cp = Checkpoint.parse(h2b(entry["canonical"]))
        assert cp.digest().hex() == entry["digest"]
        assert cp.prev_cp_hash == prev
        prev = cp.digest()


def test_vector_anchor():
    from shc_guard.anchor import LocalAnchor, entry_hash
    v = _load("anchor.json")
    assert len(v["receipts"]) == 3
    prev = bytes(64)
    for r in v["receipts"]:
        assert entry_hash(prev, h2b(r["cp_hash"]),
                          r["anchor_seq"]).hex() == r["entry_hash"]
        assert r["verifies"] is True
        prev = h2b(r["entry_hash"])
    assert v["head"] == prev.hex()
    assert v["entries"] == 3


def test_vector_direction_init():
    from shc_guard.chains import (
        DIRECTION_A_TO_B, DIRECTION_B_TO_A, make_rx_chain)
    v = _load("direction_init.json")
    sid = h2b(v["session_id"])
    assert make_rx_chain(sid, h2b(v["sender_device_id"]),
                         DIRECTION_A_TO_B).initial_digest.hex() == v["a_to_b"]
    assert make_rx_chain(sid, h2b(v["sender_device_id"]),
                         DIRECTION_B_TO_A).initial_digest.hex() == v["b_to_a"]
    assert v["a_to_b"] != v["b_to_a"]  # direction in the init value
    assert v["a_to_b"] != v["a_to_b_other_sender"]  # sender in the init


def test_vector_generation_aad():
    v = _load("generation_aad.json")
    assert v["generation_1"] != v["generation_2"]
    aad1 = AAD(h2b(_load("aead.json")["session_id"]), b"A" * 32, 1, 0, 3,
               0, 2, bytes(range(64)))
    assert aad1.canonical().hex() == v["generation_1"]


def test_vector_challenge_table():
    from shc_guard.suspect import ChallengeTable
    v = _load("challenge_table.json")
    assert v["first_superseded"] is True
    assert v["second_consumed"] is True
    tbl = ChallengeTable.restore(v["serialized"], clock=lambda: 1000.0)
    assert tbl.is_superseded(h2b(v["first_nonce"]))
    assert tbl.is_consumed(h2b(v["second_nonce"]))
    assert tbl.outstanding_nonce is None
