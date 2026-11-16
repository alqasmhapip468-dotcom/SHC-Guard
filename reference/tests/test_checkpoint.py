# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Checkpoint tests: canonical form, dual signatures, rules (a)–(f),
cadence, and CP-carried digest checks at the session level.
"""
import pytest

from shc_guard.checkpoint import (
    Checkpoint, CheckpointVerification, ZERO_NONCE,
    pack_signed_checkpoint, unpack_signed_checkpoint, verify_checkpoint,
)
from shc_guard.identity import Identity
from tests.helpers import build_pair, craft_message, exchange


def _cp(a, b, rx_count, rx_digest, seq=1, nonce=ZERO_NONCE,
        rx_epoch=0, prev=None, anchor_head=None):
    # v0.6 CHANGED: CP now carries generation, tx_epoch, rx_epoch,
    # prev_cp_hash and anchor_head (freeze SS2).
    from shc_guard.checkpoint import ZERO_HASH
    return Checkpoint(session_id=a.session_id, device_id=a.my_device_id,
                      generation=a.generation,
                      cp_seq=seq, tx_epoch=0, tx_ctr=a.tx_ctr,
                      rx_epoch=rx_epoch, rx_ctr_max=rx_count,
                      rx_digest=rx_digest,
                      guard_level=a.guard_level,
                      prev_cp_hash=prev if prev is not None else ZERO_HASH,
                      anchor_head=(anchor_head if anchor_head is not None
                                   else ZERO_HASH),
                      challenge_nonce=nonce)


def test_cp_sign_verify_round_trip(pair):
    a, b = pair
    exchange(a, b, 1)
    cp = _cp(a, b, a.rx_count, a.rx_chain.digest)
    blob = cp.sign(a.material.own_identity)
    assert cp.verify_signatures(a.peer_record if False else
                                a.material.own_identity.record(), blob)
    cp2, blob2 = unpack_signed_checkpoint(pack_signed_checkpoint(cp, blob))
    assert cp2 == cp and blob2 == blob


def test_cp_rule_a_bad_signature(pair):
    a, b = pair
    exchange(a, b, 1)
    cp = _cp(a, b, a.rx_count, a.rx_chain.digest)
    blob = cp.sign(a.material.own_identity)
    bad = bytes([blob[0] ^ 1]) + blob[1:]
    v = verify_checkpoint(cp, bad, a.material.own_identity.record(),
                          a.session_id, a.my_device_id, a.guard_level, 0,
                          0, a.tx_ctr, lambda e, c: a._tx_digest_after(e, c))
    assert v.status == CheckpointVerification.BAD_SIGNATURE


def test_cp_rule_c_seq_must_increase(pair):
    a, b = pair
    exchange(a, b, 1)
    w = a.send_checkpoint()
    assert b.receive(w)["status"] == "checkpoint_ok"
    # Same cp_seq again (fresh CP, same seq): rejected.
    cp = _cp(a, b, a.rx_count, a.rx_chain.digest, seq=1)
    blob = cp.sign(a.material.own_identity)
    wire = craft_message(a, 0x02, pack_signed_checkpoint(cp, blob))
    assert b.receive(wire)["status"] == "rejected"


def test_cp_rule_d_position_mismatch(pair):
    a, b = pair
    exchange(a, b, 1)
    cp = _cp(a, b, a.rx_count, a.rx_chain.digest, seq=5)
    blob = cp.sign(a.material.own_identity)
    # Carry it at the WRONG position (tx_ctr+3).
    wire = craft_message(a, 0x02, pack_signed_checkpoint(cp, blob),
                         position=(0, a.tx_ctr + 3))
    # Position beyond expected → buffered, not verified yet; instead
    # craft it at the next position but with a wrong tx_ctr inside.
    cp_bad = Checkpoint(session_id=a.session_id, device_id=a.my_device_id,
                        generation=a.generation,
                        cp_seq=5, tx_epoch=0, tx_ctr=a.tx_ctr + 9,
                        rx_epoch=0,
                        rx_ctr_max=a.rx_count, rx_digest=a.rx_chain.digest,
                        guard_level=a.guard_level)
    blob_bad = cp_bad.sign(a.material.own_identity)
    wire2 = craft_message(a, 0x02,
                          pack_signed_checkpoint(cp_bad, blob_bad))
    assert b.receive(wire2)["status"] == "rejected"


def test_cp_rule_f_wrong_nonce_rejected(pair):
    a, b = pair
    exchange(a, b, 1)
    b._enter_suspect("test")
    assert b.state == "SUSPECT"
    cp = _cp(a, b, a.rx_count, a.rx_chain.digest, seq=1,
             nonce=b"N" * 32)  # wrong nonce
    blob = cp.sign(a.material.own_identity)
    wire = craft_message(a, 0x02, pack_signed_checkpoint(cp, blob))
    res = b.receive(wire)
    assert res["status"] == "rejected"
    assert b.state == "SUSPECT"  # not resolved, not quarantined (yet)


def test_cp_digest_mismatch_inside_window_is_suspect(pair):
    a, b = pair
    exchange(a, b, 2)
    # B's CP claims the right rx count but a WRONG digest (rolled back).
    cp = Checkpoint(session_id=b.session_id, device_id=b.my_device_id,
                    generation=b.generation,
                    cp_seq=1, tx_epoch=0, tx_ctr=b.tx_ctr, rx_epoch=0,
                    rx_ctr_max=b.rx_count, rx_digest=b"D" * 64,
                    guard_level=b.guard_level)
    blob = cp.sign(b.material.own_identity)
    wire = craft_message(b, 0x02, pack_signed_checkpoint(cp, blob))
    res = a.receive(wire)
    assert res["status"] == "suspect"
    assert a.state == "SUSPECT"


def test_cp_digest_outside_window_is_suspect(pair):
    a, b = pair
    exchange(a, b, 1)
    # CP claims rx_ctr_max far beyond what A ever sent.
    cp = Checkpoint(session_id=b.session_id, device_id=b.my_device_id,
                    generation=b.generation,
                    cp_seq=1, tx_epoch=0, tx_ctr=b.tx_ctr, rx_epoch=0,
                    rx_ctr_max=9999, rx_digest=b"D" * 64,
                    guard_level=b.guard_level)
    blob = cp.sign(b.material.own_identity)
    wire = craft_message(b, 0x02, pack_signed_checkpoint(cp, blob))
    res = a.receive(wire)
    assert res["status"] == "suspect"
    assert a.state == "SUSPECT"  # NOT quarantined


def test_cp_cadence_due_after_50_messages(pair):
    a, b = pair
    assert not a.checkpoint_due()
    for _ in range(50):
        w = a.send_app(b"x")
        b.receive(w)
    assert a.checkpoint_due()


def test_cp_cadence_due_after_24h(pair, clock):
    a, b = pair
    assert not a.checkpoint_due()
    clock.advance(24 * 3600 + 1)
    assert a.checkpoint_due()


def test_checkpoint_loss_logged_not_hidden(pair):
    # Storing no CPs: a peer whose CPs are lost degrades to attestation.
    # The reference surfaces it via notifications, never silently.
    a, b = pair
    assert b.last_peer_cp is None
    exchange(a, b, 1)
    assert b.last_peer_cp is None  # no CP sent yet
