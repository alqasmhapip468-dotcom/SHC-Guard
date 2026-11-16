# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Handshake tests: replayed handshake (consumed ID + timestamp window),
key confirmation, revocation fail-closed, guard-level policy.
"""
import time

import pytest
from nacl.public import PrivateKey
from nacl.signing import VerifyKey

from shc_guard import pq
from shc_guard.handshake import (
    ConsumedHandshakeIDs, HandshakeError, initiator_confirm,
    initiator_finish, initiator_start, responder_finish, responder_reply,
)
from shc_guard.identity import Identity
from shc_guard.revocation import (
    RevocationChecker, RevocationList, generate_test_operator,
)
from shc_guard.session import Session
from tests.helpers import FakeClock, build_pair, make_checker


def _handshake_parts(clock):
    alice = Identity.generate("alice", b"A" * 32)
    bob = Identity.generate("bob", b"B" * 32)
    checker_a = make_checker()
    checker_b = make_checker()
    consumed = ConsumedHandshakeIDs(clock=clock)
    return alice, bob, checker_a, checker_b, consumed


def test_full_handshake_succeeds_and_ids_consumed_only_after_save(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    offer, pa = initiator_start(alice, clock=clock)
    # Not consumed before any save.
    assert not consumed.is_consumed(offer["handshake_id"])
    reply, pb = responder_reply(offer, bob, cb, consumed, clock=clock)
    finish, mat_a = initiator_finish(reply, pa, ca, consumed, clock=clock)
    confirm, mat_b = responder_finish(finish, pb, consumed, clock=clock)
    initiator_confirm(confirm, mat_a)
    # Still not consumed: no session saved yet.
    assert not consumed.is_consumed(offer["handshake_id"])
    sa = Session(mat_a, consumed_ids=consumed, clock=clock)
    sa.save()
    assert consumed.is_consumed(offer["handshake_id"])
    sb = Session(mat_b, consumed_ids=consumed, clock=clock)
    sb.save()
    assert sa.session_id == sb.session_id
    assert sa.state == "ACTIVE" and sb.state == "ACTIVE"


def test_replayed_handshake_id_rejected(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    offer, pa = initiator_start(alice, clock=clock)
    reply, pb = responder_reply(offer, bob, cb, consumed, clock=clock)
    finish, mat_a = initiator_finish(reply, pa, ca, consumed, clock=clock)
    confirm, mat_b = responder_finish(finish, pb, consumed, clock=clock)
    initiator_confirm(confirm, mat_a)
    Session(mat_a, consumed_ids=consumed, clock=clock).save()
    # Replaying the SAME offer now hits the consumed-ID check.
    with pytest.raises(HandshakeError, match="consumed"):
        responder_reply(offer, bob, make_checker(), consumed, clock=clock)


def test_replayed_finish_rejected_after_save(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    offer, pa = initiator_start(alice, clock=clock)
    reply, pb = responder_reply(offer, bob, cb, consumed, clock=clock)
    finish, mat_a = initiator_finish(reply, pa, ca, consumed, clock=clock)
    confirm, mat_b = responder_finish(finish, pb, consumed, clock=clock)
    initiator_confirm(confirm, mat_a)
    Session(mat_a, consumed_ids=consumed, clock=clock).save()
    # A second responder pending (built with a clean registry) receiving
    # the same transcript must fail once the id is marked consumed.
    clean = ConsumedHandshakeIDs(clock=clock)
    _reply3, pb3 = responder_reply(offer, bob, cb, clean, clock=clock)
    clean.record(offer["handshake_id"])
    with pytest.raises(HandshakeError, match="consumed"):
        responder_finish(finish, pb3, clean, clock=clock)


def test_offer_timestamp_outside_window_rejected(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    old = int(clock()) - 400  # > 5 minutes old
    offer, _pa = initiator_start(alice, timestamp=old, clock=clock)
    with pytest.raises(HandshakeError, match="timestamp"):
        responder_reply(offer, bob, cb, consumed, clock=clock)
    future = int(clock()) + 400
    offer2, _pa2 = initiator_start(alice, timestamp=future, clock=clock)
    with pytest.raises(HandshakeError, match="timestamp"):
        responder_reply(offer2, bob, cb, consumed, clock=clock)


def test_reply_timestamp_outside_window_rejected(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    offer, pa = initiator_start(alice, clock=clock)
    reply, _pb = responder_reply(offer, bob, cb, consumed, clock=clock)
    # Forge a stale timestamp on the (otherwise genuine) reply. The
    # pending handshake is still fresh, so only the ±5 min window trips.
    stale = dict(reply, timestamp=int(clock()) - 400)
    with pytest.raises(HandshakeError, match="timestamp"):
        initiator_finish(stale, pa, ca, consumed, clock=clock)
    future = dict(reply, timestamp=int(clock()) + 400)
    with pytest.raises(HandshakeError, match="timestamp"):
        initiator_finish(future, pa, ca, consumed, clock=clock)


def test_handshake_timeout_30s(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    offer, pa = initiator_start(alice, clock=clock)
    reply, pb = responder_reply(offer, bob, cb, consumed, clock=clock)
    clock.advance(31)
    with pytest.raises(HandshakeError):
        initiator_finish(reply, pa, ca, consumed, clock=clock)


def test_key_confirmation_mac_tamper_rejected(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    offer, pa = initiator_start(alice, clock=clock)
    reply, pb = responder_reply(offer, bob, cb, consumed, clock=clock)
    finish, mat_a = initiator_finish(reply, pa, ca, consumed, clock=clock)
    bad = dict(finish)
    bad["key_confirmation_mac"] = bytes(
        b ^ 0xFF for b in finish["key_confirmation_mac"][:1]) + \
        finish["key_confirmation_mac"][1:]
    with pytest.raises(HandshakeError, match="key confirmation"):
        responder_finish(bad, pb, consumed, clock=clock)


def test_transcript_signature_tamper_rejected(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    offer, pa = initiator_start(alice, clock=clock)
    reply, pb = responder_reply(offer, bob, cb, consumed, clock=clock)
    finish, _m = initiator_finish(reply, pa, ca, consumed, clock=clock)
    bad = dict(finish)
    bad["ed_sig"] = bytes([finish["ed_sig"][0] ^ 1]) + finish["ed_sig"][1:]
    with pytest.raises(HandshakeError, match="signatures"):
        responder_finish(bad, pb, consumed, clock=clock)


def test_revocation_fail_closed_no_list(clock):
    alice, bob, _ca, _cb, consumed = _handshake_parts(clock)
    naked = RevocationChecker(operator_verify_key=None,
                              revocation_list=None)
    offer, _pa = initiator_start(alice, clock=clock)
    with pytest.raises(HandshakeError, match="revocation"):
        responder_reply(offer, bob, naked, consumed, clock=clock)


def test_revocation_stale_list_rejected(clock):
    alice, bob, _ca, _cb, consumed = _handshake_parts(clock)
    op_sk, _lst = generate_test_operator()
    stale = RevocationList(issued_at=int(clock()) - 25 * 3600, revoked=[])
    stale.sign(op_sk)
    checker = RevocationChecker(VerifyKey(bytes(op_sk.verify_key)), stale)
    offer, _pa = initiator_start(alice, clock=clock)
    with pytest.raises(HandshakeError, match="revocation"):
        responder_reply(offer, bob, checker, consumed, clock=clock)


def test_revoked_identity_rejected(clock):
    alice, bob, _ca, _cb, consumed = _handshake_parts(clock)
    op_sk, _lst = generate_test_operator()
    lst = RevocationList(issued_at=int(clock()),
                         revoked=[("alice", 1)])
    lst.sign(op_sk)
    checker = RevocationChecker(VerifyKey(bytes(op_sk.verify_key)), lst)
    offer, _pa = initiator_start(alice, clock=clock)
    with pytest.raises(HandshakeError, match="revoked"):
        responder_reply(offer, bob, checker, consumed, clock=clock)


def test_version_pinning_lower_version_rejected(clock):
    alice, bob, _ca, _cb, consumed = _handshake_parts(clock)
    checker = make_checker()
    alice_v2 = Identity.generate("alice", b"A" * 32, record_version=2)
    offer2, _ = initiator_start(alice_v2, clock=clock)
    responder_reply(offer2, bob, checker, consumed, clock=clock)
    # Same user, lower version now → pinned out.
    alice_v1 = Identity.generate("alice", b"A" * 32, record_version=1)
    offer1, _ = initiator_start(alice_v1, clock=clock)
    with pytest.raises(HandshakeError, match="pinning"):
        responder_reply(offer1, bob, checker, consumed, clock=clock)


def test_guard_level_b_rejected_without_flag(clock):
    alice, bob, ca, cb, consumed = _handshake_parts(clock)
    offer, _pa = initiator_start(alice, clock=clock)  # level B offer
    with pytest.raises(HandshakeError, match="guard_level B"):
        responder_reply(offer, bob, cb, consumed, allow_level_b=False,
                        clock=clock)


def test_pq_mechanisms_available():
    assert pq.is_available()
    kems, sigs = pq.enabled_mechanisms()
    assert "ML-KEM-768" in kems
    assert "ML-DSA-65" in sigs
