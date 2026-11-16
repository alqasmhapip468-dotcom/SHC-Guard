# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Adversarial tests AT-01...AT-12 (freeze v0.6 SS10, ChatGPT SS11).

A test documenting a residual is a pass; a test claiming detection
that does not exist is a failure -- none of these tests claim a
detection the implementation cannot do.
"""
import threading

import pytest

from shc_guard.checkpoint import (
    Checkpoint, ZERO_HASH, pack_signed_checkpoint,
)
from shc_guard.session import (
    CHALLENGE_COMMIT_BEFORE_WRITE, STATE_ACTIVE, STATE_QUARANTINED,
    STATE_SUSPECT, SessionError, SessionRegistry, SimulatedCrash,
)
from shc_guard.suspect import DIRECTION_ISSUED, DIRECTION_RECEIVED, SuspectManager
from tests.helpers import build_pair, craft_message, exchange


def _cp(sender, rx_count, rx_digest, seq, nonce=None, prev=None,
        rx_epoch=0):
    from shc_guard.checkpoint import ZERO_NONCE
    return Checkpoint(session_id=sender.session_id,
                      device_id=sender.my_device_id,
                      generation=sender.generation,
                      cp_seq=seq, tx_epoch=0, tx_ctr=sender.tx_ctr,
                      rx_epoch=rx_epoch, rx_ctr_max=rx_count,
                      rx_digest=rx_digest, guard_level=sender.guard_level,
                      prev_cp_hash=prev if prev is not None else ZERO_HASH,
                      challenge_nonce=nonce if nonce is not None else ZERO_NONCE)


def _force_suspect_via_gap(b, a):
    wire = craft_message(a, 0x01, b"far",
                         position=(0, b.expected_rx_ctr + 1001))
    assert b.receive(wire)["status"] == "suspect"
    assert b.state == STATE_SUSPECT
    return b.pending_challenge_wire


# ---- AT-01: both-parties rollback -> anchor-absent warning / non-detection
def test_at01_both_parties_rollback_not_detected(pair):
    """Documents the P0-1 residual: with no external anchor, a
    well-signed CP over rolled-back state is ACCEPTED. The test
    asserts the warning is surfaced, NOT that the rollback is
    detected (claiming detection would be false)."""
    a, b = pair
    exchange(a, b, 2)
    w = b.send_checkpoint()
    assert a.receive(w)["status"] == "checkpoint_ok"
    # B rolls back: attests only rx=1, with the CORRECT digest for 1.
    digest_1 = b.rx_chain.digest_at(0, 0)
    cp = _cp(b, 1, digest_1, seq=2, prev=a.last_peer_cp.digest())
    wire = craft_message(b, 0x02,
                         pack_signed_checkpoint(
                             cp, cp.sign(b.material.own_identity)),
                         consume=True)
    res = a.receive(wire)
    assert res["status"] == "checkpoint_ok"  # accepted: no detection
    assert a.anchor_warning is not None  # ...but the warning is surfaced
    assert any(e == "anchor_absent" for e, _ in a.notifications)


# ---- AT-02: fork outside the window -> SUSPECT + challenge, no detection claim
def test_at02_fork_outside_window_is_suspect(pair):
    a, b = pair
    exchange(a, b, 1)
    from shc_guard.session import decode_wire
    header, nonce, ct = decode_wire(a.send_app(b"z"))
    header["tx_ctr"] = 0
    b._recv_positions.clear()  # position evicted from the window
    res = b._handle_replay(header, nonce, ct)
    assert res["status"] == "suspect"
    assert b.state == STATE_SUSPECT
    assert b.pending_challenge_wire is not None
    # No claim that the fork itself was detected -- only that the
    # challenge path was entered.


# ---- AT-03: tx_epoch / rx_epoch mismatch -> reject
def test_at03_split_epoch_mismatch_rejected(pair):
    a, b = pair
    exchange(a, b, 1)
    # A message whose tx_epoch does not match B's rx_epoch.
    wire = craft_message(a, 0x01, b"x", position=(5, b.expected_rx_ctr))
    res = b.receive(wire)
    assert res["status"] == "rejected"
    assert "rx_epoch" in res["reason"]
    # A CP whose rx_epoch does not match any sent position: the digest
    # is checked at (rx_epoch, rx_ctr_max) -- epoch 5 has no history.
    cp = _cp(b, b.rx_count, b.rx_chain.digest, seq=1, rx_epoch=5)
    wire2 = craft_message(b, 0x02,
                          pack_signed_checkpoint(
                              cp, cp.sign(b.material.own_identity)))
    res2 = a.receive(wire2)
    assert res2["status"] == "suspect"  # outside window, not accepted
    assert a.state == STATE_SUSPECT


# ---- AT-04: stale CP after CP loss -> SUSPECT / QUARANTINED
def test_at04_stale_cp_after_cp_loss_is_suspect(pair):
    a, b = pair
    exchange(a, b, 2)
    w = b.send_checkpoint()
    assert a.receive(w)["status"] == "checkpoint_ok"
    stored_digest = a.last_peer_cp.digest()
    a.last_peer_cp = None  # A loses its stored CPs
    # B's next CP chains from the lost CP; A expects the zero hash.
    cp = _cp(b, b.rx_count, b.rx_chain.digest, seq=2, prev=stored_digest)
    wire = craft_message(b, 0x02,
                         pack_signed_checkpoint(
                             cp, cp.sign(b.material.own_identity)))
    res = a.receive(wire)
    assert res["status"] == "suspect"
    assert a.state == STATE_SUSPECT


# ---- AT-05: concurrent challenges, nonces not cross-accepted
def test_at05_concurrent_challenges_not_cross_accepted(pair):
    a, b = pair
    exchange(a, b, 1)
    # B challenges A; A also challenges B (independent directions).
    chal_b = _force_suspect_via_gap(b, a)
    assert a.receive(chal_b)["status"] == "challenge_received"
    chal_a_wire = a._send_control(0x03, a.suspect.issue_challenge())
    assert b.receive(chal_a_wire)["status"] == "challenge_received"
    # A answers B's challenge carrying A'S OWN issued nonce (crossed).
    wrong = a.send_checkpoint(
        challenge_nonce=a.suspect.outstanding_nonce)
    res = b.receive(wrong)
    assert res["status"] == "rejected"
    assert b.state == STATE_SUSPECT  # B's challenge still outstanding


def test_at05_challenge_tables_are_per_direction():
    mgr = SuspectManager(clock=lambda: 1000.0)
    mgr.enter_suspect("test")
    n_issued = mgr.issue_challenge(DIRECTION_ISSUED)
    n_received = mgr.issue_challenge(DIRECTION_RECEIVED)
    assert n_issued != n_received
    # Issuing again in the issued direction supersedes only that one.
    n_issued2 = mgr.issue_challenge(DIRECTION_ISSUED)
    assert mgr.outstanding_nonce_for(DIRECTION_ISSUED) == n_issued2
    assert mgr.outstanding_nonce_for(DIRECTION_RECEIVED) == n_received
    assert mgr.tables[DIRECTION_ISSUED].is_superseded(n_issued)
    assert not mgr.tables[DIRECTION_RECEIVED].is_superseded(n_received)


# ---- AT-06: crash between challenge commit and ACTIVE
def test_at06_crash_between_challenge_commit_and_active(pair):
    a, b = pair
    exchange(a, b, 1)
    chal = _force_suspect_via_gap(b, a)
    assert a.receive(chal)["status"] == "challenge_received"
    resp = a.respond_to_challenge()
    assert resp is not None
    nonce = b.suspect.outstanding_nonce
    b.crash_hooks.enable(CHALLENGE_COMMIT_BEFORE_WRITE)
    with pytest.raises(SimulatedCrash):
        b.receive(resp)
    b.crash_hooks.clear()
    # Crash mid-commit: SUSPECT with the challenge still pending,
    # nonce NOT consumed -- never ACTIVE without proof.
    assert b.state == STATE_SUSPECT
    assert b.suspect.outstanding_nonce == nonce
    assert not b.suspect.tables[DIRECTION_ISSUED].is_consumed(nonce)
    # Retransmission of the same CP-bearing message completes it.
    res = b.receive(resp)
    assert res["status"] == "checkpoint_ok"
    assert b.state == STATE_ACTIVE
    assert b.suspect.tables[DIRECTION_ISSUED].is_consumed(nonce)


# ---- AT-07: new session while old ACTIVE -> old CLOSED atomically
def test_at07_new_session_closes_old_atomically():
    from tests.helpers import FakeClock
    clock = FakeClock()
    a1, b1 = build_pair(clock)
    w_old = a1.send_app(b"old generation message")
    assert b1.receive(w_old)["status"] == "delivered"
    reg_a = SessionRegistry()
    reg_b = SessionRegistry()
    assert reg_a.register(a1) == 1
    assert reg_b.register(b1) == 1
    a2, b2 = build_pair(clock, generation=2)
    assert reg_a.register(a2) == 2
    assert reg_b.register(b2) == 2
    # Old session: CLOSED, outbox fail-notified, keys erased.
    assert a1.state == "CLOSED"
    assert b1.state == "CLOSED"
    assert a1.material.root_key == bytes(32)
    assert any(e == "outbox_failed" for e, _ in a1.notifications)
    assert a2.state == STATE_ACTIVE and b2.state == STATE_ACTIVE
    assert a2.generation == 2
    # A message from the old generation is rejected by the new session.
    assert b2.receive(w_old)["status"] == "rejected"
    with pytest.raises(SessionError):
        a1.send_app(b"after close")


# ---- AT-08: transcript replay after 7 days -> rejected (D-19)
def test_at08_transcript_replay_after_7_days_rejected(clock):
    from shc_guard.handshake import (
        ConsumedHandshakeIDs, HandshakeError, initiator_confirm,
        initiator_finish, initiator_start, responder_finish, responder_reply,
    )
    from shc_guard.identity import Identity
    from shc_guard.session import Session
    from tests.helpers import make_checker
    alice = Identity.generate("alice", b"A" * 32)
    bob = Identity.generate("bob", b"B" * 32)
    consumed = ConsumedHandshakeIDs(clock=clock)
    offer, pa = initiator_start(alice, clock=clock)
    reply, pb = responder_reply(offer, bob, make_checker(), consumed,
                                clock=clock)
    finish, mat_a = initiator_finish(reply, pa, make_checker(), consumed,
                                     clock=clock)
    confirm, mat_b = responder_finish(finish, pb, consumed, clock=clock)
    initiator_confirm(confirm, mat_a)
    Session(mat_a, consumed_ids=consumed, clock=clock).save()
    # 8 days pass: D-19 says the ID is STILL consumed (lifetime).
    clock.advance(8 * 24 * 3600)
    assert consumed.is_consumed(offer["handshake_id"])
    # Replay the same offer with a fresh timestamp (so only the
    # consumed-ID check can trip, not the +/-5 min window).
    offer = dict(offer, timestamp=int(clock()))
    with pytest.raises(HandshakeError, match="consumed"):
        responder_reply(offer, bob, make_checker(), consumed, clock=clock)


# ---- AT-09: buffer overflow drops the gap-bridging message -> SUSPECT
def test_at09_buffer_overflow_drops_gap_bridging_is_suspect(pair):
    a, b = pair
    wires = [a.send_app(("m%d" % i).encode()) for i in range(3)]
    import shc_guard.session as sess_mod
    old_cap = sess_mod.OUT_OF_ORDER_CAP
    sess_mod.OUT_OF_ORDER_CAP = 2
    try:
        assert b.receive(wires[1])["status"] == "buffered"
        assert b.receive(wires[2])["status"] == "buffered"
        w3 = craft_message(a, 0x01, b"m3",
                           position=(0, b.expected_rx_ctr + 3))
        res = b.receive(w3)
        assert res["status"] == "suspect"
        assert b.state == STATE_SUSPECT
        assert b.pending_challenge_wire is not None
    finally:
        sess_mod.OUT_OF_ORDER_CAP = old_cap


# ---- AT-10: concurrent sends, same counter -> second refused
def test_at10_concurrent_send_same_counter_refused(pair):
    a, b = pair
    # Hold the single-writer lock: a second send is refused, never run.
    assert a._send_lock.acquire(blocking=False)
    try:
        with pytest.raises(SessionError, match="concurrent send"):
            a.send_app(b"second")
    finally:
        a._send_lock.release()
    assert a.tx_ctr == 0
    w = a.send_app(b"first")
    assert b.receive(w)["status"] == "delivered"


def test_at10_two_threads_one_send_wins(pair):
    # Deterministic overlap: thread 1 is held INSIDE the send (lock
    # held) while thread 2 attempts -- the second send is refused,
    # never executed, and exactly one send commits.
    import types
    a, b = pair
    entered = threading.Event()
    release = threading.Event()
    orig = a._send_plaintext_locked

    def _slow(self, ptype, payload):
        entered.set()
        assert release.wait(5)
        return orig(ptype, payload)

    a._send_plaintext_locked = types.MethodType(_slow, a)
    results = []

    def _send(i):
        try:
            results.append(("ok", a.send_app(("t%d" % i).encode())))
        except SessionError as exc:
            results.append(("refused", str(exc)))

    t1 = threading.Thread(target=_send, args=(0,))
    t1.start()
    assert entered.wait(5)
    t2 = threading.Thread(target=_send, args=(1,))
    t2.start()
    t2.join(timeout=5)
    assert not t2.is_alive()
    release.set()
    t1.join(timeout=5)
    assert a.tx_ctr == 1  # exactly one send committed
    assert sorted(r[0] for r in results) == ["ok", "refused"]
    wire = [r[1] for r in results if r[0] == "ok"][0]
    assert b.receive(wire)["status"] == "delivered"


# ---- AT-11: rollback with peer's CPs lost -> degraded-mode warning
def test_at11_rollback_with_cps_lost_degraded_warning(pair):
    """No false detection claim: the CP is accepted, but the session
    is flagged degraded and the app is warned (attestation only)."""
    a, b = pair
    exchange(a, b, 2)
    w = b.send_checkpoint()
    assert a.receive(w)["status"] == "checkpoint_ok"
    a.last_peer_cp = None  # A loses the peer's CPs
    # B's next CP (seq 2) chains from nothing A can check; it is
    # accepted, with a degraded-mode warning -- NOT a detection claim.
    cp = _cp(b, b.rx_count, b.rx_chain.digest, seq=2, prev=ZERO_HASH)
    wire = craft_message(b, 0x02,
                         pack_signed_checkpoint(
                             cp, cp.sign(b.material.own_identity)))
    res = a.receive(wire)
    assert res["status"] == "checkpoint_ok"
    assert a.degraded_mode is True
    assert any(e == "degraded_mode" for e, _ in a.notifications)
    assert a.state == STATE_ACTIVE  # no false quarantine either


# ---- AT-12: compromised signer, false CP -> attestation-only flag
def test_at12_compromised_signer_flagged_attestation_only(pair):
    a, b = pair
    exchange(a, b, 1)
    # The signer's key is reported compromised out-of-band. The CP
    # still verifies (well-signed) -- it is NOT rejected as "invalid
    # device". Instead the session is flagged attestation-only.
    a.flag_attestation_only("peer signing key reported compromised")
    assert a.attestation_only is True
    assert any(e == "attestation_only" for e, _ in a.notifications)
    w = b.send_checkpoint()
    assert a.receive(w)["status"] == "checkpoint_ok"
    assert a.attestation_only is True  # flag survives a valid CP
    assert a.state == STATE_ACTIVE
