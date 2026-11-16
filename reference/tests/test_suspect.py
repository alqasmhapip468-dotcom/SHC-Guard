# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""SUSPECT challenge tests (freeze §5): success / failure / timeout /
deadline-by-messages / three episodes in 24h.
"""
import pytest

from shc_guard.checkpoint import Checkpoint, pack_signed_checkpoint
from shc_guard.session import STATE_ACTIVE, STATE_QUARANTINED, STATE_SUSPECT
from shc_guard.suspect import SuspectManager
from tests.helpers import build_pair, craft_message, exchange


def _force_suspect_via_gap(b, a):
    """Drive ``b`` into SUSPECT with a gap>1000 message from ``a``."""
    wire = craft_message(a, 0x01, b"far",
                         position=(0, b.expected_rx_ctr + 1001))
    assert b.receive(wire)["status"] == "suspect"
    assert b.state == STATE_SUSPECT
    assert b.pending_challenge_wire is not None
    return b.pending_challenge_wire


def test_suspect_challenge_success(pair):
    a, b = pair
    exchange(a, b, 1)
    chal = _force_suspect_via_gap(b, a)
    assert a.receive(chal)["status"] == "challenge_received"
    assert a._peer_challenge_nonce is not None
    resp = a.respond_to_challenge()
    assert resp is not None
    res = b.receive(resp)
    assert res["status"] == "checkpoint_ok"
    assert b.state == STATE_ACTIVE
    # Session still works after resolution.
    w = a.send_app(b"after")
    assert b.receive(w)["status"] == "delivered"


def test_suspect_challenge_wrong_nonce_then_timeout(pair, clock):
    a, b = pair
    exchange(a, b, 1)
    chal = _force_suspect_via_gap(b, a)
    assert a.receive(chal)["status"] == "challenge_received"
    # A answers with a checkpoint carrying the WRONG nonce.
    wrong = a.send_checkpoint(challenge_nonce=b"N" * 32)
    assert b.receive(wrong)["status"] == "rejected"
    assert b.state == STATE_SUSPECT  # not resolved
    # 60s deadline passes → next valid message quarantines.
    clock.advance(61)
    w = a.send_app(b"too-late")
    res = b.receive(w)
    assert res["status"] == "quarantined"
    assert b.state == STATE_QUARANTINED


def test_suspect_challenge_timeout_no_response(pair, clock):
    a, b = pair
    _force_suspect_via_gap(b, a)
    clock.advance(61)
    w = a.send_app(b"late")
    assert b.receive(w)["status"] == "quarantined"
    assert b.state == STATE_QUARANTINED


def test_suspect_challenge_deadline_20_messages(pair):
    a, b = pair
    _force_suspect_via_gap(b, a)
    # A never answers the challenge; 20 valid messages → quarantine.
    for i in range(19):
        assert b.receive(a.send_app(("m%d" % i).encode()))["status"] \
            == "delivered"
        assert b.state == STATE_SUSPECT
    res = b.receive(a.send_app(b"m19"))
    assert res["status"] == "quarantined"
    assert b.state == STATE_QUARANTINED


def test_suspect_rolled_back_cp_fails_challenge(pair):
    """A merely well-signed CP over rolled-back state FAILS (§5)."""
    a, b = pair
    exchange(a, b, 2)
    # A stores a CP from B attesting rx=2.
    w = b.send_checkpoint()
    assert a.receive(w)["status"] == "checkpoint_ok"
    chal = _force_suspect_via_gap(a, b)
    assert b.receive(chal)["status"] == "challenge_received"
    # B answers with the right nonce but REGRESSED counters (rx=1,
    # correct digest for 1) — signed rollback must fail. The correct
    # digest for count 1 is B's rx digest after its first message.
    digest_1 = b.rx_chain.digest_at(0, 0)
    # v0.6 CHANGED: the challenge answer must chain from the stored
    # CP (prev_cp_hash), or it fails on the broken chain instead of
    # on the regression check.
    cp = Checkpoint(session_id=b.session_id, device_id=b.my_device_id,
                    generation=b.generation,
                    cp_seq=2, tx_epoch=0, tx_ctr=b.tx_ctr, rx_epoch=0,
                    rx_ctr_max=1, rx_digest=digest_1,
                    guard_level=b.guard_level,
                    prev_cp_hash=a.last_peer_cp.digest(),
                    challenge_nonce=b._peer_challenge_nonce)
    wire = craft_message(b, 0x02,
                         pack_signed_checkpoint(
                             cp, cp.sign(b.material.own_identity)))
    res = a.receive(wire)
    assert res["status"] == "quarantined"
    assert a.state == STATE_QUARANTINED


def test_three_suspect_episodes_in_24h_quarantines(pair):
    a, b = pair
    exchange(a, b, 1)
    for _ in range(2):
        chal = _force_suspect_via_gap(b, a)
        assert a.receive(chal)["status"] == "challenge_received"
        assert b.receive(a.respond_to_challenge())["status"] == "checkpoint_ok"
        assert b.state == STATE_ACTIVE
    # Third episode within 24h → QUARANTINED immediately.
    wire = craft_message(a, 0x01, b"far",
                         position=(0, b.expected_rx_ctr + 1001))
    assert b.receive(wire)["status"] == "quarantined"
    assert b.state == STATE_QUARANTINED


def test_suspect_blocks_app_sending(pair):
    from shc_guard.session import SessionError

    a, b = pair
    _force_suspect_via_gap(b, a)
    with pytest.raises(SessionError):
        b.send_app(b"not allowed in SUSPECT")


def test_suspect_manager_unit():
    mgr = SuspectManager(clock=lambda: 1000.0)
    assert not mgr.deadline_exceeded()
    assert not mgr.enter_suspect("first")
    nonce = mgr.issue_challenge()
    assert len(nonce) == 32
    assert mgr.outstanding_nonce == nonce
    ok, _why = mgr.check_response(
        type("CP", (), {"challenge_nonce": nonce, "tx_ctr": 5,
                        "rx_ctr_max": 5})(), True, None)
    assert ok
    ok2, _ = mgr.check_response(
        type("CP", (), {"challenge_nonce": b"X" * 32, "tx_ctr": 5,
                        "rx_ctr_max": 5})(), True, None)
    assert not ok2
