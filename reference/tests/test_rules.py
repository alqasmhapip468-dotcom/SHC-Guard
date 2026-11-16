# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Rule-order tests (freeze §4 rules 1–7), retransmission, rollback
variants, fork, reordering, gap>1000 (D-1), duplicate-replay DoS.
"""
import pytest

from shc_guard.checkpoint import (
    Checkpoint, pack_signed_checkpoint,
)
from shc_guard.session import (
    STATE_ACTIVE, STATE_QUARANTINED, STATE_SUSPECT,
)
from tests.helpers import (
    build_pair, craft_message, exchange, reencrypt_at_position,
)


def test_retransmission_outbox_resend_no_key_reuse(pair):
    a, b = pair
    from shc_guard.session import decode_wire

    w = a.send_app(b"hello")
    assert len(a.outbox) == 1
    _h, _n, orig_ct = decode_wire(w)
    resent = a.outbox.resend_all()
    assert len(resent) == 1
    # Resend returns the SAME stored ciphertext: no re-encryption,
    # no key reuse.
    assert resent[0].ciphertext == orig_ct
    assert b.receive(w)["status"] == "delivered"
    # The resent copy is an exact duplicate → silently ignored.
    assert b.receive(resent[0].header_bytes)["status"] == "ignored"
    assert b.delivered == [b"hello"]
    assert b.state == STATE_ACTIVE


def test_outbox_cap_500_and_expiry(pair, clock):
    a, b = pair
    events = []
    a.outbox.notify = lambda e, entry: events.append(e)
    for _ in range(501):
        a.send_app(b"x")
    assert len(a.outbox) == 500
    assert "dropped_overflow" in events
    clock.advance(7 * 24 * 3600 + 1)
    expired = a.outbox.expire()
    assert len(expired) == 500
    assert events.count("expired") == 500


def test_rollback_single_party_cp_digest_mismatch(pair):
    a, b = pair
    exchange(a, b, 2)
    cp = Checkpoint(session_id=b.session_id, device_id=b.my_device_id,
                    generation=b.generation,
                    cp_seq=1, tx_epoch=0, tx_ctr=b.tx_ctr, rx_epoch=0,
                    rx_ctr_max=b.rx_count, rx_digest=b"D" * 64,
                    guard_level=b.guard_level)
    wire = craft_message(b, 0x02,
                         pack_signed_checkpoint(
                             cp, cp.sign(b.material.own_identity)))
    res = a.receive(wire)
    assert res["status"] == "suspect"
    assert a.state == STATE_SUSPECT


def test_rollback_receive_only_ack_regression(pair):
    a, b = pair
    exchange(a, b, 1)  # A acked_by_peer advances to (0,1) via B's reply
    assert a.acked_by_peer == (0, 1)
    # B now claims to have received NOTHING (receive-only rollback).
    wire = craft_message(b, 0x01, b"hi",
                         ack=(0, 0, a.tx_chain.initial_digest))
    res = a.receive(wire)
    assert res["status"] == "suspect"
    assert a.state == STATE_SUSPECT


def test_rollback_below_checkpoint(pair):
    a, b = pair
    exchange(a, b, 2)
    # B attests rx=2 in a CP; A stores it.
    w = b.send_checkpoint()
    assert a.receive(w)["status"] == "checkpoint_ok"
    assert a.last_peer_cp.rx_ctr_max == 2
    # B then sends a CP attesting only rx=1 (below its own checkpoint),
    # with the CORRECT digest for count 1 — accepted as a CP, but the
    # next app message acking only 1 trips rule 5.
    digest_1 = a._tx_digest_after(0, 1)
    # v0.6 CHANGED: the regressed CP must still chain from the stored
    # CP (prev_cp_hash), or it is rejected for a broken chain instead
    # of being accepted and tripping rule 5 on the next message.
    cp = Checkpoint(session_id=b.session_id, device_id=b.my_device_id,
                    generation=b.generation,
                    cp_seq=2, tx_epoch=0, tx_ctr=b.tx_ctr, rx_epoch=0,
                    rx_ctr_max=1, rx_digest=digest_1,
                    guard_level=b.guard_level,
                    prev_cp_hash=a.last_peer_cp.digest())
    wire = craft_message(b, 0x02,
                         pack_signed_checkpoint(
                             cp, cp.sign(b.material.own_identity)),
                         consume=True)
    assert a.receive(wire)["status"] == "checkpoint_ok"
    # The regressed app message must occupy the NEXT position (the CP
    # consumed position 3) with the next chain key.
    wire2 = craft_message(b, 0x01, b"hi", ack=(0, 1, digest_1),
                          position=(0, 4), consume=True)
    res = a.receive(wire2)
    assert res["status"] == "suspect"
    assert a.state == STATE_SUSPECT


def test_rollback_above_checkpoint(pair):
    a, b = pair
    exchange(a, b, 1)
    # B's CP claims rx far beyond what A sent → outside window → SUSPECT.
    cp = Checkpoint(session_id=b.session_id, device_id=b.my_device_id,
                    generation=b.generation,
                    cp_seq=1, tx_epoch=0, tx_ctr=b.tx_ctr, rx_epoch=0,
                    rx_ctr_max=5000, rx_digest=b"D" * 64,
                    guard_level=b.guard_level)
    wire = craft_message(b, 0x02,
                         pack_signed_checkpoint(
                             cp, cp.sign(b.material.own_identity)))
    res = a.receive(wire)
    assert res["status"] == "suspect"
    assert a.state == STATE_SUSPECT  # NOT quarantined


def test_fork_same_position_different_ciphertext(pair):
    a, b = pair
    w = a.send_app(b"original")
    assert b.receive(w)["status"] == "delivered"
    fork = reencrypt_at_position(b, w, b"forged")
    res = b.receive(fork)
    assert res["status"] == "quarantined"
    assert b.state == STATE_QUARANTINED


def test_reordering_no_false_quarantine(pair):
    a, b = pair
    wires = [a.send_app(("m%d" % i).encode()) for i in range(3)]
    assert b.receive(wires[0])["status"] == "delivered"
    assert b.receive(wires[2])["status"] == "buffered"
    assert b.state == STATE_ACTIVE
    assert b.receive(wires[1])["status"] == "delivered"
    assert b.delivered == [b"m0", b"m1", b"m2"]
    assert b.state == STATE_ACTIVE


def test_reordering_all_out_of_order(pair):
    a, b = pair
    wires = [a.send_app(("m%d" % i).encode()) for i in range(3)]
    assert b.receive(wires[2])["status"] == "buffered"
    assert b.receive(wires[1])["status"] == "buffered"
    assert b.receive(wires[0])["status"] == "delivered"
    assert b.delivered == [b"m0", b"m1", b"m2"]
    assert b.state == STATE_ACTIVE


def test_gap_over_1000_is_suspect_not_quarantined(pair):
    a, b = pair
    exchange(a, b, 1)
    wire = craft_message(a, 0x01, b"far",
                         position=(0, b.expected_rx_ctr + 1001))
    res = b.receive(wire)
    assert res["status"] == "suspect"
    assert b.state == STATE_SUSPECT
    assert b.pending_challenge_wire is not None


def test_gap_exactly_1000_is_buffered(pair):
    a, b = pair
    wire = craft_message(a, 0x01, b"edge",
                         position=(0, b.expected_rx_ctr + 1000))
    res = b.receive(wire)
    assert res["status"] == "buffered"
    assert b.state == STATE_ACTIVE


def test_duplicate_replay_dos_no_suspect_parking(pair):
    a, b = pair
    w = a.send_app(b"once")
    assert b.receive(w)["status"] == "delivered"
    for _ in range(50):
        assert b.receive(w)["status"] == "ignored"
    assert b.state == STATE_ACTIVE
    assert b.suspect.state.episodes == []
    assert b.delivered == [b"once"]


def test_rule1_aead_failure_rejected(pair):
    a, b = pair
    w = bytearray(a.send_app(b"secret"))
    w[-1] ^= 0xFF  # tamper with the ciphertext tail
    res = b.receive(bytes(w))
    assert res["status"] == "rejected"
    assert b.state == STATE_ACTIVE
    assert b.delivered == []


def test_rule4_old_position_no_record(pair):
    # v0.6 CHANGED (freeze SS6): rule 4 no longer silently rejects +
    # increments an anomaly counter. An old position with no retained
    # record now enters SUSPECT + checkpoint challenge.
    a, b = pair
    exchange(a, b, 1)
    from shc_guard.session import decode_wire
    header, nonce, ct = decode_wire(a.send_app(b"z"))
    header["tx_ctr"] = 0
    # B already consumed position 0; evict it from the record map.
    b._recv_positions.clear()
    res = b._handle_replay(header, nonce, ct)
    assert res["status"] == "suspect"
    assert "rule4" in res["reason"]
    assert b.anomaly_count >= 1
    assert b.state == STATE_SUSPECT
    assert b.pending_challenge_wire is not None


def test_rule6_ack_beyond_sent_is_quarantined(pair):
    a, b = pair
    exchange(a, b, 1)
    # B claims to have received 5 more than A ever sent.
    wire = craft_message(b, 0x01, b"hi",
                         ack=(0, a.tx_ctr + 5, b"D" * 64))
    res = a.receive(wire)
    assert res["status"] == "quarantined"
    assert a.state == STATE_QUARANTINED


def test_rule7_ack_digest_mismatch_is_quarantined(pair):
    a, b = pair
    exchange(a, b, 1)
    # B acks the right count but a wrong digest.
    wire = craft_message(b, 0x01, b"hi", ack=(0, 1, b"D" * 64))
    res = a.receive(wire)
    assert res["status"] == "quarantined"
    assert a.state == STATE_QUARANTINED


def test_buffer_overflow_drops_gap_bridging_is_suspect(pair):
    # v0.6 CHANGED (D-20): the v0.5 test asserted NO quarantine for
    # overflow alone. If the overflow drops the message that would
    # complete the contiguous prefix (the lowest buffered position),
    # the session now enters SUSPECT + challenge instead of stalling
    # silently.
    a, b = pair
    wires = [a.send_app(("m%d" % i).encode()) for i in range(3)]
    # Fill B's buffer to the cap with crafted future messages, then one
    # more to overflow. Use a small cap via monkeypatching the constant.
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
        assert b.anomaly_count >= 1
        assert b.state == STATE_SUSPECT
        assert b.pending_challenge_wire is not None
    finally:
        sess_mod.OUT_OF_ORDER_CAP = old_cap


def test_quarantined_is_terminal(pair):
    from shc_guard.session import SessionError

    a, b = pair
    exchange(a, b, 1)
    wire = craft_message(b, 0x01, b"hi",
                         ack=(0, a.tx_ctr + 5, b"D" * 64))
    assert a.receive(wire)["status"] == "quarantined"
    with pytest.raises(SessionError):
        a.send_app(b"after")
    assert a.receive(craft_message(b, 0x01, b"y"))["status"] == "rejected"
