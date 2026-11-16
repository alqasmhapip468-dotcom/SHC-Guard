# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Misc session tests: rekeying, 7-day no-ack warning, close, demo pair
lifecycle, state-machine transition guards.
"""
import pytest

from shc_guard.session import (
    STATE_ACTIVE, STATE_CLOSED, STATE_QUARANTINED, STATE_REKEYING,
    SessionError,
)
from tests.helpers import build_pair, exchange


def test_rekey_round_trip(pair, clock):
    a, b = pair
    exchange(a, b, 1)
    a.start_rekey()
    assert a.state == STATE_REKEYING
    with pytest.raises(SessionError):
        a.send_app(b"blocked while rekeying")
    # Fresh handshake material for the rekey (reuse the pair builder's
    # material shape via a second full handshake is heavy; instead the
    # rekey path is exercised with the ORIGINAL material to check the
    # state machine mechanics — epoch bumps, counters reset).
    a.complete_rekey(a.material)
    assert a.state == STATE_ACTIVE
    assert a.epoch == 1
    assert a.tx_ctr == 0


def test_rekey_timeout_closes(pair, clock):
    a, _b = pair
    a.start_rekey()
    clock.advance(31)
    a.check_rekey_timeout()
    assert a.state == STATE_CLOSED


def test_no_ack_advance_7day_warning_no_close(pair, clock):
    a, b = pair
    w = a.send_app(b"unacked")
    assert b.receive(w)["status"] == "delivered"
    # B never replies → A's outbox still holds the message; after 7 days
    # of no ack advance A must warn (لا يمكن التحقق) but NOT close.
    assert a.ack_stale_warning is False
    clock.advance(7 * 24 * 3600 + 1)
    a.check_ack_staleness()
    assert a.ack_stale_warning is True
    assert a.state == STATE_ACTIVE
    assert any(e == "ack_stale" for e, _ in a.notifications)


def test_ack_advance_clears_staleness_risk(pair, clock):
    a, b = pair
    exchange(a, b, 1)  # B's reply acks A's message
    assert len(a.outbox) == 0
    clock.advance(8 * 24 * 3600)
    a.check_ack_staleness()
    assert a.ack_stale_warning is False  # nothing unacked → no warning


def test_close_then_new_session(pair):
    a, b = pair
    a.close()
    assert a.state == STATE_CLOSED
    with pytest.raises(SessionError):
        a.send_app(b"nope")
    # A NEW session (new handshake) is the only path back.
    a2, b2 = build_pair()
    assert a2.state == STATE_ACTIVE and b2.state == STATE_ACTIVE
    assert a2.session_id != a.session_id


def test_quarantined_cannot_return_to_active(pair):
    a, b = pair
    from tests.helpers import craft_message
    exchange(a, b, 1)
    wire = craft_message(b, 0x01, b"hi",
                         ack=(0, a.tx_ctr + 5, b"D" * 64))
    assert a.receive(wire)["status"] == "quarantined"
    assert a.state == STATE_QUARANTINED
    # No API moves QUARANTINED → ACTIVE; only close() is allowed.
    a.close()
    assert a.state == STATE_CLOSED
