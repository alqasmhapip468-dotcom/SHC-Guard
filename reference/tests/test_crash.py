# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Crash tests: fault-injection at EVERY send and receive point
(freeze §11). Each crash must leave the session consistent.
"""
import pytest

from shc_guard.session import (
    RECV_AFTER_DECRYPT_BEFORE_SAVE, RECV_AFTER_DELIVER_BEFORE_ACK,
    RECV_AFTER_SAVE_BEFORE_DELIVER, SEND_AFTER_SAVE_BEFORE_SEND,
    SEND_AFTER_SEND_BEFORE_ACK, SEND_BEFORE_SAVE,
    SEND_DURING_ATOMIC_SAVE, STATE_ACTIVE, SimulatedCrash,
)
from tests.helpers import build_pair, exchange


# ---- send path ---------------------------------------------------------------

def test_crash_send_before_save(pair):
    a, b = pair
    a.crash_hooks.enable(SEND_BEFORE_SAVE)
    with pytest.raises(SimulatedCrash):
        a.send_app(b"lost?")
    a.crash_hooks.clear()
    assert a.tx_ctr == 0  # nothing committed
    assert len(a.outbox) == 0
    w = a.send_app(b"retry")
    assert b.receive(w)["status"] == "delivered"
    assert b.delivered == [b"retry"]


def test_crash_send_during_atomic_save(pair):
    a, b = pair
    a.crash_hooks.enable(SEND_DURING_ATOMIC_SAVE)
    with pytest.raises(SimulatedCrash):
        a.send_app(b"lost?")
    a.crash_hooks.clear()
    assert a.tx_ctr == 0  # rolled back to the snapshot
    assert len(a.outbox) == 0
    w = a.send_app(b"retry")
    assert b.receive(w)["status"] == "delivered"


def test_crash_send_after_save_before_send(pair):
    a, b = pair
    a.crash_hooks.enable(SEND_AFTER_SAVE_BEFORE_SEND)
    with pytest.raises(SimulatedCrash):
        a.send_app(b"committed")
    a.crash_hooks.clear()
    assert a.tx_ctr == 1  # committed: message exists in the outbox
    assert len(a.outbox) == 1
    resent = a.outbox.resend_all()
    assert len(resent) == 1
    assert b.receive(resent[0].header_bytes)["status"] == "delivered"
    assert b.delivered == [b"committed"]
    # The app-level retry is a NEW message at the next position.
    w = a.send_app(b"next")
    assert b.receive(w)["status"] == "delivered"
    assert b.delivered == [b"committed", b"next"]


def test_crash_send_after_send_before_ack(pair):
    a, b = pair
    a.crash_hooks.enable(SEND_AFTER_SEND_BEFORE_ACK)
    with pytest.raises(SimulatedCrash):
        a.send_app(b"sent")
    a.crash_hooks.clear()
    assert a.tx_ctr == 1
    assert len(a.outbox) == 1
    resent = a.outbox.resend_all()
    assert b.receive(resent[0].header_bytes)["status"] == "delivered"
    assert b.delivered == [b"sent"]


# ---- receive path ------------------------------------------------------------

def test_crash_recv_after_decrypt_before_save(pair):
    a, b = pair
    w = a.send_app(b"again?")
    b.crash_hooks.enable(RECV_AFTER_DECRYPT_BEFORE_SAVE)
    with pytest.raises(SimulatedCrash):
        b.receive(w)
    b.crash_hooks.clear()
    assert b.expected_rx_ctr == 0  # nothing committed
    assert b.delivered == []
    assert b.receive(w)["status"] == "delivered"  # redelivery works
    assert b.delivered == [b"again?"]


def test_crash_recv_after_save_before_deliver(pair):
    a, b = pair
    w = a.send_app(b"saved-not-delivered")
    b.crash_hooks.enable(RECV_AFTER_SAVE_BEFORE_DELIVER)
    with pytest.raises(SimulatedCrash):
        b.receive(w)
    b.crash_hooks.clear()
    assert b.expected_rx_ctr == 1  # committed…
    assert b.delivered == []  # …but not delivered
    assert b.deliver_pending()["status"] == "delivered"  # recovery path
    assert b.delivered == [b"saved-not-delivered"]
    # A redelivery now is an exact duplicate → ignored, no double deliver.
    assert b.receive(w)["status"] == "ignored"
    assert b.delivered == [b"saved-not-delivered"]


def test_crash_recv_after_deliver_before_ack(pair):
    a, b = pair
    w = a.send_app(b"delivered")
    b.crash_hooks.enable(RECV_AFTER_DELIVER_BEFORE_ACK)
    with pytest.raises(SimulatedCrash):
        b.receive(w)
    b.crash_hooks.clear()
    assert b.delivered == [b"delivered"]  # delivered despite the crash
    assert b.state == STATE_ACTIVE
    # Redelivery is a duplicate → ignored, no double delivery.
    assert b.receive(w)["status"] == "ignored"
    assert b.delivered == [b"delivered"]
    # The ack is piggybacked on B's next message; A accepts it.
    w2 = b.send_app(b"reply")
    assert a.receive(w2)["status"] == "delivered"
    assert a.acked_by_peer == (0, 1)


def test_crash_hooks_reject_unknown_point(pair):
    a, _b = pair
    with pytest.raises(ValueError):
        a.crash_hooks.enable("send:nope")
