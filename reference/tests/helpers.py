# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Shared fixtures + forgery harness for the SHC-Guard v0.6 tests.

The harness crafts wire messages with a sender's own keys (the
rollback/fork threat model is a rolled-back or compromised peer, so a
test may use the sender's live ratchet state to build messages the
sender never actually sent). Crafted messages are TERMINAL for that
pair: the sender's ratchet is snapshotted/restored around the craft,
so later real sends from that sender would desync — use a fresh pair
per scenario.
"""

import time

from nacl.signing import VerifyKey

from shc_guard import aead
from shc_guard.aead import AAD
from shc_guard.handshake import (
    ConsumedHandshakeIDs, initiator_confirm, initiator_finish,
    initiator_start, responder_finish, responder_reply,
)
from shc_guard.identity import Identity
from shc_guard.revocation import RevocationChecker, generate_test_operator
from shc_guard.session import Session, decode_wire, encode_wire


class FakeClock:
    """Controllable clock (callable returning a float)."""

    def __init__(self, start: float = None):
        self.now = float(start if start is not None else time.time())

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_checker():
    op_sk, op_list = generate_test_operator()
    checker = RevocationChecker(VerifyKey(bytes(op_sk.verify_key)), op_list)
    return checker


def build_pair(clock=None, allow_level_b=True, generation=1,
               anchor=None, allow_unverified=False,
               verify_fingerprints=True):
    """Build a fresh ACTIVE pair. Fingerprints are verified out-of-band
    (freeze SS5) before any application message is sent: the harness
    compares each peer's fingerprint and marks it verified, mirroring
    what the demo does explicitly. Pass allow_unverified=True only for
    tests of the TOFU gate itself."""
    clock = clock or FakeClock()
    alice = Identity.generate("alice", b"A" * 32)
    bob = Identity.generate("bob", b"B" * 32)
    checker_a = make_checker()
    checker_b = make_checker()
    consumed = ConsumedHandshakeIDs(clock=clock)
    offer, pend_a = initiator_start(alice, allow_level_b=allow_level_b,
                                    clock=clock, generation=generation)
    reply, pend_b = responder_reply(offer, bob, checker_b, consumed,
                                    allow_level_b=allow_level_b, clock=clock)
    finish, mat_a = initiator_finish(reply, pend_a, checker_a, consumed,
                                     clock=clock)
    confirm, mat_b = responder_finish(finish, pend_b, consumed, clock=clock)
    initiator_confirm(confirm, mat_a)
    a = Session(mat_a, consumed_ids=consumed, clock=clock, anchor=anchor,
                allow_unverified=allow_unverified)
    b = Session(mat_b, consumed_ids=consumed, clock=clock, anchor=anchor,
                allow_unverified=allow_unverified)
    a.save()
    b.save()
    if not allow_unverified and verify_fingerprints:
        # Out-of-band fingerprint verification (test harness stands in
        # for the user comparing fingerprints on a second channel).
        assert a.verify_peer_fingerprint(
            b.material.own_identity.fingerprint().hex())
        assert b.verify_peer_fingerprint(
            a.material.own_identity.fingerprint().hex())
    assert a.state == "ACTIVE" and b.state == "ACTIVE"
    return a, b


def exchange(a, b, n=1):
    """Send n app messages each way; return (a_delivered, b_delivered)."""
    for i in range(n):
        w = a.send_app(("a%d" % i).encode())
        assert b.receive(w)["status"] == "delivered"
        w = b.send_app(("b%d" % i).encode())
        assert a.receive(w)["status"] == "delivered"
    return a.delivered, b.delivered


def craft_message(sender: Session, ptype: int, payload: bytes,
                  ack=None, position=None, consume: bool = False):
    """Craft a wire message from ``sender`` WITHOUT committing its state.

    ``ack`` overrides (ack_epoch, ack_ctr, ack_digest); ``position``
    overrides (epoch, tx_ctr). By default the sender's ratchet is
    snapshotted and restored, so the crafted message is terminal for
    this pair. With ``consume=True`` the ratchet advance (key + any
    rotation) is KEPT, so a sequence of crafted messages can occupy
    successive positions — the caller must then pass explicit
    ``position`` values; the sender's tx_ctr is never advanced here.
    """
    from shc_guard.session import PT_APP  # noqa: F401  (docs only)

    snap = sender.ratchet.snapshot()
    try:
        sender.ratchet.rotate_for_send()
        key = sender.ratchet.peek_send_key()
        if consume:
            sender.ratchet.advance_send_chain()
        header_pub = sender.ratchet.dh_public
        epoch, ctr = position or (sender.tx_epoch, sender.tx_ctr)
        if ack is None:
            ack_epoch, ack_ctr, ack_digest = sender._my_ack()
        else:
            ack_epoch, ack_ctr, ack_digest = ack
        aad = AAD(sender.session_id, sender.my_device_id,
                  sender.generation, epoch, ctr,
                  ack_epoch, ack_ctr, ack_digest)
        nonce = aead.fresh_nonce()
        ct = aead.encrypt(key, nonce, bytes([ptype]) + payload, aad)
        header = {
            "session_id": sender.session_id,
            "sender_device_id": sender.my_device_id,
            "generation": sender.generation,
            "tx_epoch": epoch, "tx_ctr": ctr,
            "ack_rx_epoch": ack_epoch, "ack_ctr": ack_ctr,
            "ack_digest": ack_digest, "ratchet_eph": header_pub,
        }
        return encode_wire(header, nonce, ct)
    finally:
        if not consume:
            sender.ratchet.restore(snap)


def reencrypt_at_position(receiver: Session, wire: bytes, new_payload: bytes):
    """Re-encrypt ``wire``'s plaintext at the SAME position with the
    receiver's STORED message key (same AAD/header), new app payload.

    Used for the fork test: same position, valid decrypt, different
    ciphertext hash → rule 3.
    """
    header, nonce, _ct = decode_wire(wire)
    pos = (header["tx_epoch"], header["tx_ctr"])
    key, _h = receiver._recv_positions[pos]
    aad = AAD(receiver.session_id, header["sender_device_id"],
              header.get("generation", 1),
              header["tx_epoch"], header["tx_ctr"], header["ack_rx_epoch"],
              header["ack_ctr"], header["ack_digest"])
    ct = aead.encrypt(key, nonce, bytes([0x01]) + new_payload, aad)
    return encode_wire(header, nonce, ct)
