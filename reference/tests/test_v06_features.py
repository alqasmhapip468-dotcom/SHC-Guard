# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""v0.6 feature tests: LocalAnchor, TOFU gate, hw-bound state key,
one-session generation, v0.5 wire rejection, identity rotation,
challenge-table persistence, split-epoch CP verification.
"""
import json
import os

import pytest

from shc_guard.anchor import AnchorCorruptError, LocalAnchor
from shc_guard.checkpoint import (
    Checkpoint, ZERO_HASH, pack_signed_checkpoint,
)
from shc_guard.handshake import HandshakeError, initiator_start
from shc_guard.identity import (
    Identity, create_rotation_record, verify_rotation_record,
)
from shc_guard.journal import (
    BOOT_ROLLBACK, BOOT_SOUND, DoubleJournal, JournalRecord,
    SimulatedHwCounter, derive_state_key, seal_state_record,
    unseal_state_record,
)
from shc_guard.session import (
    STATE_ACTIVE, STATE_QUARANTINED, SessionError,
)
from shc_guard.suspect import ChallengeTable
from tests.helpers import build_pair, craft_message, exchange


# ---- LocalAnchor -----------------------------------------------------------

def test_anchor_register_receipt_and_chain(tmp_path):
    anchor = LocalAnchor(str(tmp_path / "anchor.log"))
    r1 = anchor.register(bytes([0x31] * 64))
    r2 = anchor.register(bytes([0x32] * 64))
    assert r1.anchor_seq == 1 and r2.anchor_seq == 2
    assert anchor.verify_receipt(r1) and anchor.verify_receipt(r2)
    assert anchor.get_latest().anchor_seq == 2
    assert anchor.head == r2.entry_hash
    # Reload verifies the chain.
    anchor2 = LocalAnchor(str(tmp_path / "anchor.log"))
    assert len(anchor2) == 2
    assert anchor2.head == r2.entry_hash


def test_anchor_rewritten_log_refused(tmp_path):
    anchor = LocalAnchor(str(tmp_path / "anchor.log"))
    anchor.register(bytes([0x31] * 64))
    anchor.register(bytes([0x32] * 64))
    # Rewrite the second entry's cp_hash in place: chain breaks.
    lines = open(str(tmp_path / "anchor.log")).read().splitlines()
    entry = json.loads(lines[2])
    entry["cp_hash"] = (bytes([0x99] * 64)).hex()
    lines[2] = json.dumps(entry)
    open(str(tmp_path / "anchor.log"), "w").write("\n".join(lines) + "\n")
    with pytest.raises(AnchorCorruptError):
        LocalAnchor(str(tmp_path / "anchor.log"))


def test_anchor_truncated_log_refused_against_stored_tip(tmp_path):
    anchor = LocalAnchor(str(tmp_path / "anchor.log"))
    anchor.register(bytes([0x31] * 64))
    r2 = anchor.register(bytes([0x32] * 64))
    # Truncate the tail (drop the last entry) and reload against the
    # stored tip: refused, never silently repaired.
    lines = open(str(tmp_path / "anchor.log")).read().splitlines()
    open(str(tmp_path / "anchor.log"), "w").write("\n".join(lines[:2]) + "\n")
    with pytest.raises(AnchorCorruptError):
        LocalAnchor(str(tmp_path / "anchor.log"),
                    expected_head=r2.entry_hash)


def test_anchor_extends():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        anchor = LocalAnchor(os.path.join(td, "a.log"))
        h0 = anchor.head
        r1 = anchor.register(bytes([0x31] * 64))
        r2 = anchor.register(bytes([0x32] * 64))
        assert anchor.extends(bytes(64), r1.entry_hash)
        assert anchor.extends(r1.entry_hash, r2.entry_hash)
        assert anchor.extends(r1.entry_hash, r1.entry_hash)
        assert not anchor.extends(r2.entry_hash, r1.entry_hash)
        assert not anchor.extends(r2.entry_hash, bytes(64))
        assert not anchor.extends(h0, bytes([0x77] * 64))


def test_anchor_cp_flow_end_to_end(tmp_path):
    """Both parties share one stand-in anchor file; CPs register
    before sending and the peer's anchor-head check passes."""
    anchor = LocalAnchor(str(tmp_path / "anchor.log"))
    a, b = build_pair(anchor=anchor)
    exchange(a, b, 1)
    w = a.send_checkpoint()
    assert len(anchor) == 1  # CP hash registered before sending
    assert b.receive(w)["status"] == "checkpoint_ok"
    # First CP's anchor_head is the head known when it was built
    # (zero: no entry yet); the registration precedes the send.
    assert b._peer_anchor_head == bytes(64)
    w2 = b.send_checkpoint()
    assert a.receive(w2)["status"] == "checkpoint_ok"
    assert len(anchor) == 2
    assert a._peer_anchor_head != bytes(64)  # now includes A's entry


# ---- TOFU gate (SS5) ---------------------------------------------------------

def test_tofu_blocks_app_sending_until_verified():
    a, b = build_pair(verify_fingerprints=False)  # fresh TOFU peers
    assert a.trust.status_of(a.peer_record.fingerprint()) == \
        "TRUSTED-UNVERIFIED"
    with pytest.raises(SessionError, match="unverified"):
        a.send_app(b"not yet")
    # Wrong fingerprint does not verify.
    assert not a.verify_peer_fingerprint("00" * 64)
    assert not a.peer_verified
    # The real out-of-band fingerprint verifies.
    assert a.verify_peer_fingerprint(
        b.material.own_identity.fingerprint().hex())
    assert a.peer_verified
    w = a.send_app(b"now ok")
    assert b.receive(w)["status"] == "delivered"


# ---- hw-bound state key (SS8) -------------------------------------------------

def test_state_key_derivation_is_hw_bound():
    master = bytes(range(32))
    k1 = derive_state_key(master, 5)
    k2 = derive_state_key(master, 6)
    assert k1 != k2
    assert derive_state_key(master, 5) == k1  # deterministic


def test_state_record_seal_unseal_and_header_tamper():
    master = bytes(range(32))
    blob = seal_state_record(master, 7, b"state-bytes")
    hw, pt = unseal_state_record(master, blob)
    assert hw == 7 and pt == b"state-bytes"
    # Tamper with the header hw_at_save: AEAD verification fails.
    import struct
    (hlen,) = struct.unpack(">I", blob[:4])
    header = json.loads(blob[4:4 + hlen])
    header["hw_at_save"] = 8
    bad_header = json.dumps(header, sort_keys=True).encode()
    bad = struct.pack(">I", len(bad_header)) + bad_header + blob[4 + hlen:]
    with pytest.raises(ValueError):
        unseal_state_record(master, bad)
    # Wrong master key fails too.
    with pytest.raises(ValueError):
        unseal_state_record(bytes([0xFF] * 32), blob)


def test_send_path_refuses_on_hw_mismatch(tmp_path, clock):
    from shc_guard.journal import DoubleJournal
    from tests.helpers import FakeClock
    clock = FakeClock()
    a, b = build_pair(clock)
    key = bytes([0x4B] * 32)
    a.journal = DoubleJournal(str(tmp_path / "j"), key)
    a.hw_counter = SimulatedHwCounter(str(tmp_path / "hw.json"))
    a.state_master_key = bytes(range(32))
    a.save()
    assert a._stored_hw == 1
    # The counter advances without a save (crash / rollback window).
    a.hw_counter.increment()
    with pytest.raises(SessionError, match="hw counter mismatch"):
        a.send_app(b"must not send")
    assert a.state == STATE_QUARANTINED
    # Boot check on the sealed record still verifies (sound case
    # relative to the stored record's own hw value).
    case, hw_at_save, pt = a.verify_saved_state()
    assert hw_at_save == 1
    assert pt is not None


# ---- v0.5 wire incompatibility -------------------------------------------------

def test_v05_offer_rejected_at_handshake(clock):
    alice = Identity.generate("alice", b"A" * 32)
    offer, _ = initiator_start(alice, clock=clock)
    offer["version"] = "SHC-Guard/v0.5"  # a v0.5 peer
    from shc_guard.handshake import responder_reply
    from tests.helpers import make_checker
    from shc_guard.handshake import ConsumedHandshakeIDs
    with pytest.raises(HandshakeError, match="unsupported protocol"):
        responder_reply(offer, Identity.generate("bob", b"B" * 32),
                        make_checker(), ConsumedHandshakeIDs(clock=clock),
                        clock=clock)


def test_old_generation_wire_rejected(pair):
    a, b = pair
    w = a.send_app(b"gen1")
    assert b.receive(w)["status"] == "delivered"
    # Same wire, but the receiver has moved to generation 2.
    b.generation = 2
    assert b.receive(w)["status"] == "rejected"


# ---- identity rotation (SS5) ----------------------------------------------------

def test_identity_rotation_record():
    old = Identity.generate("alice", b"A" * 32, record_version=1)
    new = Identity.generate("alice", b"A" * 32, record_version=2)
    blob = create_rotation_record(old, new)
    assert verify_rotation_record(blob, old.record(), new.record())
    # Tamper: wrong new record fails.
    other = Identity.generate("alice", b"A" * 32, record_version=2)
    assert not verify_rotation_record(blob, old.record(), other.record())


# ---- challenge table persistence -------------------------------------------------

def test_challenge_table_persists_consumed_and_superseded():
    tbl = ChallengeTable("issued", clock=lambda: 1000.0)
    n1 = tbl.issue().nonce
    n2 = tbl.issue().nonce
    assert tbl.is_superseded(n1)
    tbl.consume(n2)
    assert tbl.is_consumed(n2)
    data = tbl.serialize()
    tbl2 = ChallengeTable.restore(data, clock=lambda: 1000.0)
    assert tbl2.is_superseded(n1)
    assert tbl2.is_consumed(n2)
    assert tbl2.outstanding_nonce is None
    # A replayed consumed nonce is not the outstanding one.
    assert tbl2.consume(n2) is None


# ---- split-epoch CP verification ---------------------------------------------------

def test_split_epoch_cp_verifies_against_rx_epoch(pair):
    a, b = pair
    exchange(a, b, 2)
    # B's CP: tx_epoch 0 (its send epoch), rx_epoch 0, digest checked
    # at (rx_epoch, rx_ctr_max) -- the epoch used is rx_epoch.
    cp = Checkpoint(session_id=b.session_id, device_id=b.my_device_id,
                    generation=b.generation, cp_seq=1, tx_epoch=0,
                    tx_ctr=b.tx_ctr, rx_epoch=0, rx_ctr_max=b.rx_count,
                    rx_digest=b.rx_chain.digest,
                    guard_level=b.guard_level)
    wire = craft_message(b, 0x02,
                         pack_signed_checkpoint(
                             cp, cp.sign(b.material.own_identity)))
    assert a.receive(wire)["status"] == "checkpoint_ok"
