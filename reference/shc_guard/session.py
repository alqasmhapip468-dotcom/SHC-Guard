# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Session state machine + send/receive paths (freeze v0.6 SS2-SS9).

States: ACTIVE / SUSPECT / QUARANTINED / REKEYING / CLOSED.
Transitions (freeze SS9 / v0.5 SS9):
  SUSPECT -> ACTIVE (challenge success) | SUSPECT -> QUARANTINED
    (failure, timeout, or 3 episodes / 24h).
  REKEYING -> ACTIVE (key confirmation) | REKEYING -> CLOSED (30s timeout).
  QUARANTINED -> CLOSED only; then a NEW session with a NEW session_id.
  ACTIVE -> SUSPECT (rule 5 / gap / CP-content mismatch).
  CLOSED -> (new handshake) -> ACTIVE.

v0.6 changes vs v0.5 (see reference/README.md for the full list):
- Split epochs: tx_epoch/tx_ctr (send position) and rx_epoch/rx_ctr
  (receive position), advancing independently per direction. AAD
  carries (generation, tx_epoch, tx_ctr, ack_rx_epoch, ack_ctr,
  ack_digest); the ack refers to MY receive position.
- CP format v0.6 (generation, tx_epoch, rx_epoch, prev_cp_hash,
  anchor_head, challenge_nonce) with CP chaining and anchor-head
  extension checks; one unified CP verification path.
- TOFU + out-of-band fingerprint gate (SS5): no application messages
  until the peer fingerprint is verified, unless test-only
  allow_unverified.
- Rule 4 revised (SS6): old position, no record -> SUSPECT + challenge.
- Challenge lifecycle per direction (SS7) with persisted consumed
  records and an atomic commit of challenge success.
- hw-bound state key (SS8): send path refuses when the actual hw
  counter differs from the stored hw_at_save.
- D-19: consumed handshake IDs retained for the lifetime of the
  identity record. D-20: reorder-buffer overflow dropping the
  gap-bridging message -> SUSPECT. D-21: single-writer lock on sends.
  D-22: compromised-signer CP flagged attestation-only.
- One-session policy (SS4): SessionRegistry below; a new handshake
  for the same pair atomically closes the old session.

Receive rule order (SS2/SS6, rules 1-7, executed in this order):
  1. AEAD/AAD failure -> reject, unified response.
  2. Exact duplicate -> silent ignore, no state change.
  3. Same position, different hash -> QUARANTINED (fork / key reuse).
  4. Position older than the window with no record -> SUSPECT +
     checkpoint challenge (NOT a silent reject + anomaly counter).
  5. ack regresses below highest previous ack OR below a signed
     checkpoint -> SUSPECT.
  6. ack higher than what I actually sent -> QUARANTINED.
  7. ack_digest does not match the send log -> QUARANTINED.
Gap rule (D-1): gap > 1000 -> SUSPECT + challenge, NOT QUARANTINED.
Out-of-order buffer cap 1000; overflow drops the oldest buffered
message -- if that message is the gap-bridging one (the lowest
buffered position, needed to complete the contiguous prefix once
the gap fills), the session enters SUSPECT + challenge (D-20).
Duplicate replay: silent ignore, never parks the session in SUSPECT.
7-day no-ack-advance -> "لا يمكن التحقق" warning, no close.

Plaintext framing: type(1B) || payload:
  0x01 application, 0x02 checkpoint, 0x03 challenge (32B nonce),
  0x04 reserved (unused).

Conventions used here (documented interpretations of the freeze):
- ack_ctr is a COUNT of contiguous received messages (0 = none), and
  ack_digest is the digest after that many messages (initial digest
  when the count is 0). CP.rx_ctr_max is likewise a COUNT.
- CP.tx_ctr is the carrying message's 0-based send position.
- anchor_head in a CP is the anchor head known when the CP was
  built (the previous entry); the CP hash is registered with the
  anchor BEFORE the CP-bearing message is sent, so the next CP's
  anchor_head includes this one. This avoids a self-referential
  digest (the registered hash is over the CP as built).

Fault-injection crash hooks (send + receive paths, enumerated):
  SEND_BEFORE_SAVE, SEND_AFTER_SAVE_BEFORE_SEND,
  SEND_AFTER_SEND_BEFORE_ACK, SEND_DURING_ATOMIC_SAVE,
  RECV_AFTER_DECRYPT_BEFORE_SAVE, RECV_AFTER_SAVE_BEFORE_DELIVER,
  RECV_AFTER_DELIVER_BEFORE_ACK, CHALLENGE_COMMIT_BEFORE_WRITE.
A hook raises SimulatedCrash; state stays consistent per the freeze's
"send only after save" / "no ack before save" rules.

Reference / تجريبي only.
"""

import struct
import threading
import time
from collections import OrderedDict

from . import aead
from .aead import AAD
from .chains import (
    DIRECTION_A_TO_B, DIRECTION_B_TO_A, RETENTION,
    make_rx_chain, make_tx_chain,
)
from .checkpoint import (
    Checkpoint, CheckpointVerification, ZERO_HASH, ZERO_NONCE,
    pack_signed_checkpoint, unpack_signed_checkpoint, verify_checkpoint,
)
from .common import H, u64, u64_decode
from .handshake import HANDSHAKE_TIMEOUT_S
from .identity import TrustStore
from .outbox import Outbox
from .ratchet import DemonstrationRatchet
from .suspect import (
    DIRECTION_ISSUED, DIRECTION_RECEIVED, SuspectManager,
)
from .tlv import decode_expected, encode_fields

# ---- states ---------------------------------------------------------------
STATE_ACTIVE = "ACTIVE"
STATE_SUSPECT = "SUSPECT"
STATE_QUARANTINED = "QUARANTINED"
STATE_REKEYING = "REKEYING"
STATE_CLOSED = "CLOSED"

# ---- plaintext framing ------------------------------------------------------
PT_APP = 0x01
PT_CHECKPOINT = 0x02
PT_CHALLENGE = 0x03
PT_RESERVED = 0x04

# ---- crash points -------------------------------------------------------------
SEND_BEFORE_SAVE = "send:before_save"
SEND_AFTER_SAVE_BEFORE_SEND = "send:after_save_before_send"
SEND_AFTER_SEND_BEFORE_ACK = "send:after_send_before_ack"
SEND_DURING_ATOMIC_SAVE = "send:during_atomic_save"
RECV_AFTER_DECRYPT_BEFORE_SAVE = "recv:after_decrypt_before_save"
RECV_AFTER_SAVE_BEFORE_DELIVER = "recv:after_save_before_deliver"
RECV_AFTER_DELIVER_BEFORE_ACK = "recv:after_deliver_before_ack"
CHALLENGE_COMMIT_BEFORE_WRITE = "challenge:commit_before_write"

ALL_CRASH_POINTS = (
    SEND_BEFORE_SAVE, SEND_AFTER_SAVE_BEFORE_SEND,
    SEND_AFTER_SEND_BEFORE_ACK, SEND_DURING_ATOMIC_SAVE,
    RECV_AFTER_DECRYPT_BEFORE_SAVE, RECV_AFTER_SAVE_BEFORE_DELIVER,
    RECV_AFTER_DELIVER_BEFORE_ACK, CHALLENGE_COMMIT_BEFORE_WRITE,
)

OUT_OF_ORDER_CAP = 1000
GAP_LIMIT = 1000
NO_ACK_WARNING_S = 7 * 24 * 3600

# ---- wire header ------------------------------------------------------------
H_SESSION_ID = 0x01
H_SENDER_DEVICE_ID = 0x02
H_GENERATION = 0x03
H_TX_EPOCH = 0x04
H_TX_CTR = 0x05
H_ACK_RX_EPOCH = 0x06
H_ACK_CTR = 0x07
H_ACK_DIGEST = 0x08
H_RATCHET_EPH = 0x09


class SessionError(Exception):
    pass


class SimulatedCrash(Exception):
    """Raised by a fault-injection hook to simulate a crash."""

    def __init__(self, point: str):
        super().__init__("simulated crash at %s" % point)
        self.point = point


class CrashHooks:
    """Fault-injection registry. Enable points; maybe_crash raises."""

    def __init__(self):
        self.enabled = set()

    def enable(self, *points: str) -> None:
        for p in points:
            if p not in ALL_CRASH_POINTS:
                raise ValueError("unknown crash point: %s" % p)
            self.enabled.add(p)

    def disable(self, *points: str) -> None:
        for p in points:
            self.enabled.discard(p)

    def clear(self) -> None:
        self.enabled.clear()

    def maybe_crash(self, point: str) -> None:
        if point in self.enabled:
            raise SimulatedCrash(point)


def encode_wire(header: dict, nonce: bytes, ciphertext: bytes) -> bytes:
    h = encode_fields([
        (H_SESSION_ID, header["session_id"]),
        (H_SENDER_DEVICE_ID, header["sender_device_id"]),
        (H_GENERATION, u64(header.get("generation", 1))),
        (H_TX_EPOCH, u64(header.get("tx_epoch", header.get("epoch", 0)))),
        (H_TX_CTR, u64(header["tx_ctr"])),
        (H_ACK_RX_EPOCH, u64(header.get("ack_rx_epoch",
                                        header.get("ack_epoch", 0)))),
        (H_ACK_CTR, u64(header["ack_ctr"])),
        (H_ACK_DIGEST, header["ack_digest"]),
        (H_RATCHET_EPH, header["ratchet_eph"]),
    ])
    return struct.pack(">I", len(h)) + h + nonce + ciphertext


def decode_wire(data: bytes):
    if len(data) < 4:
        raise ValueError("wire message too short")
    (hlen,) = struct.unpack(">I", data[:4])
    if len(data) < 4 + hlen + aead.NONCE_LEN:
        raise ValueError("wire message truncated")
    f = decode_expected(data[4:4 + hlen], [
        H_SESSION_ID, H_SENDER_DEVICE_ID, H_GENERATION, H_TX_EPOCH,
        H_TX_CTR, H_ACK_RX_EPOCH, H_ACK_CTR, H_ACK_DIGEST, H_RATCHET_EPH])
    header = {
        "session_id": f[H_SESSION_ID],
        "sender_device_id": f[H_SENDER_DEVICE_ID],
        "generation": u64_decode(f[H_GENERATION]),
        "tx_epoch": u64_decode(f[H_TX_EPOCH]),
        "epoch": u64_decode(f[H_TX_EPOCH]),  # alias (v0.5 name)
        "tx_ctr": u64_decode(f[H_TX_CTR]),
        "ack_rx_epoch": u64_decode(f[H_ACK_RX_EPOCH]),
        "ack_epoch": u64_decode(f[H_ACK_RX_EPOCH]),  # alias
        "ack_ctr": u64_decode(f[H_ACK_CTR]),
        "ack_digest": f[H_ACK_DIGEST],
        "ratchet_eph": f[H_RATCHET_EPH],
    }
    nonce = data[4 + hlen:4 + hlen + aead.NONCE_LEN]
    ciphertext = data[4 + hlen + aead.NONCE_LEN:]
    return header, nonce, ciphertext


class Session:
    """One SHC-Guard session (one direction pair, one peer)."""

    def __init__(self, material, consumed_ids=None, journal=None,
                 hw_counter=None, notify=None, clock=time.time,
                 anchor=None, state_master_key=None,
                 allow_unverified: bool = False):
        self.material = material
        self.session_id = material.session_id
        self.state = STATE_ACTIVE
        self.generation = getattr(material, "generation", 1)
        self.tx_epoch = 0
        self.rx_epoch = 0
        self.tx_ctr = 0
        self.is_initiator = material.is_initiator
        self.my_device_id = material.own_identity.device_id
        self.peer_device_id = material.peer_record.device_id
        self.peer_record = material.peer_record
        self.guard_level = material.guard_level
        self.clock = clock
        self.notify = notify or (lambda event, detail: None)
        self.notifications = []
        self.consumed_ids = consumed_ids
        self.journal = journal
        self.hw_counter = hw_counter
        self.anchor = anchor  # LocalAnchor (stand-in) or None
        self.state_master_key = state_master_key
        self.allow_unverified = allow_unverified
        self._saved_once = False
        self._stored_hw = None  # hw counter value at last save (SS8)

        # TOFU (SS5): peer starts TRUSTED-UNVERIFIED.
        self.trust = TrustStore()
        self.trust.trust_unverified(self.peer_record.fingerprint())
        self.peer_verified = False

        # Anchor / attestation state.
        self.anchor_warning = None
        if self.anchor is None:
            self.anchor_warning = (
                "no external anchor configured -- simultaneous rollback "
                "of both parties is UNDETECTED (residual P0-1)")
        self.degraded_mode = False
        self.attestation_only = False
        self.attestation_only_reason = None

        my_dir = DIRECTION_A_TO_B if self.is_initiator else DIRECTION_B_TO_A
        peer_dir = DIRECTION_B_TO_A if self.is_initiator else DIRECTION_A_TO_B
        self.rx_chain = make_rx_chain(self.session_id, self.peer_device_id,
                                      peer_dir)
        self.tx_chain = make_tx_chain(self.session_id, self.my_device_id,
                                      my_dir)
        self.ratchet = DemonstrationRatchet(
            material.root_key, self.is_initiator,
            material.own_eph_private, material.peer_eph_pub)

        # Receive state.
        self.expected_rx_ctr = 0  # next contiguous ctr expected
        self.rx_count = 0  # contiguous received count (== expected_rx_ctr)
        self._recv_positions = OrderedDict()  # (rx_epoch,ctr)->(key, ct_hash)
        self._buffer = OrderedDict()  # (rx_epoch,ctr)->(header,nonce,ct)
        self.anomaly_count = 0
        self.delivered = []  # app plaintexts delivered (tests/demo)
        self._pending_delivery = None  # (framed, header)

        # Ack state (peer's ack of me).
        self.acked_by_peer = (0, 0)  # (tx_epoch of peer, count)
        self._my_last_cp_pos = None  # (tx_epoch, tx_ctr) of last CP I sent
        self.last_ack_advance_at = self.clock()
        self.ack_stale_warning = False

        # Checkpoints.
        self._own_cp_seq = 0
        self.last_peer_cp = None
        self._last_own_cp_hash = ZERO_HASH
        self._peer_anchor_head = ZERO_HASH
        self._last_cp_sent_at = self.clock()
        self._msgs_since_cp = 0

        # SUSPECT / challenge.
        self.suspect = SuspectManager(clock=clock)
        self._peer_challenge_nonce = None  # incoming challenge to answer
        self.pending_challenge_wire = None

        # Outbox + crash hooks + single-writer lock (D-21).
        self.outbox = Outbox(notify=self._outbox_notify, clock=clock)
        self.crash_hooks = CrashHooks()
        self._send_lock = threading.Lock()

        # Rekeying.
        self._rekey_started_at = None

    # -- compat ---------------------------------------------------------------

    @property
    def epoch(self) -> int:
        """v0.5 name: the send epoch (tx_epoch)."""
        return self.tx_epoch

    # -- notifications ---------------------------------------------------------

    def _notify(self, event, detail=None):
        self.notifications.append((event, detail))
        self.notify(event, detail)

    def _outbox_notify(self, event, entry):
        self._notify("outbox_" + event, entry.position)

    # -- TOFU (SS5) ------------------------------------------------------------

    def verify_peer_fingerprint(self, expected_hex: str) -> bool:
        """Verify the peer fingerprint out-of-band.

        ``expected_hex`` is the fingerprint the user compared in person
        or on a second channel. Returns True and marks the peer
        VERIFIED on a match; False otherwise (peer stays
        TRUSTED-UNVERIFIED and application messages stay blocked).
        """
        ok = self.trust.verify_fingerprint(
            self.peer_record.fingerprint(), expected_hex)
        if ok:
            self.peer_verified = True
            self._notify("peer_verified", self.peer_record.fingerprint().hex()[:16])
        return ok

    def mark_peer_verified(self) -> None:
        """Test/demo helper: mark the peer verified (the caller must
        have compared the fingerprint out-of-band first)."""
        self.trust.verify_fingerprint(
            self.peer_record.fingerprint(),
            self.peer_record.fingerprint().hex())
        self.peer_verified = True

    # -- D-22: attestation-only flag --------------------------------------------

    def flag_attestation_only(self, reason: str) -> None:
        """Flag that the peer's signer is reported compromised.

        A false but well-signed CP from a compromised signer is NOT
        rejected as "invalid device": the session is flagged
        "attestation-only, not device-integrity" and the app is told
        the check proves consistency with available evidence only.
        No false claim of device integrity is made.
        """
        self.attestation_only = True
        self.attestation_only_reason = reason
        self._notify("attestation_only",
                     "attestation-only, not device-integrity: %s" % reason)

    # -- persistence -------------------------------------------------------------

    def _state_snapshot(self) -> bytes:
        import json

        return json.dumps({
            "session_id": self.session_id.hex(),
            "generation": self.generation,
            "tx_epoch": self.tx_epoch, "rx_epoch": self.rx_epoch,
            "tx_ctr": self.tx_ctr,
            "rx_count": self.rx_count,
            "rx_digest": self.rx_chain.digest.hex(),
            "tx_digest": self.tx_chain.digest.hex(),
            "state": self.state,
            "suspect": self.suspect.serialize(),
            "peer_anchor_head": self._peer_anchor_head.hex(),
            "last_peer_cp_hash": (
                self.last_peer_cp.digest().hex()
                if self.last_peer_cp else None),
        }, sort_keys=True).encode()

    def save(self) -> None:
        """Persist the session (journal if configured) and, on the FIRST
        save, record the handshake_id as consumed (freeze SS2: only after
        the session is saved). With a hw counter, the hw value is
        reserved (increment) before the write and stored as
        ``_stored_hw``; with a state master key the record is sealed
        with the hw-bound state key (SS8)."""
        if self.journal is not None and self.hw_counter is not None:
            hw = self.hw_counter.increment()  # reserve-then-commit
            from .journal import JournalRecord, seal_state_record

            payload = self._state_snapshot()
            if self.state_master_key is not None:
                payload = seal_state_record(self.state_master_key, hw,
                                            payload)
            self.journal.append_with_meta(JournalRecord(
                seq=self.tx_ctr + self.rx_count + 1, hw_ctr=hw,
                payload=payload))
            self._stored_hw = hw
        if not self._saved_once and self.consumed_ids is not None:
            self.consumed_ids.record(self.material.handshake_id)
            self._saved_once = True

    def verify_saved_state(self):
        """Boot check for a journaled session: load the best record,
        unseal it (if a master key is set) and classify the hw case.
        Returns (case, hw_at_save, plaintext-or-None)."""
        if self.journal is None or self.hw_counter is None:
            return None, None, None
        from .journal import unseal_state_record

        case, record = self.journal.boot(self.hw_counter)
        if record is None:
            return case, None, None
        if self.state_master_key is not None:
            hw_at_save, plaintext = unseal_state_record(
                self.state_master_key, record.payload)
            return case, hw_at_save, plaintext
        return case, record.hw_ctr, record.payload

    def erase_keys(self) -> None:
        """Best-effort key erasure (SS4 atomic replacement): overwrite
        the session key material in place. Python bytes are immutable,
        so this replaces the references with zeros and drops the
        ratchet chains -- it is best-effort, stated as such."""
        try:
            self.material.root_key = bytes(32)
            self.material.shared_secret = bytes(
                len(getattr(self.material, "shared_secret", b"") or b""))
        except Exception:
            pass
        try:
            self.ratchet.root_key = bytes(32)
            self.ratchet.send_chain_key = bytes(32)
            self.ratchet.recv_chain_key = bytes(32)
        except Exception:
            pass

    # -- acks ------------------------------------------------------------------

    def _my_ack(self):
        """My ack of the peer: (rx_epoch, count, digest of contiguous prefix)."""
        return self.rx_epoch, self.rx_count, self.rx_chain.digest

    def _tx_digest_after(self, epoch: int, count: int):
        """My tx_digest after ``count`` sent messages in ``epoch``."""
        if count <= 0:
            return self.tx_chain.initial_digest
        return self.tx_chain.digest_at(epoch, count - 1)

    def check_ack_staleness(self) -> None:
        """7-day no-ack-advance -> 'لا يمكن التحقق' warning, no close."""
        if self.state != STATE_ACTIVE:
            return
        if len(self.outbox) == 0 or self.ack_stale_warning:
            return
        if self.clock() - self.last_ack_advance_at > NO_ACK_WARNING_S:
            self.ack_stale_warning = True
            self._notify("ack_stale",
                         "لا يمكن التحقق — لم يتقدم إقرار الطرف الآخر "
                         "منذ 7 أيام")

    # -- state transitions ---------------------------------------------------------

    def _enter_suspect(self, reason: str) -> None:
        if self.state == STATE_QUARANTINED:
            return
        hit_limit = self.suspect.enter_suspect(reason)
        if hit_limit:
            self.state = STATE_QUARANTINED
            self._notify("quarantined", "3 SUSPECT episodes in 24h")
            return
        self.state = STATE_SUSPECT
        self._notify("suspect", reason)
        nonce = self.suspect.issue_challenge(DIRECTION_ISSUED)
        self.pending_challenge_wire = self._send_control(
            PT_CHALLENGE, nonce, allow_in_suspect=True)

    def _enter_quarantined(self, reason: str) -> None:
        self.suspect.resolve_failure()
        self.state = STATE_QUARANTINED
        self._notify("quarantined", reason)

    def close(self) -> None:
        # Fail-notify the app for any unacked outbox entries (SS4).
        try:
            self.outbox.fail_all()
        except Exception:
            pass
        self.state = STATE_CLOSED
        self._notify("closed", None)

    # -- sending -------------------------------------------------------------------

    def send_app(self, data: bytes) -> bytes:
        """Send an application message (type 0x01).

        SS5: refused until the peer fingerprint is verified
        out-of-band, unless the explicit test-only allow_unverified
        flag was passed at construction.
        """
        if not self.peer_verified and not self.allow_unverified:
            raise SessionError(
                "peer identity unverified (TOFU) -- verify the fingerprint "
                "out-of-band before sending application messages")
        if self.state == STATE_SUSPECT:
            raise SessionError("no application sending during SUSPECT")
        return self._send_plaintext(PT_APP, data)

    def send_checkpoint(self, challenge_nonce: bytes = ZERO_NONCE) -> bytes:
        """Send a checkpoint control message (type 0x02).

        The CP hash is registered with the anchor BEFORE the
        CP-bearing message is sent (SS3). anchor_head is the head
        known when the CP was built (see module docstring).
        """
        self._own_cp_seq += 1
        anchor_head = self.anchor.head if self.anchor is not None else ZERO_HASH
        cp = Checkpoint(
            session_id=self.session_id, device_id=self.my_device_id,
            generation=self.generation,
            cp_seq=self._own_cp_seq, tx_epoch=self.tx_epoch,
            tx_ctr=self.tx_ctr, rx_epoch=self.rx_epoch,
            rx_ctr_max=self.rx_count,
            rx_digest=self.rx_chain.digest,
            guard_level=self.guard_level,
            prev_cp_hash=self._last_own_cp_hash,
            anchor_head=anchor_head,
            challenge_nonce=challenge_nonce)
        if self.anchor is not None:
            self.anchor.register(cp.digest())
        payload = pack_signed_checkpoint(cp, cp.sign(self.material.own_identity))
        wire = self._send_plaintext(PT_CHECKPOINT, payload)
        self._last_own_cp_hash = cp.digest()
        self._my_last_cp_pos = (self.tx_epoch, self.tx_ctr - 1)
        self._last_cp_sent_at = self.clock()
        self._msgs_since_cp = 0
        return wire

    def checkpoint_due(self) -> bool:
        """CP cadence: every 50 messages OR 24h (mandatory upper bound)."""
        if self._msgs_since_cp >= 50:
            return True
        return (self.clock() - self._last_cp_sent_at) >= 24 * 3600

    def respond_to_challenge(self):
        """Answer an incoming SUSPECT challenge with a CP carrying the
        challenger's nonce. Returns the wire bytes, or None."""
        if self._peer_challenge_nonce is None:
            return None
        nonce = self._peer_challenge_nonce
        self._peer_challenge_nonce = None
        wire = self.send_checkpoint(challenge_nonce=nonce)
        self.suspect.tables[DIRECTION_RECEIVED].consume(nonce)
        return wire

    def _send_control(self, ptype: int, payload: bytes,
                      allow_in_suspect: bool = False) -> bytes:
        if self.state == STATE_SUSPECT and not allow_in_suspect:
            raise SessionError("no sending during SUSPECT except challenge")
        return self._send_plaintext(ptype, payload)

    def _check_hw_before_send(self) -> None:
        """SS8 send path: before deriving any message key, verify the
        actual hw counter equals the stored hw_at_save. Mismatch ->
        refuse to send + QUARANTINED."""
        if self.hw_counter is None or self._stored_hw is None:
            return
        if self.hw_counter.read() != self._stored_hw:
            self._enter_quarantined(
                "hw counter mismatch (actual %d != stored %d) -- "
                "refuse to send" % (self.hw_counter.read(), self._stored_hw))
            raise SessionError(
                "hw counter mismatch -- refuse to send (QUARANTINED)")

    def _send_plaintext(self, ptype: int, payload: bytes) -> bytes:
        if self.state in (STATE_QUARANTINED, STATE_CLOSED):
            raise SessionError("session is %s" % self.state)
        if self.state == STATE_REKEYING:
            raise SessionError("session is REKEYING")
        self._check_hw_before_send()
        # D-21: single-writer lock; a second concurrent send with the
        # same counter is refused, never executed.
        if not self._send_lock.acquire(blocking=False):
            raise SessionError("concurrent send refused (single-writer lock)")
        try:
            return self._send_plaintext_locked(ptype, payload)
        finally:
            self._send_lock.release()

    def _send_plaintext_locked(self, ptype: int, payload: bytes) -> bytes:
        self.check_ack_staleness()
        snap = self.ratchet.snapshot()
        committed = False
        try:
            self.crash_hooks.maybe_crash(SEND_BEFORE_SAVE)
            framed = bytes([ptype]) + payload
            position = (self.tx_epoch, self.tx_ctr)
            self.ratchet.rotate_for_send()
            msg_key = self.ratchet.peek_send_key()
            header_pub = self.ratchet.dh_public
            nonce = aead.fresh_nonce()
            ack_rx_epoch, ack_ctr, ack_digest = self._my_ack()
            aad = AAD(self.session_id, self.my_device_id, self.generation,
                      self.tx_epoch, self.tx_ctr, ack_rx_epoch, ack_ctr,
                      ack_digest)
            ciphertext = aead.encrypt(msg_key, nonce, framed, aad)
            header = {
                "session_id": self.session_id,
                "sender_device_id": self.my_device_id,
                "generation": self.generation,
                "tx_epoch": self.tx_epoch, "tx_ctr": self.tx_ctr,
                "ack_rx_epoch": ack_rx_epoch, "ack_ctr": ack_ctr,
                "ack_digest": ack_digest, "ratchet_eph": header_pub,
            }
            wire = encode_wire(header, nonce, ciphertext)
            self.crash_hooks.maybe_crash(SEND_DURING_ATOMIC_SAVE)
            # ---- commit point: state changes only after this line ----
            self.ratchet.advance_send_chain()
            self.tx_chain.advance(self.tx_epoch, self.tx_ctr, ciphertext)
            from .outbox import OutboxEntry

            self.outbox.enqueue(OutboxEntry(
                position=position, ciphertext=ciphertext, nonce=nonce,
                aad_bytes=aad.canonical(), header_bytes=wire))
            self.tx_ctr += 1
            self._msgs_since_cp += 1
            committed = True
            self.crash_hooks.maybe_crash(SEND_AFTER_SAVE_BEFORE_SEND)
            self.crash_hooks.maybe_crash(SEND_AFTER_SEND_BEFORE_ACK)
            return wire
        except SimulatedCrash:
            if not committed:
                self.ratchet.restore(snap)
            raise

    # -- receiving -----------------------------------------------------------------

    def receive(self, data: bytes) -> dict:
        """Process one incoming wire message. Returns a result dict."""
        try:
            header, nonce, ciphertext = decode_wire(data)
        except ValueError as exc:
            return {"status": "rejected", "reason": "malformed: %s" % exc}
        if header["session_id"] != self.session_id:
            return {"status": "rejected", "reason": "session_id mismatch"}
        if header.get("generation", 1) != self.generation:
            return {"status": "rejected",
                    "reason": "generation mismatch (stale generation %s)"
                    % header.get("generation")}
        if self.state in (STATE_QUARANTINED, STATE_CLOSED):
            return {"status": "rejected", "reason": "session is %s" % self.state}
        if header["tx_epoch"] != self.rx_epoch:
            return {"status": "rejected", "reason": "rx_epoch mismatch"}
        ctr = header["tx_ctr"]
        if ctr < self.expected_rx_ctr:
            return self._handle_replay(header, nonce, ciphertext)
        if ctr > self.expected_rx_ctr:
            gap = ctr - self.expected_rx_ctr
            if gap > GAP_LIMIT:
                # D-1: SUSPECT + challenge, NOT QUARANTINED.
                self._notify("gap_rejected", gap)
                if self.state == STATE_ACTIVE:
                    self._enter_suspect("gap>%d" % GAP_LIMIT)
                if self.state == STATE_QUARANTINED:
                    return {"status": "quarantined",
                            "reason": "gap>%d + 3 episodes" % GAP_LIMIT}
                return {"status": "suspect", "reason": "gap>%d" % GAP_LIMIT}
            self._buffer[(self.rx_epoch, ctr)] = (header, nonce, ciphertext)
            if len(self._buffer) > OUT_OF_ORDER_CAP:
                oldest = next(iter(self._buffer))
                del self._buffer[oldest]
                self.anomaly_count += 1
                self._notify("buffer_overflow", oldest)
                # D-20: the dropped message is the lowest buffered
                # position -- the one that would complete the
                # contiguous prefix once the gap fills. Losing it
                # stalls detection silently in v0.5; in v0.6 the
                # session enters SUSPECT + challenge instead.
                if oldest[1] == self.expected_rx_ctr + 1:
                    if self.state == STATE_ACTIVE:
                        self._enter_suspect(
                            "buffer overflow dropped gap-bridging message %s"
                            % (oldest,))
                    if self.state == STATE_QUARANTINED:
                        return {"status": "quarantined",
                                "reason": "buffer overflow + 3 episodes"}
                    return {"status": "suspect",
                            "reason": "buffer overflow dropped gap-bridging"}
            return {"status": "buffered", "position": (self.rx_epoch, ctr)}
        result = self._process_in_order(header, nonce, ciphertext)
        # Drain the contiguous buffer.
        while result.get("status") in ("delivered", "checkpoint_ok",
                                       "challenge_received", "ignored"):
            nxt = (self.rx_epoch, self.expected_rx_ctr)
            if nxt not in self._buffer:
                break
            h2, n2, c2 = self._buffer.pop(nxt)
            result = self._process_in_order(h2, n2, c2)
        return result

    def _handle_replay(self, header, nonce, ciphertext) -> dict:
        """Rules 1-4 for positions below the contiguous prefix."""
        pos = (header["tx_epoch"], header["tx_ctr"])
        stored = self._recv_positions.get(pos)
        if stored is None:
            # Rule 4 REVISED (SS6): old position with no retained
            # record -> SUSPECT + checkpoint challenge (NOT a silent
            # reject + anomaly counter). Detection outside the window
            # is NOT guaranteed -- the challenge is the mechanism.
            self.anomaly_count += 1
            self._notify("old_position_no_record", pos)
            if self.state == STATE_ACTIVE:
                self._enter_suspect("rule4 old position %s" % (pos,))
            if self.state == STATE_QUARANTINED:
                return {"status": "quarantined",
                        "reason": "rule4 + 3 episodes"}
            return {"status": "suspect",
                    "reason": "rule4 old position, no record -- challenge"}
        key, ct_hash = stored
        aad = AAD(self.session_id, header["sender_device_id"],
                  header.get("generation", 1),
                  header["tx_epoch"], header["tx_ctr"], header["ack_rx_epoch"],
                  header["ack_ctr"], header["ack_digest"])
        try:
            aead.decrypt(key, nonce, ciphertext, aad)
        except Exception:
            # Rule 1: AEAD/AAD failure -> reject, unified response.
            return {"status": "rejected", "reason": "rule1 aead failure"}
        if H(ciphertext) == ct_hash:
            # Rule 2: exact duplicate -> silent ignore, no state change.
            # EXCEPTION (SS7 crash recovery): if the session is in
            # SUSPECT and the duplicated message carries a checkpoint,
            # the first delivery may have crashed between the message
            # commit and the challenge commit (AT-06). Re-run the CP
            # handler on the retransmission so the challenge can still
            # complete -- otherwise the session would be stranded in
            # SUSPECT with a consumed-looking position.
            if self.state == STATE_SUSPECT:
                try:
                    framed = aead.decrypt(key, nonce, ciphertext, aad)
                except Exception:
                    return {"status": "ignored",
                            "reason": "rule2 duplicate"}
                if framed and framed[0] == PT_CHECKPOINT:
                    return self._handle_checkpoint(framed[1:], header)
            return {"status": "ignored", "reason": "rule2 duplicate"}
        # Rule 3: same position, different ciphertext -> QUARANTINED.
        self._enter_quarantined("rule3 fork at %s" % (pos,))
        return {"status": "quarantined", "reason": "rule3 fork"}

    def _process_in_order(self, header, nonce, ciphertext) -> dict:
        """Decrypt + rules 1, 5-7 + commit + deliver for the next position."""
        pos = (header["tx_epoch"], header["tx_ctr"])
        self.ratchet.prepare_recv(header["ratchet_eph"])
        key = self.ratchet.peek_recv_key()
        aad = AAD(self.session_id, header["sender_device_id"],
                  header.get("generation", 1),
                  header["tx_epoch"], header["tx_ctr"], header["ack_rx_epoch"],
                  header["ack_ctr"], header["ack_digest"])
        try:
            framed = aead.decrypt(key, nonce, ciphertext, aad)
        except Exception:
            return {"status": "rejected", "reason": "rule1 aead failure"}
        try:
            self.crash_hooks.maybe_crash(RECV_AFTER_DECRYPT_BEFORE_SAVE)
        except SimulatedCrash:
            raise
        # Rules 5-7 on the authenticated ack.
        ack_pos = (header["ack_rx_epoch"], header["ack_ctr"])
        outcome = self._check_ack_rules(header, ack_pos)
        if outcome is not None:
            return outcome
        # ---- commit point ----
        self.ratchet.advance_recv_chain()
        self.rx_chain.advance(header["tx_epoch"], header["tx_ctr"], ciphertext)
        self._recv_positions[pos] = (key, H(ciphertext))
        while len(self._recv_positions) > RETENTION:
            self._recv_positions.popitem(last=False)
        self.expected_rx_ctr += 1
        self.rx_count += 1
        self._apply_peer_ack(header)
        self._pending_delivery = (framed, header)
        try:
            self.crash_hooks.maybe_crash(RECV_AFTER_SAVE_BEFORE_DELIVER)
        except SimulatedCrash:
            raise
        return self._deliver_pending()

    def _check_ack_rules(self, header, ack_pos) -> dict:
        """Rules 5-7. Returns a result dict on violation, else None."""
        ack_rx_epoch, ack_count = ack_pos
        # Rule 5: ack regresses below the highest previous ack...
        if ack_pos < self.acked_by_peer:
            if self.state == STATE_ACTIVE:
                self._enter_suspect("rule5 ack regression")
            if self.state == STATE_QUARANTINED:
                return {"status": "quarantined",
                        "reason": "rule5 + 3 episodes"}
            return {"status": "suspect", "reason": "rule5 ack regression"}
        # ...or below a signed checkpoint OF THE PEER: the peer's own
        # last CP attested rx_ctr_max in ITS rx_epoch; a later ack
        # claiming less regresses.
        if self.last_peer_cp is not None:
            cp = self.last_peer_cp
            if (ack_rx_epoch, ack_count) < (cp.rx_epoch, cp.rx_ctr_max):
                if self.state == STATE_ACTIVE:
                    self._enter_suspect("rule5 ack below peer checkpoint")
                if self.state == STATE_QUARANTINED:
                    return {"status": "quarantined",
                            "reason": "rule5 + 3 episodes"}
                return {"status": "suspect",
                        "reason": "rule5 ack below checkpoint"}
        # Rules 6-7 apply to acks for my current tx epoch only; an ack
        # for a superseded epoch cannot be checked against the
        # (replaced) send log, so it is not punished here (rule 5
        # already covers regression across epochs via the tuple
        # comparison above). The ack's rx_epoch equals the peer's
        # receive epoch, which is MY tx epoch for that stream.
        if ack_rx_epoch != self.tx_epoch:
            return None
        # Rule 6: ack higher than what I actually sent.
        if ack_count > self.tx_ctr:
            self._enter_quarantined("rule6 ack beyond sent")
            return {"status": "quarantined", "reason": "rule6 ack beyond sent"}
        # Rule 7: ack_digest does not match the send log.
        expected = self._tx_digest_after(ack_rx_epoch, ack_count)
        if expected is None or expected != header["ack_digest"]:
            self._enter_quarantined("rule7 ack_digest mismatch")
            return {"status": "quarantined", "reason": "rule7 ack_digest"}
        return None

    def _apply_peer_ack(self, header) -> None:
        ack_pos = (header["ack_rx_epoch"], header["ack_ctr"])
        if ack_pos > self.acked_by_peer:
            self.acked_by_peer = ack_pos
            self.last_ack_advance_at = self.clock()
            self.outbox.acked_through(header["ack_rx_epoch"],
                                      header["ack_ctr"] - 1)

    def _deliver_pending(self) -> dict:
        """Deliver the committed pending message to the app / handlers."""
        if self._pending_delivery is None:
            return {"status": "ignored", "reason": "nothing pending"}
        framed, header = self._pending_delivery
        self._pending_delivery = None
        ptype, payload = framed[0], framed[1:]
        if ptype == PT_APP:
            self.delivered.append(payload)
            result = {"status": "delivered", "payload": payload}
        elif ptype == PT_CHECKPOINT:
            result = self._handle_checkpoint(payload, header)
        elif ptype == PT_CHALLENGE:
            if len(payload) != 32:
                return {"status": "rejected",
                        "reason": "challenge nonce length"}
            self._peer_challenge_nonce = payload
            # Record the incoming challenge in the RECEIVED direction
            # table (independent of challenges I issued).
            self.suspect.tables[DIRECTION_RECEIVED].record_received(payload)
            self._notify("challenge_received", payload.hex()[:16])
            result = {"status": "challenge_received"}
        else:
            return {"status": "rejected", "reason": "unknown frame type"}
        try:
            self.crash_hooks.maybe_crash(RECV_AFTER_DELIVER_BEFORE_ACK)
        except SimulatedCrash:
            raise
        if self.state == STATE_SUSPECT:
            self.suspect.note_valid_message()
            if self.suspect.deadline_exceeded():
                self._enter_quarantined("suspect deadline exceeded")
                return {"status": "quarantined",
                        "reason": "suspect deadline"}
        return result

    def deliver_pending(self) -> dict:
        """Recovery entry point after a crash at AFTER_SAVE_BEFORE_DELIVER."""
        return self._deliver_pending()

    def _handle_checkpoint(self, payload: bytes, header) -> dict:
        try:
            cp, signed_blob = unpack_signed_checkpoint(payload)
        except ValueError as exc:
            return {"status": "rejected", "reason": "bad CP: %s" % exc}
        # Anchor-absent warning (SS3 residual P0-1): without an anchor,
        # a well-signed CP proves consistency only, and simultaneous
        # rollback is undetected. Surface it; never hide it.
        if self.anchor is None:
            self._notify("anchor_absent",
                         "no external anchor -- simultaneous rollback "
                         "undetected (residual P0-1)")
        elif self.anchor is not None:
            try:
                self.anchor.refresh()
            except Exception as exc:
                return {"status": "rejected",
                        "reason": "anchor log refused: %s" % exc}
        last_seq = self.last_peer_cp.cp_seq if self.last_peer_cp else -1
        expected_prev = (self.last_peer_cp.digest()
                         if self.last_peer_cp else ZERO_HASH)
        # Unified CP verification path (SS9): the same function serves
        # the SS6.3 path and the SS7.2 challenge path -- no bypass.
        verdict = verify_checkpoint(
            cp, signed_blob, self.peer_record, self.session_id,
            self.peer_device_id, self.guard_level, last_seq,
            header["tx_epoch"], header["tx_ctr"],
            lambda e, c: self._tx_digest_after(e, c),
            outstanding_nonce=self.suspect.outstanding_nonce,
            generation=self.generation,
            expected_prev_cp_hash=expected_prev,
            stored_anchor_head=self._peer_anchor_head,
            anchor=self.anchor)
        if verdict.status in (
                CheckpointVerification.DIGEST_OUTSIDE_WINDOW,
                CheckpointVerification.DIGEST_MISMATCH,
                CheckpointVerification.PREV_CP_HASH_MISMATCH,
                CheckpointVerification.ANCHOR_NOT_EXTENDING):
            if self.state == STATE_ACTIVE:
                self._enter_suspect("cp %s" % verdict.status)
            return {"status": "suspect",
                    "reason": "cp %s" % verdict.status}
        if not verdict.ok:
            return {"status": "rejected",
                    "reason": "cp " + verdict.status}
        # CP verified.
        if self.state == STATE_SUSPECT:
            # No late acceptance (SS7): a response after the deadline
            # is rejected and the session stays QUARANTINED.
            if self.suspect.deadline_exceeded():
                self.suspect.expire_challenge(DIRECTION_ISSUED)
                self._enter_quarantined("challenge response arrived late")
                return {"status": "quarantined",
                        "reason": "challenge response late"}
            prev_peer_cp = self.last_peer_cp
            ok, why = self.suspect.check_response(cp, True, prev_peer_cp)
            if not ok:
                self._enter_quarantined("challenge failed: %s" % why)
                return {"status": "quarantined",
                        "reason": "challenge failed: %s" % why}
            # ATOMIC COMMIT (SS7): crash hook first -- a crash here
            # leaves SUSPECT with the nonce NOT consumed. The commit
            # itself (nonce consumption + CP storage + ACTIVE) is one
            # journal write when a journal is configured; without a
            # journal it is one in-memory step, in the same order.
            # (Anchor registration is the signer's pre-send step, SS3.)
            try:
                self.crash_hooks.maybe_crash(CHALLENGE_COMMIT_BEFORE_WRITE)
            except SimulatedCrash:
                raise
            self.suspect.consume_challenge(cp.challenge_nonce,
                                           DIRECTION_ISSUED)
            self.last_peer_cp = cp
            self._peer_anchor_head = cp.anchor_head
            # Anchor registration was already done by the SIGNER
            # before sending (SS3); the receiver does NOT re-register
            # the same hash (that would append a duplicate entry).
            if self.journal is not None:
                self.save()
            self.suspect.state.active = False
            self.suspect.state.nonce = b""
            self.suspect.state.messages_seen = 0
            self.state = STATE_ACTIVE
            self._notify("suspect_resolved", why)
            return {"status": "checkpoint_ok",
                    "reason": "challenge satisfied"}
        # ACTIVE path: store the CP. Degraded mode (AT-11): accepting a
        # CP with no prior CP history from this peer is attestation
        # only -- surface it, do not claim detection.
        if self.last_peer_cp is None and cp.cp_seq > 1:
            self.degraded_mode = True
            self._notify("degraded_mode",
                         "CP accepted without prior CP history -- "
                         "attestation only, no false detection claim")
        self.last_peer_cp = cp
        self._peer_anchor_head = cp.anchor_head
        return {"status": "checkpoint_ok"}

    # -- rekeying ---------------------------------------------------------------

    def start_rekey(self) -> None:
        if self.state != STATE_ACTIVE:
            raise SessionError("rekey requires ACTIVE")
        self.state = STATE_REKEYING
        self._rekey_started_at = self.clock()

    def complete_rekey(self, material) -> None:
        """Finish rekeying with fresh handshake material (key confirmation
        already verified by the caller). A rekey is session-wide: both
        direction epochs advance together (it is not a per-direction
        DH ratchet step, which advances only one direction's epoch).
        """
        if self.state != STATE_REKEYING:
            raise SessionError("not in REKEYING")
        if self.clock() - self._rekey_started_at > HANDSHAKE_TIMEOUT_S:
            self.state = STATE_CLOSED
            raise SessionError("rekey timeout (30s) -> CLOSED")
        self.material = material
        self.session_id = material.session_id
        self.tx_epoch += 1
        self.rx_epoch += 1
        self.tx_ctr = 0
        self.expected_rx_ctr = 0
        self.rx_count = 0
        self._recv_positions.clear()
        self._buffer.clear()
        my_dir = DIRECTION_A_TO_B if self.is_initiator else DIRECTION_B_TO_A
        peer_dir = DIRECTION_B_TO_A if self.is_initiator else DIRECTION_A_TO_B
        self.rx_chain = make_rx_chain(self.session_id, self.peer_device_id,
                                      peer_dir)
        self.tx_chain = make_tx_chain(self.session_id, self.my_device_id,
                                      my_dir)
        self.ratchet = DemonstrationRatchet(
            material.root_key, self.is_initiator,
            material.own_eph_private, material.peer_eph_pub)
        self.state = STATE_ACTIVE
        self._notify("rekeyed", self.tx_epoch)

    def check_rekey_timeout(self) -> None:
        if (self.state == STATE_REKEYING and self._rekey_started_at
                and self.clock() - self._rekey_started_at
                > HANDSHAKE_TIMEOUT_S):
            self.state = STATE_CLOSED
            self._notify("closed", "rekey timeout")


# ---- one-session policy (SS4) -------------------------------------------------

class SessionRegistry:
    """ONE active session per (user_id pair, device_id pair).

    Generation (u64) increments with every new session for the same
    pair. Registering a new session ATOMICALLY closes the old one:
    the same call that records the new session marks the old session
    CLOSED, fail-notifies the app for the old outbox entries, and
    erases the old session's keys (best-effort). There is no moment
    when two sessions for the same pair are both ACTIVE.
    """

    def __init__(self):
        self._sessions = {}  # pair key -> (generation, Session)
        self._lock = threading.Lock()

    @staticmethod
    def pair_key(session: Session):
        own = (session.material.own_identity.user_id,
               session.my_device_id)
        peer = (session.peer_record.user_id, session.peer_device_id)
        return tuple(sorted([own, peer]))

    def next_generation(self, session: Session) -> int:
        key = self.pair_key(session)
        entry = self._sessions.get(key)
        return (entry[0] + 1) if entry else 1

    def register(self, session: Session) -> int:
        """Register ``session`` as the active session for its pair.

        Returns the generation assigned. If an ACTIVE session already
        exists for the pair, it is closed atomically first (CLOSED +
        outbox fail-notify + key erasure, in this call).
        """
        key = self.pair_key(session)
        with self._lock:
            entry = self._sessions.get(key)
            if entry is not None:
                old_gen, old = entry
                if old is not session and old.state == STATE_ACTIVE:
                    old.close()
                    old.erase_keys()
                    old._notify("replaced_by_generation", old_gen + 1)
                generation = old_gen + 1
            else:
                generation = 1
            session.generation = generation
            self._sessions[key] = (generation, session)
            return generation

    def active(self, session: Session):
        entry = self._sessions.get(self.pair_key(session))
        return entry[1] if entry else None
