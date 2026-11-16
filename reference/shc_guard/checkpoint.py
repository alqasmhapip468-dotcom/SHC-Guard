# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Signed checkpoints (freeze v0.6 SS2/SS3/SS7).

CP canonical fields, in order:
  label, session_id (32B), device_id (32B), generation (u64),
  cp_seq (u64, strictly increasing per sender), tx_epoch (u64),
  tx_ctr (u64), rx_epoch (u64), rx_ctr_max (u64), rx_digest (64B),
  guard_level (1 byte), prev_cp_hash (64B; SHA-512 of the previous
  CP's canonical bytes, or 64 zero bytes for the first CP),
  anchor_head (64B; hash of the latest anchor-log entry known to the
  signer), challenge_nonce (32B; zero unless answering a challenge).

FIELD SEMANTICS: rx_ctr_max is a COUNT of contiguous received
messages (0 = none received), so CP.rx_digest is the digest after
that many messages and can be checked against the local tx_digest
at (rx_epoch, rx_ctr_max) -- the epoch used is the CP's rx_epoch,
NEVER its tx_epoch. CP.tx_ctr is the carrying message's 0-based
send position; (tx_epoch, tx_ctr) MUST equal the carrying message's
send position.

Domain separator (SS7, CH-02 resolved by definition): the label in
the canonical CP is "SHC-Guard/v0.6/checkpoint" normally and
"SHC-Guard/v0.6/checkpoint-challenge" when challenge_nonce != 0.
The CP is signed with Ed25519 AND ML-DSA-65 over the canonical bytes.

CP verification -- ALL must hold, else the message is rejected:
  (a) both signatures verify;
  (b) session_id/device_id/guard_level/generation match the session;
  (c) cp_seq strictly greater than the last stored CP from that peer;
  (d) (tx_epoch, tx_ctr) equals the carrying message position;
  (e) CP.prev_cp_hash equals the stored previous CP hash (chain
      continuity, CP-03); a CP that does not extend the stored anchor
      head -> SUSPECT + challenge;
  (f) CP.rx_digest equals local tx_digest at (rx_epoch, rx_ctr_max),
      or the position is outside the retained window -> SUSPECT +
      challenge, NOT QUARANTINED;
  (g) if challenge_nonce != 0 it must equal the outstanding challenge
      nonce, else reject.
A CP is attestation of consistency with available evidence only --
it proves NOTHING about device integrity (D-22).

CP cadence: every 50 messages OR 24h (MAXIMUM interval, mandatory).
On every CP the signer registers the CP hash with the anchor BEFORE
sending the CP-bearing message (SS3).
Reference / تجريبي only.
"""

from dataclasses import dataclass

from .common import H, label, u64, u64_decode
from .identity import IdentityRecord
from .tlv import decode_expected, encode_fields

CP_CADENCE_MESSAGES = 50
CP_CADENCE_SECONDS = 24 * 3600

# TLV field types for the canonical CP (fixed order).
C_LABEL = 0x01
C_SESSION_ID = 0x02
C_DEVICE_ID = 0x03
C_GENERATION = 0x04
C_CP_SEQ = 0x05
C_TX_EPOCH = 0x06
C_TX_CTR = 0x07
C_RX_EPOCH = 0x08
C_RX_CTR_MAX = 0x09
C_RX_DIGEST = 0x0A
C_GUARD_LEVEL = 0x0B
C_PREV_CP_HASH = 0x0C
C_ANCHOR_HEAD = 0x0D
C_CHALLENGE_NONCE = 0x0E

ZERO_NONCE = bytes(32)
ZERO_HASH = bytes(64)


@dataclass
class Checkpoint:
    session_id: bytes  # 32 bytes
    device_id: bytes  # 32 bytes (sender's device)
    cp_seq: int
    tx_epoch: int
    tx_ctr: int
    rx_epoch: int
    rx_ctr_max: int
    rx_digest: bytes  # 64 bytes
    guard_level: int  # 1 byte
    generation: int = 1
    prev_cp_hash: bytes = ZERO_HASH  # 64 bytes
    anchor_head: bytes = ZERO_HASH  # 64 bytes
    challenge_nonce: bytes = ZERO_NONCE  # 32 bytes
    # Back-compat: v0.5 code used a single ``epoch`` field.
    epoch: int = None  # if set, used as BOTH tx_epoch and rx_epoch

    def __post_init__(self):
        if self.epoch is not None:
            if self.tx_epoch in (None, 0) and self.rx_epoch in (None, 0):
                self.tx_epoch = self.epoch
                self.rx_epoch = self.epoch

    @property
    def _label(self) -> bytes:
        # Domain separator (SS7): challenge answers are signed under a
        # different label from ordinary checkpoints.
        if self.challenge_nonce != ZERO_NONCE:
            return label("checkpoint-challenge")
        return label("checkpoint")

    def canonical(self) -> bytes:
        return encode_fields([
            (C_LABEL, self._label),
            (C_SESSION_ID, self.session_id),
            (C_DEVICE_ID, self.device_id),
            (C_GENERATION, u64(self.generation)),
            (C_CP_SEQ, u64(self.cp_seq)),
            (C_TX_EPOCH, u64(self.tx_epoch)),
            (C_TX_CTR, u64(self.tx_ctr)),
            (C_RX_EPOCH, u64(self.rx_epoch)),
            (C_RX_CTR_MAX, u64(self.rx_ctr_max)),
            (C_RX_DIGEST, self.rx_digest),
            (C_GUARD_LEVEL, bytes([self.guard_level])),
            (C_PREV_CP_HASH, self.prev_cp_hash),
            (C_ANCHOR_HEAD, self.anchor_head),
            (C_CHALLENGE_NONCE, self.challenge_nonce),
        ])

    def digest(self) -> bytes:
        return H(self.canonical())

    @classmethod
    def parse(cls, data: bytes) -> "Checkpoint":
        f = decode_expected(data, [C_LABEL, C_SESSION_ID, C_DEVICE_ID,
                                   C_GENERATION, C_CP_SEQ, C_TX_EPOCH,
                                   C_TX_CTR, C_RX_EPOCH, C_RX_CTR_MAX,
                                   C_RX_DIGEST, C_GUARD_LEVEL,
                                   C_PREV_CP_HASH, C_ANCHOR_HEAD,
                                   C_CHALLENGE_NONCE])
        if f[C_LABEL] not in (label("checkpoint"),
                             label("checkpoint-challenge")):
            raise ValueError("bad checkpoint label")
        return cls(
            session_id=f[C_SESSION_ID],
            device_id=f[C_DEVICE_ID],
            generation=u64_decode(f[C_GENERATION]),
            cp_seq=u64_decode(f[C_CP_SEQ]),
            tx_epoch=u64_decode(f[C_TX_EPOCH]),
            tx_ctr=u64_decode(f[C_TX_CTR]),
            rx_epoch=u64_decode(f[C_RX_EPOCH]),
            rx_ctr_max=u64_decode(f[C_RX_CTR_MAX]),
            rx_digest=f[C_RX_DIGEST],
            guard_level=f[C_GUARD_LEVEL][0],
            prev_cp_hash=f[C_PREV_CP_HASH],
            anchor_head=f[C_ANCHOR_HEAD],
            challenge_nonce=f[C_CHALLENGE_NONCE])

    def sign(self, identity) -> bytes:
        """Dual-sign the canonical CP. Returns ed_sig || mldsa_sig bytes."""
        import struct

        ed_sig, mldsa_sig = identity.sign(self.canonical())
        return ed_sig + struct.pack(">I", len(mldsa_sig)) + mldsa_sig

    def verify_signatures(self, signer_record: IdentityRecord,
                          signed_blob: bytes) -> bool:
        """Verify rule (a): both signatures over the canonical bytes."""
        import struct

        if len(signed_blob) < 64 + 4:
            return False
        ed_sig = signed_blob[:64]
        (mlen,) = struct.unpack(">I", signed_blob[64:68])
        if len(signed_blob) != 68 + mlen:
            return False
        mldsa_sig = signed_blob[68:]
        return signer_record.verify_dual(self.canonical(), ed_sig, mldsa_sig)


def pack_signed_checkpoint(cp: Checkpoint, signed_blob: bytes) -> bytes:
    """Payload of a type-0x02 plaintext: canonical CP || signed blob."""
    import struct

    canon = cp.canonical()
    return struct.pack(">I", len(canon)) + canon + signed_blob


def unpack_signed_checkpoint(payload: bytes):
    """Inverse of pack_signed_checkpoint. Returns (Checkpoint, signed_blob)."""
    import struct

    if len(payload) < 4:
        raise ValueError("checkpoint payload too short")
    (clen,) = struct.unpack(">I", payload[:4])
    if len(payload) < 4 + clen:
        raise ValueError("checkpoint payload truncated")
    cp = Checkpoint.parse(payload[4:4 + clen])
    return cp, payload[4 + clen:]


class CheckpointVerification:
    """Result of CP verification rules (a)-(g)."""

    OK = "ok"
    BAD_SIGNATURE = "bad_signature"          # (a)
    SESSION_MISMATCH = "session_mismatch"    # (b)
    CP_SEQ_NOT_INCREASING = "cp_seq"         # (c)
    POSITION_MISMATCH = "position"           # (d)
    PREV_CP_HASH_MISMATCH = "prev_cp_hash"   # (e) chain broken
    ANCHOR_NOT_EXTENDING = "anchor_head"     # (e) anchor head regressed
    DIGEST_OUTSIDE_WINDOW = "outside_window"  # (f) outside window -> SUSPECT
    DIGEST_MISMATCH = "digest_mismatch"      # (f) inside window, mismatch
    NONCE_MISMATCH = "nonce_mismatch"        # (g)

    def __init__(self, status: str):
        self.status = status

    @property
    def ok(self) -> bool:
        return self.status == self.OK


def verify_checkpoint(cp: Checkpoint, signed_blob: bytes,
                      signer_record: IdentityRecord,
                      session_id: bytes, expected_device_id: bytes,
                      guard_level: int, last_cp_seq: int,
                      carrying_tx_epoch: int, carrying_tx_ctr: int,
                      local_tx_digest_at, outstanding_nonce: bytes = None,
                      generation: int = None,
                      expected_prev_cp_hash: bytes = None,
                      stored_anchor_head: bytes = None,
                      anchor=None):
    """Run CP verification rules (a)-(g) in order.

    ``local_tx_digest_at(rx_epoch, rx_ctr_max)`` returns the local
    tx_digest at that position, or None if the position is outside the
    retained window. ``outstanding_nonce`` is the active SUSPECT
    challenge nonce (None when no challenge is outstanding).
    ``expected_prev_cp_hash`` is the digest of the last stored CP from
    this peer (ZERO_HASH when none). ``anchor`` is a LocalAnchor (or
    None: anchor checks are skipped and the caller must surface the
    anchor-absent warning -- simultaneous rollback is then undetected,
    residual P0-1).
    """
    if not cp.verify_signatures(signer_record, signed_blob):
        return CheckpointVerification(CheckpointVerification.BAD_SIGNATURE)
    if (cp.session_id != session_id or cp.device_id != expected_device_id
            or cp.guard_level != guard_level):
        return CheckpointVerification(CheckpointVerification.SESSION_MISMATCH)
    if generation is not None and cp.generation != generation:
        return CheckpointVerification(CheckpointVerification.SESSION_MISMATCH)
    if cp.cp_seq <= last_cp_seq:
        return CheckpointVerification(
            CheckpointVerification.CP_SEQ_NOT_INCREASING)
    if cp.tx_epoch != carrying_tx_epoch or cp.tx_ctr != carrying_tx_ctr:
        return CheckpointVerification(CheckpointVerification.POSITION_MISMATCH)
    if expected_prev_cp_hash is not None:
        if cp.prev_cp_hash != expected_prev_cp_hash:
            return CheckpointVerification(
                CheckpointVerification.PREV_CP_HASH_MISMATCH)
    if anchor is not None and stored_anchor_head is not None:
        if not anchor.extends(stored_anchor_head, cp.anchor_head):
            return CheckpointVerification(
                CheckpointVerification.ANCHOR_NOT_EXTENDING)
    # (f): the epoch used is the CP's rx_epoch, never its tx_epoch.
    expected = local_tx_digest_at(cp.rx_epoch, cp.rx_ctr_max)
    if expected is None:
        return CheckpointVerification(
            CheckpointVerification.DIGEST_OUTSIDE_WINDOW)
    if expected != cp.rx_digest:
        return CheckpointVerification(CheckpointVerification.DIGEST_MISMATCH)
    if cp.challenge_nonce != ZERO_NONCE:
        if outstanding_nonce is None or cp.challenge_nonce != outstanding_nonce:
            return CheckpointVerification(
                CheckpointVerification.NONCE_MISMATCH)
    return CheckpointVerification(CheckpointVerification.OK)
