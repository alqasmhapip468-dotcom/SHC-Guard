# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Hybrid handshake (freeze v0.6 §2/§4/§5).

  Ed25519 + ML-DSA-65 identities, X25519 + ML-KEM-768 key agreement,
  transcript signatures (dual, incl. role), key-confirmation MAC over
  the transcript with a label-derived key.

Flow (in-process message passing; wire encoding is not frozen):
  1. initiator_start()  → offer (record, X25519 eph pub, nonce,
     handshake_id, timestamp, guard_level)
  2. responder_reply()  → reply (record, X25519 eph pub, ML-KEM-768 pk,
     nonce, timestamp) — responder keeps a pending KEM secret key.
  3. initiator_finish() → finish (transcript, KEM ciphertext, dual
     transcript signatures, key-confirmation MAC)
  4. responder_finish() → session material + responder key-confirmation
     MAC; initiator_confirm() verifies it.

Rules enforced here:
- Handshake timestamp within ±5 minutes (both directions).
- Revocation-list check + version pinning at every handshake
  (fail-closed: no valid list → reject).
- ML-KEM-768 mandatory (algorithm list in the transcript).
- Consumed handshake IDs kept for the LIFETIME of the identity
  record (D-19, freeze SS9) and recorded ONLY after the session is
  saved (see session.py: Session.save() records the ID). A replayed
  transcript after 7 days is still rejected -- by permanent state,
  not by the clock.
  A crash during handshake → retry with a NEW handshake_id.
- Incomplete-handshake timeout: 30s.
- guard_level B is advisory (freeze §7, D-2). Reference policy: B is
  rejected unless ``allow_level_b=True`` (the --allow-level-b test-only
  flag in the demo). Production guidance: default REJECT_B.

Reference / تجريبي only.
"""

import time
from dataclasses import dataclass, field

from nacl.public import PrivateKey

from . import pq
from .common import H, label
from .identity import Identity, IdentityRecord
from .revocation import RevocationChecker
from .transcript import (
    Transcript, key_confirmation_mac, verify_key_confirmation,
)

HANDSHAKE_TIMEOUT_S = 30
# D-19: consumed IDs are retained for the LIFETIME of the identity
# record. The constant is kept (value unused for expiry) for callers
# that referenced it in v0.5.
CONSUMED_ID_RETENTION_S = None


class HandshakeError(Exception):
    """Any handshake rejection (timestamp, revocation, MAC, timeout…)."""


class HandshakeTimeout(HandshakeError):
    pass


class ConsumedHandshakeIDs:
    """Consumed handshake IDs, kept for the LIFETIME of the identity
    record (D-19). No expiry, no purge: an ID recorded once stays
    consumed forever (storage cost accepted as a security choice).

    An ID is recorded ONLY after the session is saved -- never during
    the handshake itself (freeze SS2).
    """

    def __init__(self, clock=time.time):
        self.clock = clock
        self._ids = {}  # handshake_id bytes -> recorded unix time

    def is_consumed(self, handshake_id: bytes) -> bool:
        return handshake_id in self._ids

    def record(self, handshake_id: bytes) -> None:
        self._ids[handshake_id] = self.clock()

    def _purge(self) -> None:
        """No-op (D-19): consumed IDs are never purged."""
        return None


@dataclass
class HandshakeMaterial:
    """Agreed session material for one party."""

    session_id: bytes  # 32 bytes
    transcript: Transcript
    transcript_bytes: bytes
    shared_secret: bytes  # X25519 DH || ML-KEM-768 shared secret
    root_key: bytes  # 32 bytes, seeds the demonstration ratchet
    handshake_id: bytes
    guard_level: int
    is_initiator: bool
    own_identity: Identity
    peer_record: IdentityRecord
    own_eph_private: PrivateKey
    peer_eph_pub: bytes
    key_confirmation_mac: bytes
    generation: int = 1  # freeze SS4


def _derive_root_key(shared_secret: bytes) -> bytes:
    return H(label("state-encryption") + shared_secret)[:32]


def _check_guard_level(guard_level: int, allow_level_b: bool) -> None:
    from .identity import GUARD_LEVEL_A, GUARD_LEVEL_B

    if guard_level == GUARD_LEVEL_B and not allow_level_b:
        raise HandshakeError(
            "guard_level B rejected by policy (test-only --allow-level-b "
            "is required in this reference; production default is REJECT_B)")
    if guard_level not in (GUARD_LEVEL_A, GUARD_LEVEL_B):
        raise HandshakeError("unknown guard_level")


# ---- step 1: initiator ------------------------------------------------------

@dataclass
class _InitiatorPending:
    identity: Identity
    eph_private: PrivateKey
    handshake_id: bytes
    nonce: bytes
    timestamp: int
    started_at: float
    guard_level: int
    generation: int = 1


def initiator_start(identity: Identity, guard_level: int = None,
                    allow_level_b: bool = True,
                    eph_private: PrivateKey = None,
                    handshake_id: bytes = None, nonce: bytes = None,
                    timestamp: int = None, clock=time.time,
                    generation: int = 1) -> tuple:
    """Create the handshake offer. Returns (offer dict, pending)."""
    guard_level = identity.guard_level if guard_level is None else guard_level
    _check_guard_level(guard_level, allow_level_b)
    eph_private = eph_private or PrivateKey.generate()
    offer = {
        "type": "offer",
        "version": "SHC-Guard/v0.6",
        "record": identity.record().canonical(),
        "eph_pub": bytes(eph_private.public_key),
        "handshake_id": handshake_id or pq.random_bytes(32),
        "nonce": nonce or pq.random_bytes(32),
        "timestamp": int(timestamp if timestamp is not None else clock()),
        "guard_level": guard_level,
        "generation": generation,
    }
    pending = _InitiatorPending(
        identity=identity, eph_private=eph_private,
        handshake_id=offer["handshake_id"], nonce=offer["nonce"],
        timestamp=offer["timestamp"], started_at=clock(),
        guard_level=guard_level, generation=offer.get("generation", 1))
    return offer, pending


# ---- step 2: responder ------------------------------------------------------

@dataclass
class _ResponderPending:
    identity: Identity
    eph_private: PrivateKey
    kem_secret_key: bytes
    kem_public_key: bytes
    nonce: bytes
    offer: dict
    started_at: float
    generation: int = 1


def responder_reply(offer: dict, identity: Identity,
                    revocation: RevocationChecker,
                    consumed: ConsumedHandshakeIDs,
                    allow_level_b: bool = True,
                    eph_private: PrivateKey = None, nonce: bytes = None,
                    clock=time.time) -> tuple:
    """Validate the offer; return (reply dict, pending)."""
    if offer.get("version") not in (None, "SHC-Guard/v0.6"):
        # v0.6 is WIRE-INCOMPATIBLE with v0.5 by design: a peer
        # offering v0.5 labels/records is rejected at the handshake.
        raise HandshakeError(
            "peer offers unsupported protocol version %r (v0.6 required)"
            % offer.get("version"))
    now = int(clock())
    if abs(now - offer["timestamp"]) > 300:
        raise HandshakeError("offer timestamp outside ±5 minutes")
    if consumed.is_consumed(offer["handshake_id"]):
        raise HandshakeError("handshake_id already consumed (replay)")
    peer_record = IdentityRecord.parse(offer["record"])
    ok, reason = revocation.check(peer_record.user_id,
                                  peer_record.record_version, now)
    if not ok:
        raise HandshakeError("revocation check failed: %s" % reason)
    _check_guard_level(offer["guard_level"], allow_level_b)
    if offer["guard_level"] != identity.guard_level:
        raise HandshakeError("guard_level mismatch between parties")
    eph_private = eph_private or PrivateKey.generate()
    kem_pk, kem_sk = pq.kem_keypair()
    reply = {
        "type": "reply",
        "record": identity.record().canonical(),
        "eph_pub": bytes(eph_private.public_key),
        "kem_public_key": kem_pk,
        "nonce": nonce or pq.random_bytes(32),
        "timestamp": now,
        "guard_level": identity.guard_level,
    }
    pending = _ResponderPending(
        identity=identity, eph_private=eph_private,
        kem_secret_key=kem_sk, kem_public_key=kem_pk,
        nonce=reply["nonce"], offer=offer, started_at=clock(),
        generation=offer.get("generation", 1))
    return reply, pending


# ---- step 3: initiator finishes ----------------------------------------------

def initiator_finish(reply: dict, pending: _InitiatorPending,
                     revocation: RevocationChecker,
                     consumed: ConsumedHandshakeIDs,
                     clock=time.time) -> tuple:
    """Validate the reply, build + sign the transcript, encapsulate.

    Returns (finish dict, HandshakeMaterial)."""
    if clock() - pending.started_at > HANDSHAKE_TIMEOUT_S:
        raise HandshakeTimeout("handshake incomplete for >30s")
    now = int(clock())
    if abs(now - reply["timestamp"]) > 300:
        raise HandshakeError("reply timestamp outside ±5 minutes")
    peer_record = IdentityRecord.parse(reply["record"])
    ok, reason = revocation.check(peer_record.user_id,
                                  peer_record.record_version, now)
    if not ok:
        raise HandshakeError("revocation check failed: %s" % reason)
    if reply["guard_level"] != pending.guard_level:
        raise HandshakeError("guard_level mismatch between parties")
    kem_ct, kem_ss = pq.kem_encaps(reply["kem_public_key"])
    dh_shared = _dh(pending.eph_private, reply["eph_pub"])
    shared_secret = dh_shared + kem_ss
    transcript = Transcript(
        handshake_id=pending.handshake_id,
        initiator_record=pending.identity.record(),
        responder_record=peer_record,
        initiator_eph_pub=bytes(pending.eph_private.public_key),
        responder_eph_pub=reply["eph_pub"],
        kem_public_key=reply["kem_public_key"],
        kem_ciphertext=kem_ct,
        initiator_nonce=pending.nonce,
        responder_nonce=reply["nonce"],
        guard_level=pending.guard_level,
        timestamp=pending.timestamp,
        generation=pending.generation)
    t_bytes = transcript.canonical()
    ed_sig, mldsa_sig = pending.identity.sign(t_bytes)
    mac = key_confirmation_mac(shared_secret, t_bytes)
    finish = {
        "type": "finish",
        "transcript": t_bytes,
        "kem_ciphertext": kem_ct,
        "ed_sig": ed_sig,
        "mldsa_sig": mldsa_sig,
        "key_confirmation_mac": mac,
    }
    material = HandshakeMaterial(
        session_id=H(t_bytes)[:32], transcript=transcript,
        transcript_bytes=t_bytes, shared_secret=shared_secret,
        root_key=_derive_root_key(shared_secret),
        handshake_id=pending.handshake_id,
        guard_level=pending.guard_level, generation=pending.generation,
        is_initiator=True,
        own_identity=pending.identity, peer_record=peer_record,
        own_eph_private=pending.eph_private,
        peer_eph_pub=reply["eph_pub"], key_confirmation_mac=mac)
    return finish, material


def _dh(private: PrivateKey, peer_pub: bytes) -> bytes:
    from nacl.bindings import crypto_scalarmult

    return crypto_scalarmult(bytes(private), peer_pub)


# ---- step 4: responder finishes ----------------------------------------------

def responder_finish(finish: dict, pending: _ResponderPending,
                     consumed: ConsumedHandshakeIDs,
                     clock=time.time) -> tuple:
    """Validate transcript + signatures + key confirmation.

    Returns (confirm dict, HandshakeMaterial). The handshake_id is NOT
    recorded as consumed here — the session records it after saving.
    """
    if clock() - pending.started_at > HANDSHAKE_TIMEOUT_S:
        raise HandshakeTimeout("handshake incomplete for >30s")
    t_bytes = finish["transcript"]
    transcript = Transcript.parse(t_bytes)
    if not transcript.check_timestamp():
        raise HandshakeError("transcript timestamp outside ±5 minutes")
    if consumed.is_consumed(transcript.handshake_id):
        raise HandshakeError("handshake_id already consumed (replay)")
    if transcript.handshake_id != pending.offer["handshake_id"]:
        raise HandshakeError("handshake_id mismatch with offer")
    if transcript.kem_ciphertext != finish["kem_ciphertext"]:
        raise HandshakeError("KEM ciphertext mismatch with transcript")
    initiator_record = transcript.initiator_record
    if not initiator_record.verify_dual(
            t_bytes, finish["ed_sig"], finish["mldsa_sig"]):
        raise HandshakeError("initiator transcript signatures invalid")
    kem_ss = pq.kem_decaps(pending.kem_secret_key,
                           finish["kem_ciphertext"])
    dh_shared = _dh(pending.eph_private, transcript.initiator_eph_pub)
    shared_secret = dh_shared + kem_ss
    if not verify_key_confirmation(shared_secret, t_bytes,
                                   finish["key_confirmation_mac"]):
        raise HandshakeError("key confirmation MAC invalid")
    mac = key_confirmation_mac(shared_secret, t_bytes)
    confirm = {"type": "confirm", "key_confirmation_mac": mac}
    material = HandshakeMaterial(
        session_id=H(t_bytes)[:32], transcript=transcript,
        transcript_bytes=t_bytes, shared_secret=shared_secret,
        root_key=_derive_root_key(shared_secret),
        handshake_id=transcript.handshake_id,
        guard_level=transcript.guard_level,
        generation=transcript.generation, is_initiator=False,
        own_identity=pending.identity, peer_record=initiator_record,
        own_eph_private=pending.eph_private,
        peer_eph_pub=transcript.initiator_eph_pub,
        key_confirmation_mac=mac)
    return confirm, material


def initiator_confirm(confirm: dict, material: HandshakeMaterial) -> None:
    """Verify the responder's key-confirmation MAC (step 4, initiator)."""
    if not verify_key_confirmation(material.shared_secret,
                                   material.transcript_bytes,
                                   confirm["key_confirmation_mac"]):
        raise HandshakeError("responder key confirmation MAC invalid")
