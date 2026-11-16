# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Handshake transcript (freeze §2).

Transcript includes: protocol name/version "SHC-Guard/v0.6",
handshake_id (32 random bytes), both identity records + fingerprints,
roles, algorithm list (ML-KEM-768 mandatory), ephemeral X25519 pubkeys,
ML-KEM-768 public key + ciphertext, nonce from each party (32 bytes),
guard_level (1 byte), handshake timestamp (u64 unix seconds).

Timestamp valid within ±5 minutes of the local clock; outside → reject.
Both parties sign the transcript with Ed25519 AND ML-DSA-65 over the
same bytes, including role (anti-reflection). Key confirmation: HMAC
(SHA-512) over the transcript with a label-derived key, before the
session is accepted.

Reference / تجريبي only.
"""

import hashlib
import hmac
import time
from dataclasses import dataclass

from .common import H, label, u64, u64_decode
from .identity import IdentityRecord
from .tlv import decode_expected, encode_fields

PROTOCOL_VERSION = "SHC-Guard/v0.6"
TIMESTAMP_TOLERANCE_S = 300  # ±5 minutes (freeze §2)

# TLV field types for the canonical transcript (fixed order).
T_VERSION = 0x01
T_HANDSHAKE_ID = 0x02
T_INITIATOR_RECORD = 0x03
T_INITIATOR_FP = 0x04
T_RESPONDER_RECORD = 0x05
T_RESPONDER_FP = 0x06
T_INITIATOR_ROLE = 0x07
T_RESPONDER_ROLE = 0x08
T_ALGORITHMS = 0x09
T_INITIATOR_EPH = 0x0A
T_RESPONDER_EPH = 0x0B
T_KEM_PK = 0x0C
T_KEM_CT = 0x0D
T_INITIATOR_NONCE = 0x0E
T_RESPONDER_NONCE = 0x0F
T_GUARD_LEVEL = 0x10
T_TIMESTAMP = 0x11
T_GENERATION = 0x12

ROLE_INITIATOR = b"initiator"
ROLE_RESPONDER = b"responder"
ALGORITHMS = b"ML-KEM-768,X25519,Ed25519,ML-DSA-65,XChaCha20-Poly1305"


@dataclass
class Transcript:
    handshake_id: bytes  # 32 bytes
    initiator_record: IdentityRecord
    responder_record: IdentityRecord
    initiator_eph_pub: bytes  # X25519 ephemeral public key (32B)
    responder_eph_pub: bytes  # X25519 ephemeral public key (32B)
    kem_public_key: bytes  # ML-KEM-768 public key (responder's)
    kem_ciphertext: bytes  # ML-KEM-768 ciphertext (initiator's encaps)
    initiator_nonce: bytes  # 32 bytes
    responder_nonce: bytes  # 32 bytes
    guard_level: int  # 1 byte
    timestamp: int  # u64 unix seconds
    generation: int = 1  # u64, freeze SS4: increments per new session

    def canonical(self) -> bytes:
        return encode_fields([
            (T_VERSION, PROTOCOL_VERSION.encode("ascii")),
            (T_HANDSHAKE_ID, self.handshake_id),
            (T_INITIATOR_RECORD, self.initiator_record.canonical()),
            (T_INITIATOR_FP, self.initiator_record.fingerprint()),
            (T_RESPONDER_RECORD, self.responder_record.canonical()),
            (T_RESPONDER_FP, self.responder_record.fingerprint()),
            (T_INITIATOR_ROLE, ROLE_INITIATOR),
            (T_RESPONDER_ROLE, ROLE_RESPONDER),
            (T_ALGORITHMS, ALGORITHMS),
            (T_INITIATOR_EPH, self.initiator_eph_pub),
            (T_RESPONDER_EPH, self.responder_eph_pub),
            (T_KEM_PK, self.kem_public_key),
            (T_KEM_CT, self.kem_ciphertext),
            (T_INITIATOR_NONCE, self.initiator_nonce),
            (T_RESPONDER_NONCE, self.responder_nonce),
            (T_GUARD_LEVEL, bytes([self.guard_level])),
            (T_TIMESTAMP, u64(self.timestamp)),
            (T_GENERATION, u64(self.generation)),
        ])

    def digest(self) -> bytes:
        """SHA-512 of the canonical transcript."""
        return H(self.canonical())

    @classmethod
    def parse(cls, data: bytes) -> "Transcript":
        f = decode_expected(data, [
            T_VERSION, T_HANDSHAKE_ID, T_INITIATOR_RECORD, T_INITIATOR_FP,
            T_RESPONDER_RECORD, T_RESPONDER_FP, T_INITIATOR_ROLE,
            T_RESPONDER_ROLE, T_ALGORITHMS, T_INITIATOR_EPH, T_RESPONDER_EPH,
            T_KEM_PK, T_KEM_CT, T_INITIATOR_NONCE, T_RESPONDER_NONCE,
            T_GUARD_LEVEL, T_TIMESTAMP, T_GENERATION])
        if f[T_VERSION].decode("ascii") != PROTOCOL_VERSION:
            raise ValueError("unsupported protocol version")
        if f[T_ALGORITHMS] != ALGORITHMS:
            raise ValueError("algorithm list mismatch (ML-KEM-768 mandatory)")
        return cls(
            handshake_id=f[T_HANDSHAKE_ID],
            initiator_record=IdentityRecord.parse(f[T_INITIATOR_RECORD]),
            responder_record=IdentityRecord.parse(f[T_RESPONDER_RECORD]),
            initiator_eph_pub=f[T_INITIATOR_EPH],
            responder_eph_pub=f[T_RESPONDER_EPH],
            kem_public_key=f[T_KEM_PK],
            kem_ciphertext=f[T_KEM_CT],
            initiator_nonce=f[T_INITIATOR_NONCE],
            responder_nonce=f[T_RESPONDER_NONCE],
            guard_level=f[T_GUARD_LEVEL][0],
            timestamp=u64_decode(f[T_TIMESTAMP]),
            generation=u64_decode(f[T_GENERATION]))

    def check_timestamp(self, now: int = None) -> bool:
        """True iff the handshake timestamp is within ±5 minutes."""
        now = int(time.time()) if now is None else now
        return abs(now - self.timestamp) <= TIMESTAMP_TOLERANCE_S


def key_confirmation_key(shared_secret: bytes) -> bytes:
    """Label-derived key-confirmation key (freeze §2)."""
    return H(label("handshake-confirm") + shared_secret)


def key_confirmation_mac(shared_secret: bytes, transcript_bytes: bytes) -> bytes:
    """HMAC-SHA-512 over the transcript with the label-derived key."""
    return hmac.new(
        key_confirmation_key(shared_secret), transcript_bytes,
        hashlib.sha512).digest()


def verify_key_confirmation(shared_secret: bytes, transcript_bytes: bytes,
                            mac: bytes) -> bool:
    expected = key_confirmation_mac(shared_secret, transcript_bytes)
    return hmac.compare_digest(expected, mac)
