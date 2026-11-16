# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Identity records + fingerprints + dual signatures (freeze v0.6 §2/§5).

- Identity record: user_id, device_id (32 bytes), record_version (u64),
  Ed25519 public key, ML-DSA-65 public key, guard_level (1 byte).
- Fingerprint = SHA-512("SHC-Guard/v0.6/identity-fp" || canonical record).
- Dual signing: Ed25519 (PyNaCl) AND ML-DSA-65 (liboqs, via pq.py)
  over the same bytes.

guard_level is a SELF-SIGNED CLAIM (freeze §7, Decision D-2): advisory +
accountability only, never proof of hardware protection.
Reference / تجريبي only.
"""

from dataclasses import dataclass

from nacl.public import PrivateKey as _X25519SK  # noqa: F401  (kept for clarity)
from nacl.signing import SigningKey, VerifyKey

from . import pq
from .common import H, label, u64
from .tlv import decode_expected, encode_fields

# TLV field types for the canonical identity record (fixed order).
F_USER_ID = 0x01
F_DEVICE_ID = 0x02
F_RECORD_VERSION = 0x03
F_ED25519_PK = 0x04
F_MLDSA_PK = 0x05
F_GUARD_LEVEL = 0x06

GUARD_LEVEL_A = 0x41  # 'A' — NOT available in this reference (no hardware).
GUARD_LEVEL_B = 0x42  # 'B' — default in this reference.


@dataclass
class Identity:
    """A long-term identity: Ed25519 + ML-DSA-65 keypairs + record data."""

    user_id: str
    device_id: bytes  # 32 bytes
    record_version: int
    guard_level: int = GUARD_LEVEL_B
    ed_signing_key: SigningKey = None  # type: ignore
    mldsa_secret_key: bytes = b""

    def __post_init__(self):
        if len(self.device_id) != 32:
            raise ValueError("device_id must be 32 bytes")
        if self.ed_signing_key is None:
            self.ed_signing_key = SigningKey.generate()
        if not self.mldsa_secret_key:
            _pk, sk = pq.sig_keypair()
            self._mldsa_public_key = _pk
            self.mldsa_secret_key = sk
        else:
            # Public key is derivable only by generating; for identities
            # built from stored keys the caller must set it via from_keys().
            self._mldsa_public_key = getattr(self, "_mldsa_public_key", b"")

    # -- construction helpers ------------------------------------------------

    @classmethod
    def generate(cls, user_id: str, device_id: bytes, record_version: int = 1,
                 guard_level: int = GUARD_LEVEL_B) -> "Identity":
        return cls(user_id=user_id, device_id=device_id,
                   record_version=record_version, guard_level=guard_level)

    @classmethod
    def from_ed_seed(cls, user_id: str, device_id: bytes, ed_seed: bytes,
                     mldsa_public_key: bytes, mldsa_secret_key: bytes,
                     record_version: int = 1,
                     guard_level: int = GUARD_LEVEL_B) -> "Identity":
        """Build an identity from fixed key material (tests / vectors).

        ed_seed is a 32-byte Ed25519 seed. ML-DSA keys come from pq
        (liboqs keygen is randomised; pass stored TEST-ONLY keys here).
        """
        obj = cls.__new__(cls)
        obj.user_id = user_id
        obj.device_id = device_id
        obj.record_version = record_version
        obj.guard_level = guard_level
        obj.ed_signing_key = SigningKey(ed_seed)
        obj._mldsa_public_key = mldsa_public_key
        obj.mldsa_secret_key = mldsa_secret_key
        return obj

    @classmethod
    def from_public(cls, user_id: str, device_id: bytes, record_version: int,
                    ed_public_key: bytes, mldsa_public_key: bytes,
                    guard_level: int = GUARD_LEVEL_B) -> "IdentityRecord":
        """Build a PUBLIC-ONLY record (e.g. a peer's record) for verification."""
        return IdentityRecord(
            user_id=user_id, device_id=device_id,
            record_version=record_version, ed_public_key=ed_public_key,
            mldsa_public_key=mldsa_public_key, guard_level=guard_level)

    # -- public material -----------------------------------------------------

    @property
    def ed_public_key(self) -> bytes:
        return bytes(self.ed_signing_key.verify_key)

    @property
    def mldsa_public_key(self) -> bytes:
        return self._mldsa_public_key

    # -- canonical form / fingerprint ----------------------------------------

    def record(self) -> "IdentityRecord":
        return IdentityRecord(
            user_id=self.user_id, device_id=self.device_id,
            record_version=self.record_version,
            ed_public_key=self.ed_public_key,
            mldsa_public_key=self.mldsa_public_key,
            guard_level=self.guard_level)

    def canonical_record(self) -> bytes:
        return self.record().canonical()

    def fingerprint(self) -> bytes:
        """SHA-512(label || canonical record) — freeze §2."""
        return H(label("identity-fp") + self.canonical_record())

    # -- dual signing ----------------------------------------------------------

    def sign(self, message: bytes):
        """Sign with Ed25519 AND ML-DSA-65. Returns (ed_sig, mldsa_sig)."""
        ed_sig = bytes(self.ed_signing_key.sign(message).signature)
        mldsa_sig = pq.sig_sign(self.mldsa_secret_key, message)
        return ed_sig, mldsa_sig


@dataclass(frozen=True)
class IdentityRecord:
    """Public-only identity record (what travels in the transcript)."""

    user_id: str
    device_id: bytes
    record_version: int
    ed_public_key: bytes
    mldsa_public_key: bytes
    guard_level: int = GUARD_LEVEL_B

    def canonical(self) -> bytes:
        return encode_fields([
            (F_USER_ID, self.user_id.encode("utf-8")),
            (F_DEVICE_ID, self.device_id),
            (F_RECORD_VERSION, u64(self.record_version)),
            (F_ED25519_PK, self.ed_public_key),
            (F_MLDSA_PK, self.mldsa_public_key),
            (F_GUARD_LEVEL, bytes([self.guard_level])),
        ])

    def fingerprint(self) -> bytes:
        return H(label("identity-fp") + self.canonical())

    @classmethod
    def parse(cls, data: bytes) -> "IdentityRecord":
        f = decode_expected(data, [F_USER_ID, F_DEVICE_ID, F_RECORD_VERSION,
                                   F_ED25519_PK, F_MLDSA_PK, F_GUARD_LEVEL])
        from .common import u64_decode

        return cls(
            user_id=f[F_USER_ID].decode("utf-8"),
            device_id=f[F_DEVICE_ID],
            record_version=u64_decode(f[F_RECORD_VERSION]),
            ed_public_key=f[F_ED25519_PK],
            mldsa_public_key=f[F_MLDSA_PK],
            guard_level=f[F_GUARD_LEVEL][0])

    def verify_dual(self, message: bytes, ed_sig: bytes, mldsa_sig: bytes) -> bool:
        """Verify BOTH signatures over the same bytes. Both must pass."""
        try:
            VerifyKey(self.ed_public_key).verify(message, ed_sig)
        except Exception:
            return False
        try:
            if not pq.sig_verify(self.mldsa_public_key, message, mldsa_sig):
                return False
        except Exception:
            return False
        return True

# ---- SS5: TOFU + out-of-band fingerprint verification --------------------
# A new identity record starts as TRUSTED-UNVERIFIED. The session may
# be established, but the app MUST display "unverified identity" and
# the reference Session MUST NOT send application messages until the
# fingerprint is verified out-of-band and marked verified -- unless
# the caller passes an explicit test-only allow_unverified flag.

TRUSTED_UNVERIFIED = "TRUSTED-UNVERIFIED"
VERIFIED = "VERIFIED"


class TrustStore:
    """TOFU trust store: fingerprint (hex) -> verification status."""

    def __init__(self):
        self._records = {}  # fingerprint hex -> status

    def status_of(self, fingerprint: bytes) -> str:
        return self._records.get(fingerprint.hex(), TRUSTED_UNVERIFIED)

    def is_verified(self, fingerprint: bytes) -> bool:
        return self.status_of(fingerprint) == VERIFIED

    def trust_unverified(self, fingerprint: bytes) -> None:
        """First sight (TOFU): record as TRUSTED-UNVERIFIED."""
        self._records.setdefault(fingerprint.hex(), TRUSTED_UNVERIFIED)

    def verify_fingerprint(self, fingerprint: bytes,
                           expected_hex: str) -> bool:
        """Mark VERIFIED iff the fingerprint matches the out-of-band
        value the user compared (in person / second channel)."""
        if fingerprint.hex() != expected_hex.lower():
            return False
        self._records[fingerprint.hex()] = VERIFIED
        return True


def create_rotation_record(old_identity, new_identity) -> bytes:
    """Signed rotation record (freeze SS5): old keys sign the new
    record, new keys sign the old fingerprint; version increments.
    Returns canonical bytes || old dual sig || new dual sig (test
    reference format; wire encoding is not frozen)."""
    import struct

    from .common import H, label
    from .tlv import encode_fields

    body = encode_fields([
        (0x01, old_identity.record().canonical()),
        (0x02, new_identity.record().canonical()),
        (0x03, old_identity.fingerprint()),
        (0x04, new_identity.fingerprint()),
    ])
    if new_identity.record_version != old_identity.record_version + 1:
        raise ValueError("rotation must increment record_version by 1")
    msg = label("identity-rotation") + body
    ed1, ml1 = old_identity.sign(msg)
    ed2, ml2 = new_identity.sign(msg)
    blob = lambda ed, ml: ed + struct.pack(">I", len(ml)) + ml
    return body + blob(ed1, ml1) + blob(ed2, ml2)


def verify_rotation_record(blob: bytes, old_record, new_record) -> bool:
    """Verify both dual signatures on a rotation record."""
    import struct

    from .common import label
    from .tlv import encode_fields

    body = encode_fields([
        (0x01, old_record.canonical()),
        (0x02, new_record.canonical()),
        (0x03, old_record.fingerprint()),
        (0x04, new_record.fingerprint()),
    ])
    msg = label("identity-rotation") + body

    def _split(rest):
        ed, rest = rest[:64], rest[64:]
        (mlen,) = struct.unpack(">I", rest[:4])
        return ed, rest[4:4 + mlen], rest[4 + mlen:]

    try:
        ed1, ml1, rest = _split(blob[len(body):])
        ed2, ml2, tail = _split(rest)
        if tail:
            return False
    except Exception:
        return False
    return (old_record.verify_dual(msg, ed1, ml1)
            and new_record.verify_dual(msg, ed2, ml2))
