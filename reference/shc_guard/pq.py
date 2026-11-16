# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Single isolation module for ALL liboqs calls (DESIGN_FREEZE.md §0).

Every post-quantum operation in this reference goes through this module.
If liboqs is unavailable, every function here raises PQUnavailableError
with a clear message — callers must NOT silently substitute another
library and tests must FAIL (not skip) in that case.

liboqs-python 0.16 API notes (verified against the installed 0.16.0.2):
- ``generate_keypair()`` returns ONLY the public key; the secret key is
  held on the object and read via ``export_secret_key()``.
- ``KeyEncapsulation(alg, secret_key=...)`` / ``Signature(alg,
  secret_key=...)`` accept a secret key, so decaps/sign take the key
  as an argument here.
- ``generate_keypair_seed(seed)`` derives a keypair deterministically
  from a seed (used for the TEST-ONLY vectors).

Reference / تجريبي only. ML-KEM-768 and ML-DSA-65 only.
"""

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


class PQUnavailableError(RuntimeError):
    """Raised when liboqs-python is not importable/usable."""


_oqs = None
_oqs_import_error = None


def _load_oqs():
    global _oqs, _oqs_import_error
    if _oqs is not None:
        return _oqs
    if _oqs_import_error is not None:
        raise PQUnavailableError(
            "liboqs-python is unavailable: %s" % _oqs_import_error
        )
    try:
        import oqs  # type: ignore
    except Exception as exc:  # noqa: BLE001
        _oqs_import_error = exc
        raise PQUnavailableError(
            "liboqs-python is unavailable: %s" % exc
        ) from exc
    _oqs = oqs
    return _oqs


def is_available() -> bool:
    """True iff liboqs imports and exposes the required mechanisms."""
    try:
        oqs = _load_oqs()
        return (
            KEM_ALG in oqs.get_enabled_kem_mechanisms()
            and SIG_ALG in oqs.get_enabled_sig_mechanisms()
        )
    except PQUnavailableError:
        return False


def check_available() -> None:
    """Raise PQUnavailableError unless both required mechanisms exist."""
    oqs = _load_oqs()
    kems = oqs.get_enabled_kem_mechanisms()
    sigs = oqs.get_enabled_sig_mechanisms()
    missing = []
    if KEM_ALG not in kems:
        missing.append(KEM_ALG)
    if SIG_ALG not in sigs:
        missing.append(SIG_ALG)
    if missing:
        raise PQUnavailableError(
            "liboqs is present but missing mechanisms: %s" % ", ".join(missing)
        )


def enabled_mechanisms():
    """Return (kem list, sig list) — raises PQUnavailableError if no oqs."""
    oqs = _load_oqs()
    return oqs.get_enabled_kem_mechanisms(), oqs.get_enabled_sig_mechanisms()


# ---- ML-KEM-768 ---------------------------------------------------------

def kem_keypair():
    """Generate an ML-KEM-768 keypair. Returns (public_key, secret_key)."""
    oqs = _load_oqs()
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair()
        return bytes(public_key), bytes(kem.export_secret_key())


def kem_keypair_from_seed(seed: bytes):
    """Deterministic ML-KEM-768 keypair from a seed (TEST-ONLY vectors)."""
    oqs = _load_oqs()
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        public_key = kem.generate_keypair_seed(seed)
        return bytes(public_key), bytes(kem.export_secret_key())


def kem_encaps(public_key: bytes):
    """Encapsulate to ``public_key``. Returns (ciphertext, shared_secret)."""
    oqs = _load_oqs()
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        ct, ss = kem.encap_secret(public_key)
        return bytes(ct), bytes(ss)


def kem_decaps(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate ``ciphertext`` with ``secret_key``. Returns shared_secret."""
    oqs = _load_oqs()
    with oqs.KeyEncapsulation(KEM_ALG, secret_key=secret_key) as kem:
        return bytes(kem.decap_secret(ciphertext))


# ---- ML-DSA-65 ----------------------------------------------------------

def sig_keypair():
    """Generate an ML-DSA-65 keypair. Returns (public_key, secret_key)."""
    oqs = _load_oqs()
    with oqs.Signature(SIG_ALG) as sig:
        public_key = sig.generate_keypair()
        return bytes(public_key), bytes(sig.export_secret_key())


def sig_sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign ``message`` with an ML-DSA-65 secret key."""
    oqs = _load_oqs()
    with oqs.Signature(SIG_ALG, secret_key=secret_key) as sig:
        return bytes(sig.sign(message))


def sig_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ML-DSA-65 signature. Returns True/False (never raises)."""
    oqs = _load_oqs()
    with oqs.Signature(SIG_ALG) as sig:
        return bool(sig.verify(message, signature, public_key))


def random_bytes(n: int) -> bytes:
    """Random bytes from libsodium (via PyNaCl) — the freeze's randombytes."""
    from nacl import utils

    return utils.random(n)
