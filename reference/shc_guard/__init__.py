# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""SHC-Guard v0.6 — reference implementation (تجريبي).

State-guard layer: hybrid handshake (Ed25519 + ML-DSA-65, X25519 +
ML-KEM-768), XChaCha20-Poly1305 AEAD, rx/tx digest chains, signed
checkpoints, SUSPECT challenge protocol, double journal + simulated
hardware counter, outbox, revocation check, state machine.

NOT audited, NOT production crypto. See DESIGN_FREEZE.md.
"""

from . import pq  # noqa: F401
from .anchor import LocalAnchor  # noqa: F401
from .session import Session, SessionRegistry  # noqa: F401

__version__ = "0.6.0"
__all__ = ["Session", "SessionRegistry", "LocalAnchor", "pq"]
