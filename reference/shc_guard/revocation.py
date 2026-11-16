# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Signed revocation-list check (freeze §2).

At every handshake, check a signed revocation list, freshness ≤ 24h.
The list is signed by an operator key configured OUT OF BAND.
The reference demo generates a test operator key + empty signed list;
production MUST configure a real one. NO fail-open default: if no
valid list is configured, the check FAILS (handshake rejected).

Highest-version pinning: reject a record_version lower than previously
seen for the same user_id. During rotation only the highest version is
accepted.

Reference / تجريبي only.
"""

import json
import time
from dataclasses import dataclass, field

from nacl.signing import SigningKey, VerifyKey

from .common import H, label

MAX_LIST_AGE_S = 24 * 3600


@dataclass
class RevocationList:
    """A signed list of revoked (user_id, record_version) pairs."""

    issued_at: int  # unix seconds
    revoked: list = field(default_factory=list)  # [(user_id, version)]
    signature: bytes = b""

    def canonical(self) -> bytes:
        body = {
            "issued_at": self.issued_at,
            "revoked": [[u, v] for u, v in self.revoked],
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def sign(self, operator_signing_key: SigningKey) -> bytes:
        msg = label("revocation-list") + self.canonical()
        self.signature = bytes(operator_signing_key.sign(msg).signature)
        return self.signature

    def verify(self, operator_verify_key: VerifyKey, now: int = None) -> bool:
        """Signature valid AND fresh (≤ 24h)."""
        now = int(time.time()) if now is None else now
        if now - self.issued_at > MAX_LIST_AGE_S or self.issued_at > now + 60:
            return False
        try:
            operator_verify_key.verify(
                label("revocation-list") + self.canonical(), self.signature)
        except Exception:
            return False
        return True

    def is_revoked(self, user_id: str, record_version: int) -> bool:
        return [user_id, record_version] in (
            [u, v] for u, v in self.revoked)


class RevocationChecker:
    """Holds the out-of-band operator key + highest seen versions.

    ``check()`` returns (allowed: bool, reason: str). No fail-open:
    without a configured, valid, fresh list the answer is (False, ...).
    """

    def __init__(self, operator_verify_key: VerifyKey = None,
                 revocation_list: RevocationList = None):
        self.operator_verify_key = operator_verify_key
        self.revocation_list = revocation_list
        self.highest_seen = {}  # user_id -> highest record_version seen

    def update_list(self, revocation_list: RevocationList) -> None:
        self.revocation_list = revocation_list

    def check(self, user_id: str, record_version: int,
              now: int = None) -> tuple:
        if self.operator_verify_key is None or self.revocation_list is None:
            return False, "no revocation list configured (fail-closed)"
        if not self.revocation_list.verify(self.operator_verify_key, now):
            return False, "revocation list invalid or stale (>24h)"
        if self.revocation_list.is_revoked(user_id, record_version):
            return False, "identity revoked"
        highest = self.highest_seen.get(user_id)
        if highest is not None and record_version < highest:
            return False, "record_version below highest seen (pinning)"
        self.highest_seen[user_id] = max(record_version, highest or 0)
        return True, "ok"


def generate_test_operator():
    """TEST-ONLY operator key + empty signed list (for demo/tests)."""
    sk = SigningKey.generate()
    lst = RevocationList(issued_at=int(time.time()), revoked=[])
    lst.sign(sk)
    return sk, lst
