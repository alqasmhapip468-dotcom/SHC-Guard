# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""rx_digest / tx_digest SHA-512 chains (freeze v0.6 SS2).

  rx_digest' = SHA-512("SHC-Guard/v0.6/rx-chain" || session_id ||
      sender_device_id || direction || rx_digest || epoch || ctr ||
      SHA-512(ciphertext))
  direction = 0x01 (A->B) / 0x02 (B->A), fixed per session.
  Direction-specific init (freeze SS2, ChatGPT D-18 objection 2):
  init = SHA-512(label "SHC-Guard/v0.6/rx-chain" || session_id ||
      direction || sender_device_id || "init").
  The direction and sender are in the init value, not only in the
  first update -- the two directions therefore start from different
  values even for the same session_id.
  tx_digest uses the SAME formula and label ("rx-chain") as rx_digest
  (retained v0.5 deviation note: SS2 CP.rx_digest must equal the
  local tx_digest, which requires identical formulas).
  Each chain keeps a history of digests per position (epoch, ctr),
  retained for the last 1000 positions.

Reference / تجريبي only.
"""

from collections import OrderedDict

from .common import H, label, u64

DIRECTION_A_TO_B = 0x01
DIRECTION_B_TO_A = 0x02

RETENTION = 1000  # retention window


class DigestChain:
    """One direction of one digest chain (rx or tx)."""

    def __init__(self, label_name: str, session_id: bytes,
                 sender_device_id: bytes, direction: int):
        self.label_name = label_name
        self.session_id = session_id
        self.sender_device_id = sender_device_id
        self.direction = direction
        # Direction-specific init (freeze SS2):
        # H(label || session_id || direction || sender_device_id || "init").
        self.digest = H(label(label_name) + session_id
                        + bytes([direction]) + sender_device_id + b"init")
        self.history = OrderedDict()  # (epoch, ctr) -> digest AFTER that msg
        self._initial_digest = self.digest

    @property
    def initial_digest(self) -> bytes:
        return self._initial_digest

    def advance(self, epoch: int, ctr: int, ciphertext: bytes) -> bytes:
        """Advance the chain over one ciphertext at (epoch, ctr)."""
        new = H(label(self.label_name) + self.session_id
                + self.sender_device_id + bytes([self.direction])
                + self.digest + u64(epoch) + u64(ctr) + H(ciphertext))
        self.digest = new
        self.history[(epoch, ctr)] = new
        while len(self.history) > RETENTION:
            self.history.popitem(last=False)
        return new

    def digest_at(self, epoch: int, ctr: int):
        """Digest after position (epoch, ctr), or None if outside retention.

        ctr == -1 (no messages yet / empty prefix) returns the initial value.
        """
        if ctr < 0:
            return self._initial_digest
        return self.history.get((epoch, ctr))

    def __repr__(self):
        return ("DigestChain(%s, digest=%s...)" %
                (self.label_name, self.digest.hex()[:16]))


def make_rx_chain(session_id: bytes, sender_device_id: bytes,
                  direction: int) -> DigestChain:
    return DigestChain("rx-chain", session_id, sender_device_id, direction)


def make_tx_chain(session_id: bytes, sender_device_id: bytes,
                  direction: int) -> DigestChain:
    """The sender's digest chain over its own sent ciphertexts.

    Uses the SAME formula/label ("rx-chain") as the peer's rx chain,
    so the equality the freeze's own checks require (CP.rx_digest ==
    local tx_digest, rule 7) actually holds. See v0.5 deviation note.
    """
    return DigestChain("rx-chain", session_id, sender_device_id, direction)
