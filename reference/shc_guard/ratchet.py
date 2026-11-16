# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""MINIMAL DEMONSTRATION ratchet — NOT Signal, NOT Triple Ratchet.

This is a small demonstration DH ratchet + symmetric chain built from
libsodium generichash (BLAKE2b) and X25519, for LOGIC REFERENCE ONLY
(freeze §0). It is NOT the Signal library, NOT a full Triple Ratchet,
NOT audited, and must NOT be presented as equivalent to PQXDH/Signal.

How the demonstration DH step works (mirrors the classic DH-ratchet
pairing, in miniature):
- SEND with a fresh keypair: generate (priv', pub'); shared =
  DH(priv', peer_pub); root' = generichash(root || shared); the sending
  chain is re-derived from root'; the header carries pub'.
- RECEIVE a new peer pub P: shared = DH(my_priv, P) — equal to the
  sender's shared, because my_priv pairs with peer_pub and P pairs
  with priv'; root' = generichash(root || shared); the receiving chain
  is re-derived from root'. Rotation itself happens at the next send.
- The initiator sends first with its handshake ephemeral public key
  (no step); the responder rotates on its first send.
- Each chain: msg_key = generichash(chain_key || "msg"), then
  chain_key' = generichash(chain_key || "next"). Message keys are
  32 bytes, used as XChaCha20-Poly1305 keys. ``peek_recv_key()``
  derives without consuming, so a failed AEAD check (rule 1) does not
  burn a key.

Reference / تجريبي only.
"""

from nacl.bindings import crypto_scalarmult
from nacl.bindings.crypto_generichash import (
    generichash_blake2b_salt_personal as _blake2b,
)
from nacl.public import PrivateKey

MSG_KEY_LEN = 32


def _gh(data: bytes, outlen: int = 32) -> bytes:
    """libsodium generichash (BLAKE2b), one-shot, raw bytes out."""
    return _blake2b(data, outlen)


def _dh(private: PrivateKey, peer_pub: bytes) -> bytes:
    return crypto_scalarmult(bytes(private), peer_pub)


class DemonstrationRatchet:
    """Minimal demonstration DH ratchet + symmetric chains."""

    def __init__(self, root_key: bytes, is_initiator: bool,
                 own_eph_private: PrivateKey, peer_eph_pub: bytes):
        if len(root_key) != 32:
            raise ValueError("root key must be 32 bytes")
        self.root_key = root_key
        self.is_initiator = is_initiator
        self._dh_private = own_eph_private
        self._peer_pub = peer_eph_pub
        # The responder rotates on its first send; the initiator sends
        # first with its handshake ephemeral public key.
        self._needs_rotation = not is_initiator
        self.send_chain_key = self._derive_chain("send")
        self.recv_chain_key = self._derive_chain("recv")
        self.send_ctr = 0
        self.recv_ctr = 0

    # -- derivation ----------------------------------------------------------

    def _derive_chain(self, which: str) -> bytes:
        # The initiator's "send" chain is the responder's "recv" chain:
        # derive from the root + a direction tag shared by both sides
        # for a given traffic direction.
        if self.is_initiator:
            tag = b"A-to-B" if which == "send" else b"B-to-A"
        else:
            tag = b"B-to-A" if which == "send" else b"A-to-B"
        return _gh(self.root_key + tag)

    # -- DH ------------------------------------------------------------------

    @property
    def dh_public(self) -> bytes:
        return bytes(self._dh_private.public_key)

    def _step_root_send(self, shared: bytes) -> None:
        """Send-side DH step: re-derive ONLY the sending chain.

        The receiving chain is untouched: the peer may still send with
        its old chain (it has not seen my new public key yet), and my
        receiving chain must keep decrypting those messages. This is
        the property that makes concurrent sending work; re-deriving
        both chains on a send step breaks decryption of the peer's
        still-old-chain messages.
        """
        self.root_key = _gh(self.root_key + shared)
        self.send_chain_key = self._derive_chain("send")

    def _step_root_recv(self, shared: bytes) -> None:
        """Receive-side DH step: re-derive ONLY the receiving chain."""
        self.root_key = _gh(self.root_key + shared)
        self.recv_chain_key = self._derive_chain("recv")

    def prepare_recv(self, header_pub: bytes) -> None:
        """Catch-up DH step for a NEW peer public key in a header.

        No-op when the header carries the already-seen key.
        """
        if header_pub == self._peer_pub:
            return
        shared = _dh(self._dh_private, header_pub)
        self._step_root_recv(shared)
        self._peer_pub = header_pub
        self._needs_rotation = True

    # -- symmetric chains ------------------------------------------------------

    def peek_send_key(self) -> bytes:
        """Derive the next sending message key WITHOUT consuming it."""
        return _gh(self.send_chain_key + b"msg", MSG_KEY_LEN)

    def advance_send_chain(self) -> None:
        """Consume one sending-chain step (call on commit)."""
        self.send_chain_key = _gh(self.send_chain_key + b"next")
        self.send_ctr += 1

    def rotate_for_send(self) -> None:
        """Perform the send-side DH rotation if one is pending."""
        if self._needs_rotation:
            new_private = PrivateKey.generate()
            shared = _dh(new_private, self._peer_pub)
            self._dh_private = new_private
            self._step_root_send(shared)
            self._needs_rotation = False

    def snapshot(self) -> dict:
        """Snapshot mutable ratchet state (for crash-before-commit restore)."""
        return {
            "root_key": self.root_key,
            "dh_private": bytes(self._dh_private),
            "peer_pub": self._peer_pub,
            "needs_rotation": self._needs_rotation,
            "send_chain_key": self.send_chain_key,
            "recv_chain_key": self.recv_chain_key,
            "send_ctr": self.send_ctr,
            "recv_ctr": self.recv_ctr,
        }

    def restore(self, snap: dict) -> None:
        self.root_key = snap["root_key"]
        self._dh_private = PrivateKey(snap["dh_private"])
        self._peer_pub = snap["peer_pub"]
        self._needs_rotation = snap["needs_rotation"]
        self.send_chain_key = snap["send_chain_key"]
        self.recv_chain_key = snap["recv_chain_key"]
        self.send_ctr = snap["send_ctr"]
        self.recv_ctr = snap["recv_ctr"]

    def next_send_key(self):
        """Return (message_key, header_pub) for the next sent message.

        Rotates the DH keypair first if a new peer key arrived since
        the last send (or on the responder's first send).
        """
        self.rotate_for_send()
        msg_key = self.peek_send_key()
        self.advance_send_chain()
        return msg_key, self.dh_public

    def peek_recv_key(self) -> bytes:
        """Derive the next receiving message key WITHOUT consuming it."""
        return _gh(self.recv_chain_key + b"msg", MSG_KEY_LEN)

    def advance_recv_chain(self) -> None:
        """Consume one receiving-chain step (call after a good decrypt)."""
        self.recv_chain_key = _gh(self.recv_chain_key + b"next")
        self.recv_ctr += 1
