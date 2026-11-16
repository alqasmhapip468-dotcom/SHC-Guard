# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""XChaCha20-Poly1305 AEAD with v0.6 SS2 AAD.

AAD = canonical TLV encoding of
  (session_id, sender_device_id, generation, tx_epoch, tx_ctr,
   ack_rx_epoch, ack_ctr, ack_digest).
generation is carried in every message's AAD (freeze SS4); the ack
refers to MY receive position (ack_rx_epoch), which equals the peer's
send position for that stream (freeze SS2).

AAD fields are PLAINTEXT (metadata leak) -- UNRESOLVED (v0.5 SS10.6
still open). Reference / تجريبي only.
"""

from dataclasses import dataclass

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.utils import random as _random

from .common import u64
from .tlv import decode_expected, encode_fields

NONCE_LEN = 24
KEY_LEN = 32

# TLV field types for the AAD (fixed order).
A_SESSION_ID = 0x01
A_SENDER_DEVICE_ID = 0x02
A_GENERATION = 0x03
A_TX_EPOCH = 0x04
A_TX_CTR = 0x05
A_ACK_RX_EPOCH = 0x06
A_ACK_CTR = 0x07
A_ACK_DIGEST = 0x08


@dataclass(frozen=True)
class AAD:
    session_id: bytes  # 32 bytes
    sender_device_id: bytes  # 32 bytes
    generation: int  # u64
    tx_epoch: int
    tx_ctr: int
    ack_rx_epoch: int
    ack_ctr: int
    ack_digest: bytes  # 64 bytes (SHA-512)

    # Back-compat aliases for the v0.5 field names used in old call sites.
    @property
    def epoch(self) -> int:
        return self.tx_epoch

    @property
    def ack_epoch(self) -> int:
        return self.ack_rx_epoch

    def canonical(self) -> bytes:
        return encode_fields([
            (A_SESSION_ID, self.session_id),
            (A_SENDER_DEVICE_ID, self.sender_device_id),
            (A_GENERATION, u64(self.generation)),
            (A_TX_EPOCH, u64(self.tx_epoch)),
            (A_TX_CTR, u64(self.tx_ctr)),
            (A_ACK_RX_EPOCH, u64(self.ack_rx_epoch)),
            (A_ACK_CTR, u64(self.ack_ctr)),
            (A_ACK_DIGEST, self.ack_digest),
        ])

    @classmethod
    def parse(cls, data: bytes) -> "AAD":
        from .common import u64_decode

        f = decode_expected(data, [A_SESSION_ID, A_SENDER_DEVICE_ID,
                                   A_GENERATION, A_TX_EPOCH, A_TX_CTR,
                                   A_ACK_RX_EPOCH, A_ACK_CTR, A_ACK_DIGEST])
        return cls(
            session_id=f[A_SESSION_ID],
            sender_device_id=f[A_SENDER_DEVICE_ID],
            generation=u64_decode(f[A_GENERATION]),
            tx_epoch=u64_decode(f[A_TX_EPOCH]),
            tx_ctr=u64_decode(f[A_TX_CTR]),
            ack_rx_epoch=u64_decode(f[A_ACK_RX_EPOCH]),
            ack_ctr=u64_decode(f[A_ACK_CTR]),
            ack_digest=f[A_ACK_DIGEST])


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: AAD) -> bytes:
    """XChaCha20-Poly1305 encrypt. nonce must be 24 fresh random bytes."""
    if len(key) != KEY_LEN:
        raise ValueError("AEAD key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError("AEAD nonce must be 24 bytes")
    return crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad.canonical(), nonce, key)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: AAD) -> bytes:
    """XChaCha20-Poly1305 decrypt. Raises on any authentication failure."""
    if len(key) != KEY_LEN:
        raise ValueError("AEAD key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError("AEAD nonce must be 24 bytes")
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, aad.canonical(), nonce, key)


def fresh_nonce() -> bytes:
    return _random(NONCE_LEN)
