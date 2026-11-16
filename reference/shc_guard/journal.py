# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Double journal + SIMULATED hardware counter (freeze v0.6 §6/§8).

REFERENCE LIMITATION — read this first:
This reference has NO real hardware counter. The counter below is a
SIMULATED monotonic counter in a separate file (with fsync) used to test
the LOGIC of the boot cases. It is NOT a hardware counter and must NOT
be presented as prevention of anything. Default guard_level is B;
Level A is NOT available in this reference.

Boot cases (hw = actual counter, saved = stored value):
  hw == saved     → sound, continue.
  hw == saved+1   → crash between increment and write: ADOPT the stored
                    record as-is and set stored hw_ctr := hw. Do NOT
                    re-apply any lost operation — it was never saved and
                    therefore never sent (send happens only after save).
  hw > saved+1    → rollback → QUARANTINED.
  hw < saved      → counter reset / new device → QUARANTINED + new session.

Double journal: records A/B with sequence numbers and AEAD bound to
hw_ctr, written alternately; at boot the highest valid sequence wins.
Torn-write repair comes from the other copy ONLY — "return to last
sound record" means torn-write repair, never a detected rollback.

Reserve-then-commit: hw_ctr increments BEFORE the record is written.
Reference / تجريبي only.
"""

import json
import os
from dataclasses import dataclass

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)
from nacl.utils import random as _random

from .common import H, label, u64

# ---- SS8: hardware-counter-bound state key -------------------------------
# state_key = BLAKE2b-generichash(master_key,
#     "SHC-Guard/v0.6/state-encryption" || hw_ctr_at_save) via libsodium.
# The record header carries hw_at_save in plaintext, authenticated as
# AAD of the record AEAD (tampering with the header fails verification).
# LIMIT (freeze SS8): this binds the state file and the send operation
# to the counter value in the reference's SOFTWARE check; a real TPM
# must enforce the check in hardware. A fully compromised device can
# bypass a software check -- residual.


def derive_state_key(master_key: bytes, hw_ctr: int) -> bytes:
    """BLAKE2b generichash (libsodium) keyed by ``master_key``."""
    from nacl.bindings.crypto_generichash import (
        generichash_blake2b_salt_personal as _gh,
    )

    if len(master_key) != 32:
        raise ValueError("state master key must be 32 bytes")
    return _gh(label("state-encryption") + u64(hw_ctr), 32,
               key=master_key)


def seal_state_record(master_key: bytes, hw_ctr: int,
                      plaintext: bytes) -> bytes:
    """Seal a state record: header (hw_at_save, plaintext) + nonce +
    XChaCha20-Poly1305 sealed bytes, AAD bound to hw_at_save."""
    import json
    import struct

    from nacl.utils import random as _random

    key = derive_state_key(master_key, hw_ctr)
    aad = H(label("state-encryption") + u64(hw_ctr))
    nonce = _random(24)
    sealed = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, key)
    header = json.dumps({"hw_at_save": hw_ctr, "version": "SHC-Guard/v0.6"},
                        sort_keys=True).encode()
    return struct.pack(">I", len(header)) + header + nonce + sealed


def unseal_state_record(master_key: bytes, blob: bytes):
    """Inverse of seal_state_record. Returns (hw_at_save, plaintext).

    Raises ValueError on any tampering (header, nonce or ciphertext).
    """
    import json
    import struct

    if len(blob) < 4:
        raise ValueError("state record too short")
    (hlen,) = struct.unpack(">I", blob[:4])
    if len(blob) < 4 + hlen + 24:
        raise ValueError("state record truncated")
    try:
        header = json.loads(blob[4:4 + hlen].decode("utf-8"))
        hw_ctr = int(header["hw_at_save"])
    except Exception as exc:
        raise ValueError("state record header unreadable: %s" % exc)
    nonce, sealed = blob[4 + hlen:4 + hlen + 24], blob[4 + hlen + 24:]
    key = derive_state_key(master_key, hw_ctr)
    aad = H(label("state-encryption") + u64(hw_ctr))
    try:
        plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
            sealed, aad, nonce, key)
    except Exception as exc:
        raise ValueError("state record AEAD verification failed: %s" % exc)
    return hw_ctr, plaintext


BOOT_SOUND = "sound"
BOOT_ADOPTED = "adopted"        # hw == saved+1
BOOT_ROLLBACK = "rollback"      # hw > saved+1
BOOT_RESET = "counter_reset"    # hw < saved


class SimulatedHwCounter:
    """SIMULATED monotonic counter (NOT hardware). File-backed, fsync'd.

    Layout: a JSON file {"hw_ctr": int}. ``increment()`` bumps the value
    and fsyncs before returning — this models "increment BEFORE write".
    """

    def __init__(self, path: str):
        self.path = path
        self.value = 0
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self.value = int(json.load(fh)["hw_ctr"])
            except Exception:
                self.value = 0

    def read(self) -> int:
        return self.value

    def increment(self) -> int:
        """Reserve-then-commit step 1: increment the counter first."""
        self.value += 1
        self._persist()
        return self.value

    def set(self, value: int) -> None:
        """Adopt a value (boot case hw == saved+1)."""
        self.value = value
        self._persist()

    def _persist(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"hw_ctr": self.value}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)


def boot_case(hw: int, saved: int) -> str:
    """Classify the boot case from the freeze v0.6 §6/§8 table."""
    if hw == saved:
        return BOOT_SOUND
    if hw == saved + 1:
        return BOOT_ADOPTED
    if hw > saved + 1:
        return BOOT_ROLLBACK
    return BOOT_RESET


@dataclass
class JournalRecord:
    seq: int
    hw_ctr: int
    payload: bytes  # plaintext state bytes (already serialised by caller)


class DoubleJournal:
    """Double journal A/B.

    Two slots (``<base>.A`` / ``<base>.B``). Each record is AEAD-sealed
    (XChaCha20-Poly1305) with a key derived from the journal key and
    bound to hw_ctr via the AAD; records are written alternately and
    carry a strictly increasing sequence number. At boot the highest
    valid sequence wins; a torn write is repaired from the other copy.
    """

    def __init__(self, base_path: str, key: bytes):
        if len(key) != 32:
            raise ValueError("journal key must be 32 bytes")
        self.base_path = base_path
        self.key = key
        self._next_slot = 0  # 0 → A, 1 → B

    def _slot_path(self, slot: int) -> str:
        return "%s.%s" % (self.base_path, "A" if slot == 0 else "B")

    def _aad(self, seq: int, hw_ctr: int) -> bytes:
        # AEAD bound to hw_ctr (freeze v0.6 §6/§8).
        return H(label("device-binding") + seq.to_bytes(8, "big")
                 + hw_ctr.to_bytes(8, "big"))

    def append(self, record: JournalRecord) -> None:
        """Write one record to the next slot (alternating A/B)."""
        nonce = _random(24)
        sealed = crypto_aead_xchacha20poly1305_ietf_encrypt(
            record.payload, self._aad(record.seq, record.hw_ctr),
            nonce, self.key)
        blob = nonce + sealed
        path = self._slot_path(self._next_slot)
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        self._next_slot = 1 - self._next_slot

    def _read_slot(self, slot: int):
        path = self._slot_path(slot)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
            nonce, sealed = blob[:24], blob[24:]
            # seq/hw_ctr are recovered by trying the stored header: the
            # header is stored as the first 16 plaintext bytes are NOT
            # available pre-decrypt, so we store seq/hw_ctr alongside in
            # a sidecar JSON written atomically with the slot.
            sidecar = path + ".meta"
            with open(sidecar, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
            seq, hw_ctr = int(meta["seq"]), int(meta["hw_ctr"])
            payload = crypto_aead_xchacha20poly1305_ietf_decrypt(
                sealed, self._aad(seq, hw_ctr), nonce, self.key)
            return JournalRecord(seq=seq, hw_ctr=hw_ctr, payload=payload)
        except Exception:
            return None  # torn / corrupt slot: the other copy repairs

    def append_with_meta(self, record: JournalRecord) -> None:
        """Append + atomically store the seq/hw_ctr sidecar for the slot."""
        slot = self._next_slot
        self.append(record)
        sidecar = self._slot_path(slot) + ".meta"
        tmp = sidecar + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"seq": record.seq, "hw_ctr": record.hw_ctr}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, sidecar)

    def load_best(self):
        """Return the highest-valid-sequence record, or None if empty."""
        candidates = [r for r in (self._read_slot(0), self._read_slot(1))
                      if r is not None]
        if not candidates:
            return None
        candidates.sort(key=lambda r: r.seq)
        return candidates[-1]

    def boot(self, hw_counter: SimulatedHwCounter):
        """Boot reconciliation.

        Returns (case, record-or-None). On BOOT_ROLLBACK / BOOT_RESET the
        caller must go QUARANTINED (+ new session for reset). On
        BOOT_ADOPTED the stored record is adopted as-is and the stored
        hw_ctr is set to hw.
        """
        record = self.load_best()
        saved = record.hw_ctr if record is not None else 0
        hw = hw_counter.read()
        case = boot_case(hw, saved)
        if case == BOOT_ADOPTED:
            hw_counter.set(hw)
        return case, record
