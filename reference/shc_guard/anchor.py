# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""LocalAnchor -- file-based, hash-chained, append-only anchor log
(freeze v0.6 SS3).

STAND-IN, NOT a trusted third party. This is a LOCAL log in a file
SEPARATE from the session state file. An attacker who can roll back
the session state AND the anchor log together defeats it. That limit
is stated in the freeze, README and REPORT -- P0-1 is NOT claimed
solved. Production requirement (stated, not implemented): a real
external notary -- RFC 3161 timestamping authority or a transparency
log -- implementing the same interface.

Interface (freeze SS3):
  register(cp_hash) -> signed receipt {anchor_seq, cp_hash, signature}
  get_latest(user_id) -> latest receipt or none.

Entries are hash-chained:
  entry_hash = SHA-512(label "SHC-Guard/v0.6/anchor-entry" ||
      prev_entry_hash || cp_hash || anchor_seq)
Each entry is signed by the anchor (Ed25519, test/stand-in key).

Load rules: the chain is verified on load. A truncated or rewritten
log is REFUSED (AnchorCorruptError), never silently repaired.
Truncation of the tail is detectable only against a stored tip:
load(expected_head=...) refuses a head that does not match the tip
the caller stored in session state; without a stored tip, a
tail-truncated log that is still internally consistent cannot be
distinguished from a shorter honest log -- that is part of the
stand-in residual, documented here and in the README.

Reference / تجريبي only.
"""

import json
import os

from nacl.signing import SigningKey, VerifyKey

from .common import H, label, u64, u64_decode


class AnchorCorruptError(ValueError):
    """The anchor log failed chain verification (truncated/rewritten)."""


class AnchorReceipt:
    """A signed receipt for one registered CP hash."""

    def __init__(self, anchor_seq: int, cp_hash: bytes, entry_hash: bytes,
                 signature: bytes):
        self.anchor_seq = anchor_seq
        self.cp_hash = cp_hash
        self.entry_hash = entry_hash
        self.signature = signature

    def as_dict(self):
        return {"anchor_seq": self.anchor_seq,
                "cp_hash": self.cp_hash.hex(),
                "entry_hash": self.entry_hash.hex(),
                "signature": self.signature.hex()}


def entry_hash(prev_entry_hash: bytes, cp_hash: bytes, anchor_seq: int) -> bytes:
    return H(label("anchor-entry") + prev_entry_hash + cp_hash
             + u64(anchor_seq))


class LocalAnchor:
    """File-based, hash-chained, append-only anchor log (STAND-IN).

    File format: line 1 is a JSON header {"anchor_public_key": hex};
    each following line is one JSON entry:
    {"anchor_seq": int, "cp_hash": hex, "prev_entry_hash": hex,
     "entry_hash": hex, "signature": hex}.
    The log file MUST be a different file from the session state file.
    """

    def __init__(self, path: str, signing_key: SigningKey = None,
                 expected_head: bytes = None):
        self.path = path
        self._entries = []  # list of dicts, in seq order
        self._signing_key = signing_key
        if os.path.exists(path):
            self._load(expected_head=expected_head)
        else:
            if signing_key is None:
                self._signing_key = SigningKey.generate()
            self._write_header()

    # -- persistence ---------------------------------------------------------

    def _write_header(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(
                {"anchor_public_key":
                 bytes(self._signing_key.verify_key).hex()}) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)

    def _load(self, expected_head: bytes = None):
        with open(self.path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        if not lines:
            raise AnchorCorruptError("anchor log is empty (no header)")
        try:
            header = json.loads(lines[0])
            self._verify_key = VerifyKey(bytes.fromhex(
                header["anchor_public_key"]))
        except Exception as exc:
            raise AnchorCorruptError("anchor header unreadable: %s" % exc)
        if self._signing_key is None:
            self._signing_key = None  # read-only handle: cannot register
        prev = bytes(64)
        entries = []
        for i, line in enumerate(lines[1:], start=1):
            try:
                e = json.loads(line)
                seq = int(e["anchor_seq"])
                cp_hash = bytes.fromhex(e["cp_hash"])
                prev_hash = bytes.fromhex(e["prev_entry_hash"])
                ehash = bytes.fromhex(e["entry_hash"])
                sig = bytes.fromhex(e["signature"])
            except Exception as exc:
                raise AnchorCorruptError(
                    "anchor entry %d unreadable: %s" % (i, exc))
            if seq != i:
                raise AnchorCorruptError(
                    "anchor entry %d has non-contiguous seq %d "
                    "(truncated/rewritten log refused)" % (i, seq))
            if prev_hash != prev:
                raise AnchorCorruptError(
                    "anchor entry %d breaks the hash chain "
                    "(rewritten log refused)" % i)
            if entry_hash(prev, cp_hash, seq) != ehash:
                raise AnchorCorruptError(
                    "anchor entry %d hash mismatch (rewritten log refused)" % i)
            try:
                self._verify_key.verify(ehash, sig)
            except Exception:
                raise AnchorCorruptError(
                    "anchor entry %d signature invalid" % i)
            entries.append(e)
            prev = ehash
        self._entries = entries
        if expected_head is not None and self.head != expected_head:
            raise AnchorCorruptError(
                "anchor head does not match the stored tip "
                "(truncated/rewritten log refused)")

    def refresh(self):
        """Re-read the log file from disk (verifying the chain).

        A peer registering a CP appends to the shared file after we
        loaded it; refresh before an anchor-head extension check.
        Raises AnchorCorruptError on a truncated/rewritten log.
        """
        if os.path.exists(self.path):
            key = self._signing_key
            self._load()
            if key is not None:
                self._signing_key = key

    # -- interface -----------------------------------------------------------

    @property
    def head(self) -> bytes:
        """Hash of the latest anchor entry, or 64 zero bytes if empty."""
        if not self._entries:
            return bytes(64)
        return bytes.fromhex(self._entries[-1]["entry_hash"])

    @property
    def public_key(self) -> bytes:
        return bytes(self._verify_key) if hasattr(self, "_verify_key") \
            else bytes(self._signing_key.verify_key)

    def register(self, cp_hash: bytes) -> AnchorReceipt:
        """Append one CP hash; returns the signed receipt."""
        if self._signing_key is None:
            raise AnchorCorruptError(
                "anchor opened read-only (no signing key) -- cannot register")
        if len(cp_hash) != 64:
            raise ValueError("cp_hash must be 64 bytes (SHA-512)")
        seq = len(self._entries) + 1
        prev = self.head
        ehash = entry_hash(prev, cp_hash, seq)
        sig = bytes(self._signing_key.sign(ehash).signature)
        entry = {"anchor_seq": seq, "cp_hash": cp_hash.hex(),
                 "prev_entry_hash": prev.hex(), "entry_hash": ehash.hex(),
                 "signature": sig.hex()}
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._entries.append(entry)
        return AnchorReceipt(seq, cp_hash, ehash, sig)

    def get_latest(self, user_id=None):
        """Latest receipt, or None. ``user_id`` is accepted for the
        freeze SS3 interface shape; this stand-in keeps one global log
        and ignores it."""
        if not self._entries:
            return None
        e = self._entries[-1]
        return AnchorReceipt(int(e["anchor_seq"]),
                             bytes.fromhex(e["cp_hash"]),
                             bytes.fromhex(e["entry_hash"]),
                             bytes.fromhex(e["signature"]))

    def verify_receipt(self, receipt: AnchorReceipt) -> bool:
        """Verify a receipt's signature against the anchor public key."""
        try:
            vk = self._verify_key if hasattr(self, "_verify_key") \
                else self._signing_key.verify_key
            vk.verify(receipt.entry_hash, receipt.signature)
            return True
        except Exception:
            return False

    def contains(self, head: bytes) -> bool:
        """True iff ``head`` is an entry hash in this log (or zero)."""
        if head == bytes(64):
            return True
        return any(bytes.fromhex(e["entry_hash"]) == head
                   for e in self._entries)

    def extends(self, stored_head: bytes, new_head: bytes) -> bool:
        """True iff ``new_head``'s chain contains ``stored_head``.

        A new CP is accepted only if its anchor_head extends the stored
        anchor head (SS3). Zero stored head (no anchor entry known yet)
        accepts anything; zero new head accepts only a zero stored head.
        """
        if stored_head == bytes(64):
            # No anchor entry known yet: accept only a head that is
            # actually in this log (or zero), never arbitrary bytes.
            if new_head == bytes(64):
                return True
            return any(bytes.fromhex(e["entry_hash"]) == new_head
                       for e in self._entries)
        if new_head == bytes(64):
            return False
        hashes = [bytes.fromhex(e["entry_hash"]) for e in self._entries]
        if new_head not in hashes:
            # The new head is not in THIS log: it may come from a log
            # the anchor has since extended beyond what we loaded, or
            # from another log entirely. Without the anchor's full
            # history we cannot prove extension -- refuse, do not guess.
            # (A caller that reloads the anchor first will see it.)
            return False
        if stored_head not in hashes:
            return False
        return hashes.index(stored_head) <= hashes.index(new_head)

    def __len__(self):
        return len(self._entries)
