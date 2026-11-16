# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Outbox with caps (freeze §6).

Cap: 500 messages OR 7 days. When an entry exceeds either bound it is
DELETED and the application is notified of the failure. This BOUNDS
the resend guarantee — the bound is the resolution, recorded in the
freeze. Retransmission resends the SAME ciphertext (no key reuse:
the message key is never re-derived and the ciphertext is never
re-encrypted).

Reference / تجريبي only.
"""

import time
from dataclasses import dataclass, field

MAX_OUTBOX_MESSAGES = 500
MAX_OUTBOX_AGE_S = 7 * 24 * 3600


@dataclass
class OutboxEntry:
    position: tuple  # (epoch, tx_ctr)
    ciphertext: bytes
    nonce: bytes
    aad_bytes: bytes
    header_bytes: bytes
    enqueued_at: float = field(default_factory=time.time)
    attempts: int = 0


class Outbox:
    """Bounded resend queue. ``notify`` is called as notify(event, entry)
    for ``expired`` / ``dropped_overflow`` events."""

    def __init__(self, notify=None, clock=time.time):
        self.entries = {}  # position -> OutboxEntry
        self.notify = notify or (lambda event, entry: None)
        self.clock = clock

    def __len__(self):
        return len(self.entries)

    def enqueue(self, entry: OutboxEntry) -> None:
        self.expire()
        if len(self.entries) >= MAX_OUTBOX_MESSAGES:
            oldest = min(self.entries.values(), key=lambda e: e.enqueued_at)
            del self.entries[oldest.position]
            self.notify("dropped_overflow", oldest)
        self.entries[entry.position] = entry

    def acked_through(self, epoch: int, ctr: int) -> None:
        """Drop every entry at or below the acknowledged position."""
        for pos in [p for p in self.entries
                    if p[0] < epoch or (p[0] == epoch and p[1] <= ctr)]:
            del self.entries[pos]

    def expire(self) -> list:
        """Delete entries older than 7 days; notify the app per entry.

        Returns the expired entries.
        """
        now = self.clock()
        expired = [e for e in self.entries.values()
                   if now - e.enqueued_at > MAX_OUTBOX_AGE_S]
        for e in expired:
            del self.entries[e.position]
            self.notify("expired", e)
        return expired

    def fail_all(self):
        """Fail-notify the app for every queued entry and clear the
        queue (SS4 atomic replacement: the old session's outbox is
        failed, not silently dropped)."""
        for e in list(self.entries.values()):
            self.notify("failed", e)
        self.entries.clear()

    def resend_all(self):
        """Return entries to resend, oldest first.

        The SAME ciphertext/nonce is returned — no re-encryption, no
        key reuse. ``attempts`` is incremented per resend round.
        """
        ordered = sorted(self.entries.values(), key=lambda e: e.position)
        for e in ordered:
            e.attempts += 1
        return ordered
