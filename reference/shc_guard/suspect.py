# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""SUSPECT challenge protocol (freeze v0.6 SS6/SS7).

- Deadline: 60 seconds OR 20 valid messages, whichever first.
- During SUSPECT: receive + challenge only, no application sending.
- Challenge: control plaintext type 0x03 containing a 32-byte nonce
  from libsodium randombytes.
- Response: a checkpoint control message (type 0x02) whose CP carries
  that nonce in challenge_nonce.
- Success requires ALL of: signatures valid, cp_seq > last stored,
  nonce matches, CP tx_ctr/rx_ctr_max do not regress below the last
  stored CP, CP.rx_digest matches local tx_digest at claimed
  (rx_epoch, rx_ctr_max), and CP (tx_epoch, tx_ctr) equals the
  carrying message position. Success -> ACTIVE. Failure or timeout ->
  QUARANTINED. Three SUSPECT episodes within 24h -> QUARANTINED.
- A SUSPECT challenge answered by a merely well-signed CP over a
  rolled-back state (without the content checks above) is a FAILURE.

Challenge lifecycle (SS7):
- ONE outstanding challenge per session PER DIRECTION: two
  independent challenge tables ("issued" -- challenges I issued to
  the peer, which the peer must answer; "received" -- challenges the
  peer issued to me, which I must answer). A nonce issued in one
  direction is NEVER accepted in the other.
- Fields per challenge: challenge_id (u64, monotonic per session),
  nonce (32B), issued_at, status (pending/consumed/expired/superseded).
- Issuing a new challenge SUPERSEDES the old one explicitly: the old
  nonce is invalidated and recorded as superseded; a response carrying
  a superseded or expired nonce is rejected.
- A nonce is CONSUMED on first successful verification; the consumed
  record is persisted (serialize()/restore() -- the session journal
  stores it, so it survives restart). A response arriving after the
  deadline (60s or 20 valid messages) is rejected and the session
  stays QUARANTINED -- no late acceptance.
- ATOMIC COMMIT: challenge success (nonce consumption + CP storage +
  anchor registration + transition to ACTIVE) happens in ONE
  double-journal write in the session; see Session._handle_checkpoint.
  On crash mid-commit, boot recovers to SUSPECT with the challenge
  still pending (nonce NOT consumed) or to ACTIVE with the proof
  stored -- never ACTIVE without proof.

Reference / تجريبي only.
"""

import time
from dataclasses import dataclass, field

from . import pq
from .checkpoint import ZERO_NONCE

CHALLENGE_DEADLINE_S = 60
CHALLENGE_DEADLINE_MESSAGES = 20
MAX_EPISODES_24H = 3
EPISODE_WINDOW_S = 24 * 3600

DIRECTION_ISSUED = "issued"    # challenges I issued to the peer
DIRECTION_RECEIVED = "received"  # challenges the peer issued to me


@dataclass
class ChallengeRecord:
    challenge_id: int
    nonce: bytes
    issued_at: float
    status: str = "pending"  # pending | consumed | expired | superseded
    direction: str = DIRECTION_ISSUED

    def as_dict(self):
        return {"challenge_id": self.challenge_id,
                "nonce": self.nonce.hex(),
                "issued_at": self.issued_at,
                "status": self.status,
                "direction": self.direction}


class ChallengeTable:
    """One direction's challenge table: one outstanding challenge.

    Consumed and superseded records are retained (persisted via
    serialize()/restore()) so a replayed or superseded nonce can never
    be accepted again, even after restart.
    """

    def __init__(self, direction: str, clock=time.time):
        self.direction = direction
        self.clock = clock
        self._next_id = 1
        self._outstanding = None  # ChallengeRecord or None
        self.consumed = {}  # nonce bytes -> ChallengeRecord
        self.superseded = {}  # nonce bytes -> ChallengeRecord
        self.expired = {}  # nonce bytes -> ChallengeRecord

    def issue(self) -> ChallengeRecord:
        """Issue a new challenge, superseding the outstanding one."""
        if self._outstanding is not None:
            old = self._outstanding
            old.status = "superseded"
            self.superseded[old.nonce] = old
        rec = ChallengeRecord(challenge_id=self._next_id,
                              nonce=pq.random_bytes(32),
                              issued_at=self.clock(),
                              direction=self.direction)
        self._next_id += 1
        self._outstanding = rec
        return rec

    def record_received(self, nonce: bytes) -> ChallengeRecord:
        """Record a challenge nonce the PEER issued to me (received
        over the wire). It becomes this direction's outstanding
        challenge; answering it consumes it here."""
        if self._outstanding is not None:
            old = self._outstanding
            old.status = "superseded"
            self.superseded[old.nonce] = old
        rec = ChallengeRecord(challenge_id=self._next_id, nonce=nonce,
                              issued_at=self.clock(),
                              direction=self.direction)
        self._next_id += 1
        self._outstanding = rec
        return rec

    @property
    def outstanding(self):
        return self._outstanding

    @property
    def outstanding_nonce(self):
        return self._outstanding.nonce if self._outstanding else None

    def consume(self, nonce: bytes):
        """Consume the outstanding nonce on success. Returns the record
        or None if the nonce is not the outstanding one."""
        if self._outstanding is None or self._outstanding.nonce != nonce:
            return None
        rec = self._outstanding
        rec.status = "consumed"
        self.consumed[nonce] = rec
        self._outstanding = None
        return rec

    def is_consumed(self, nonce: bytes) -> bool:
        return nonce in self.consumed

    def is_superseded(self, nonce: bytes) -> bool:
        return nonce in self.superseded

    def is_expired(self, nonce: bytes) -> bool:
        return nonce in self.expired

    def expire_outstanding(self, reason: str = "deadline"):
        if self._outstanding is not None:
            rec = self._outstanding
            rec.status = "expired"
            self.expired[rec.nonce] = rec
            self._outstanding = None
            return rec
        return None

    def serialize(self):
        return {"direction": self.direction, "next_id": self._next_id,
                "outstanding": (self._outstanding.as_dict()
                                if self._outstanding else None),
                "consumed": [r.as_dict() for r in self.consumed.values()],
                "superseded": [r.as_dict()
                               for r in self.superseded.values()],
                "expired": [r.as_dict() for r in self.expired.values()]}

    @classmethod
    def restore(cls, data, clock=time.time):
        tbl = cls(data["direction"], clock=clock)
        tbl._next_id = int(data["next_id"])
        for key in ("consumed", "superseded", "expired"):
            store = getattr(tbl, key)
            for d in data.get(key, []):
                rec = ChallengeRecord(
                    challenge_id=int(d["challenge_id"]),
                    nonce=bytes.fromhex(d["nonce"]),
                    issued_at=float(d["issued_at"]),
                    status=d["status"], direction=d["direction"])
                store[rec.nonce] = rec
        if data.get("outstanding"):
            d = data["outstanding"]
            tbl._outstanding = ChallengeRecord(
                challenge_id=int(d["challenge_id"]),
                nonce=bytes.fromhex(d["nonce"]),
                issued_at=float(d["issued_at"]),
                status=d["status"], direction=d["direction"])
        return tbl


@dataclass
class SuspectState:
    active: bool = False
    nonce: bytes = b""
    started_at: float = 0.0
    messages_seen: int = 0
    reason: str = ""
    episodes: list = field(default_factory=list)  # start timestamps (24h window)

    def episodes_in_24h(self, now: float = None) -> int:
        now = time.time() if now is None else now
        self.episodes = [t for t in self.episodes
                         if now - t < EPISODE_WINDOW_S]
        return len(self.episodes)


class SuspectManager:
    """Tracks SUSPECT episodes and the per-direction challenge tables."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.state = SuspectState()
        self.tables = {
            DIRECTION_ISSUED: ChallengeTable(DIRECTION_ISSUED, clock=clock),
            DIRECTION_RECEIVED: ChallengeTable(DIRECTION_RECEIVED,
                                               clock=clock),
        }

    # -- episode bookkeeping ---------------------------------------------------

    def enter_suspect(self, reason: str):
        """Record a new SUSPECT episode. Returns True if the 3-in-24h
        limit is hit (caller must then go QUARANTINED instead)."""
        now = self.clock()
        self.state.episodes.append(now)
        self.state.active = True
        self.state.started_at = now
        self.state.messages_seen = 0
        self.state.reason = reason
        self.state.nonce = b""
        return self.state.episodes_in_24h(now) >= MAX_EPISODES_24H

    def issue_challenge(self, direction: str = DIRECTION_ISSUED) -> bytes:
        """Create a 32-byte challenge nonce (type 0x03 payload).

        Issuing supersedes any outstanding challenge in the SAME
        direction only; the other direction's challenge is untouched.
        """
        rec = self.tables[direction].issue()
        if direction == DIRECTION_ISSUED:
            self.state.nonce = rec.nonce
        return rec.nonce

    @property
    def outstanding_nonce(self):
        return self.tables[DIRECTION_ISSUED].outstanding_nonce

    def outstanding_nonce_for(self, direction: str):
        return self.tables[direction].outstanding_nonce

    def note_valid_message(self) -> None:
        if self.state.active:
            self.state.messages_seen += 1

    def deadline_exceeded(self) -> bool:
        if not self.state.active:
            return False
        now = self.clock()
        if now - self.state.started_at >= CHALLENGE_DEADLINE_S:
            return True
        return self.state.messages_seen >= CHALLENGE_DEADLINE_MESSAGES

    def expire_challenge(self, direction: str = DIRECTION_ISSUED):
        """Mark the outstanding challenge in ``direction`` expired."""
        return self.tables[direction].expire_outstanding()

    # -- response evaluation ---------------------------------------------------

    def check_response(self, cp, cp_verification_ok: bool,
                       last_stored_cp, direction: str = DIRECTION_ISSUED):
        """Evaluate a challenge response CP.

        ``cp_verification_ok`` is the result of checkpoint.verify_checkpoint
        rules (a)-(g). ``last_stored_cp`` is the last stored CP from that
        peer (None if none). Returns (success: bool, reason: str).

        Success requires ALL freeze criteria; in particular a
        well-signed CP over rolled-back state FAILS, a superseded or
        already-consumed nonce FAILS, and a nonce from the OTHER
        direction FAILS (cross-direction nonces are never accepted).
        """
        if not self.state.active:
            return False, "no challenge outstanding"
        if not cp_verification_ok:
            return False, "checkpoint verification failed"
        table = self.tables[direction]
        nonce = getattr(cp, "challenge_nonce", ZERO_NONCE)
        if nonce == ZERO_NONCE:
            return False, "challenge nonce missing"
        if table.is_consumed(nonce):
            return False, "challenge nonce already consumed"
        if table.is_superseded(nonce):
            return False, "challenge nonce superseded"
        if table.is_expired(nonce):
            return False, "challenge nonce expired"
        if nonce != table.outstanding_nonce:
            return False, "challenge nonce mismatch"
        if last_stored_cp is not None:
            if getattr(cp, "tx_ctr", 0) < getattr(last_stored_cp, "tx_ctr", 0):
                return False, "tx_ctr regressed below last stored CP"
            if getattr(cp, "rx_ctr_max", 0) < getattr(
                    last_stored_cp, "rx_ctr_max", 0):
                return False, "rx_ctr_max regressed below last stored CP"
            if getattr(cp, "rx_epoch", 0) < getattr(
                    last_stored_cp, "rx_epoch", 0):
                return False, "rx_epoch regressed below last stored CP"
        return True, "challenge satisfied"

    def consume_challenge(self, nonce: bytes,
                          direction: str = DIRECTION_ISSUED):
        """Consume the outstanding nonce (atomic-commit step)."""
        return self.tables[direction].consume(nonce)

    def resolve_success(self, direction: str = DIRECTION_ISSUED) -> None:
        # Kept for back-compat: consumes the outstanding nonce in
        # ``direction`` (if any) and clears the SUSPECT state.
        if self.tables[direction].outstanding_nonce is not None:
            self.tables[direction].consume(
                self.tables[direction].outstanding_nonce)
        self.state.active = False
        self.state.nonce = b""
        self.state.messages_seen = 0

    def resolve_failure(self) -> None:
        self.state.active = False
        self.state.nonce = b""
        self.state.messages_seen = 0

    # -- persistence -----------------------------------------------------------

    def serialize(self):
        return {"episodes": list(self.state.episodes),
                "tables": {d: t.serialize() for d, t in self.tables.items()}}

    @classmethod
    def restore(cls, data, clock=time.time):
        mgr = cls(clock=clock)
        mgr.state.episodes = list(data.get("episodes", []))
        for d, tdata in data.get("tables", {}).items():
            if d in mgr.tables:
                mgr.tables[d] = ChallengeTable.restore(tdata, clock=clock)
        return mgr
