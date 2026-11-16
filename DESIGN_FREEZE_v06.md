# SHC-Guard v0.6 — Design Freeze (تجميد قرارات التصميم)
# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
# This document FORMALLY REISSUES the design freeze. It supersedes
# workspace/shc-guard-v05/DESIGN_FREEZE.md in full (this answers ChatGPT's
# D-18 objection 4: no dual authority — this freeze is the single source).
# Source of the changes: ChatGPT's adversarial audit of v0.5 (2026-11-16,
# verdict REJECT), P0 items from its §10, recorded in
# workspace/shc-guard-v05/chatgpt-audit-v05.md.
# Date: 2026-11-16. Owner: Muse (sole owner per user instruction).

## 0. Scope and honesty rules (unchanged from v0.5)
- Language: Python 3.12, same venv /home/hatch/.venvs/shc-guard
  (PyNaCl 1.6.2; liboqs via the minimal build in ~/_oqs: ML-KEM-768 + ML-DSA-65 only).
- ONLY audited libraries for primitives: libsodium via PyNaCl, liboqs via
  liboqs-python, hashlib SHA-512 for H. No hand-written primitive.
- The lower-layer ratchet remains a minimal demonstration ratchet, NOT
  Signal / Triple Ratchet. Label it so everywhere.
- Every file starts with: «تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية».
- No security claims. README must have "tested / NOT tested" sections.
- **v0.6 is WIRE-INCOMPATIBLE with v0.5 by design**: labels v0.6, CP
  format changed (split epochs, prev_cp_hash, anchor_head, generation),
  position format changed. A v0.5 peer and a v0.6 peer MUST NOT
  interoperate; handshake rejects a peer offering v0.5 labels/records.
- Work directory: /home/hatch/workspace/shc-guard-v06/ (v0.5 untouched).

## 1. Labels
All labels are "SHC-Guard/v0.6/<name>": identity-fp, handshake-confirm,
rx-chain, state-encryption, device-binding, checkpoint,
checkpoint-challenge, anchor-entry. H = SHA-512. Canonical TLV encoding
as in v0.5 (type 1B || len 4B BE || value, fixed field order).

## 2. P0-2 — Split epochs (ChatGPT CP-02; the highest-value fix)
- A message position is now TWO positions: send position
  (tx_epoch, tx_ctr) and receive position (rx_epoch, rx_ctr).
  tx_ctr starts at 0 in each tx_epoch; rx_ctr starts at 0 in each rx_epoch.
  Epochs advance independently per direction (a DH ratchet step in one
  direction advances only that direction's epoch).
- CP fields, in order: label, session_id, device_id, generation (u64),
  cp_seq (u64), tx_epoch (u64), tx_ctr (u64), rx_epoch (u64),
  rx_ctr_max (u64), rx_digest (64B), guard_level (1B),
  prev_cp_hash (64B; SHA-512 of the previous CP's canonical bytes, or
  64 zero bytes for the first CP), anchor_head (64B; hash of the latest
  anchor-log entry, §3), challenge_nonce (32B; zero unless answering).
- rx_digest chain is keyed by (rx_epoch, rx_ctr); tx_digest chain by
  (tx_epoch, tx_ctr). Update formula unchanged except the epoch field
  is now the direction's own epoch.
- Direction-specific init values (ChatGPT D-18 objection 2):
  init = SHA-512(label "SHC-Guard/v0.6/rx-chain" || session_id ||
  direction || sender_device_id || "init"). Direction and sender are in
  the init value, not only in the first update.
- AAD = canonical encoding of (session_id, sender_device_id, generation,
  tx_epoch, tx_ctr, ack_rx_epoch, ack_ctr, ack_digest).
- ack = (ack_rx_epoch, ack_ctr, ack_digest): the ack refers to MY receive
  position (which equals the peer's send position for that stream).
  CP verification compares CP.rx_digest against local tx_digest at
  (CP.rx_epoch, CP.rx_ctr_max) — the epoch used is the CP's rx_epoch,
  never the CP's tx_epoch.
- A CP whose (tx_epoch, tx_ctr) does not equal the carrying message's
  send position is rejected.

## 3. P0-1 — External anchor (ChatGPT F-01/CP-01; PARTIAL — residual open)
- Anchor interface (defined in spec, implemented in code):
  register(cp_hash) -> signed receipt {anchor_seq, cp_hash, signature};
  get_latest(user_id) -> latest receipt or none.
  The anchor is append-only: entries are hash-chained
  (entry_hash = SHA-512(label "SHC-Guard/v0.6/anchor-entry" ||
  prev_entry_hash || cp_hash || anchor_seq)), each signed by the anchor.
- Reference implementation: LocalAnchor — a file-based, hash-chained,
  append-only log stored SEPARATELY from the session state file
  (different file, verified as a chain on load; a truncated or rewritten
  log is refused, never silently repaired). It is a STAND-IN, not a
  trusted third party: an attacker who can roll back the session state
  AND the anchor log together defeats it. That limit is stated in the
  spec, README and REPORT — P0-1 is NOT claimed solved.
- Production requirement (stated, not implemented): a real external
  notary — RFC 3161 timestamping authority or a transparency log —
  implementing the same interface. Until one is plugged in, simultaneous
  rollback of both parties remains UNDETECTED (residual, §14).
- Each CP carries anchor_head (hash of the latest anchor entry known to
  the signer). The peer stores the partner's latest anchor_head and
  prev_cp_hash; a new CP is accepted only if its prev_cp_hash equals the
  stored CP hash (chain continuity, CP-03) AND its anchor_head extends
  the stored anchor head (its chain contains it). A CP that does not
  extend the stored head → SUSPECT + challenge.
- On every CP (≤50 msgs / 24h) the signer registers the CP hash with
  the anchor BEFORE sending the CP-bearing message.

## 4. P0-3 — Session policy (ChatGPT U-02)
- ONE active session per (user_id pair, device_id pair). Generation
  (u64) increments with every new session for the same pair; generation
  is carried in the handshake, every message's AAD, and every CP.
  Messages/CPs from an older generation are rejected.
- New handshake acceptance ATOMICALLY closes the old session: the same
  double-journal write that saves the new session marks the old session
  CLOSED, fails-notifies the app for the old outbox entries, and erases
  the old session's keys (best-effort overwrite + delete). There is no
  moment when two sessions for the same pair are both ACTIVE.
- A peer receiving a new handshake while a session is ACTIVE accepts it
  only as a replacement under this rule (old → CLOSED first), never as
  a second concurrent session.

## 5. P0-4 — First trust root (ChatGPT U-01; DECIDED, not left open)
- Root DECIDED: TOFU + mandatory out-of-band fingerprint verification.
  A new identity record starts as TRUSTED-UNVERIFIED. The session may
  be established, but the app MUST display "unverified identity" and
  the reference Session MUST NOT send application messages until the
  fingerprint is verified out-of-band (in person / second channel) and
  marked verified — unless the caller passes an explicit test-only
  allow_unverified flag. The demo verifies fingerprints through the
  test harness before sending.
- Identity rotation: signed rotation record — old keys sign the new
  record, new keys sign the old fingerprint; version increments;
  highest-version pinning (v0.5 §13.6) retained; revocation list as in
  v0.5 (signed, freshness ≤24h, fail-closed).

## 6. P0-5 — Fork outside the retention window (ChatGPT F-02)
- Rule 4 REVISED: a message at a position older than the window with no
  retained record → SUSPECT + checkpoint challenge (NOT a silent reject
  + anomaly counter). Challenge success requires the CP content check
  to cover that position; if the CP history cannot cover it →
  QUARANTINED. The anomaly counter is still incremented.
- The claim is restated honestly: fork detection is GUARANTEED only
  inside the 1000-message window; outside it, detection runs through
  the challenge and is NOT guaranteed. Tests assert the non-guarantee
  (AT-02): the implementation must not claim detection it cannot do.

## 7. P0-6 — SUSPECT challenge lifecycle (ChatGPT CH-01/CH-04)
- One outstanding challenge per session PER DIRECTION (two independent
  challenge tables). Fields: challenge_id (u64, monotonic per session),
  nonce (32B), issued_at, status (pending/consumed/expired/superseded).
- Issuing a new challenge SUPERSEDES the old one explicitly: the old
  nonce is invalidated and recorded as superseded; a response carrying
  a superseded or expired nonce is rejected.
- A nonce is CONSUMED on first successful verification; the consumed
  record is persisted in the journal (survives restart). A response
  arriving after the deadline (60s or 20 valid messages) is rejected
  and the session stays QUARANTINED — no late acceptance.
- ATOMIC COMMIT: challenge success (nonce consumption + CP storage +
  anchor registration + transition to ACTIVE) happens in ONE
  double-journal write. On crash mid-commit, boot recovers to SUSPECT
  with the challenge still pending (nonce NOT consumed) or to ACTIVE
  with the proof stored — never ACTIVE without proof.
- Unified processing order for a CP-bearing message during SUSPECT
  (same code path as §6.3 verification — no special bypass):
  AEAD verify → rules 1–4 → CP verify (signatures, cp_seq, prev hash,
  anchor head, content vs tx_digest) → nonce match against the
  outstanding challenge → atomic commit. A CP that fails any step is
  rejected; the challenge is NOT satisfied by a merely well-signed CP.
- CH-02 resolved by definition: the checkpoint-challenge label IS the
  domain separator of the CP signature when answering a challenge —
  signed bytes = label ‖ canonical CP, where label is
  "SHC-Guard/v0.6/checkpoint" normally and
  "SHC-Guard/v0.6/checkpoint-challenge" when challenge_nonce != 0.

## 8. P0-7 — Hardware-counter binding (ChatGPT CL-01)
- The state record's AEAD key is derived from the counter value:
  state_key = BLAKE2b-generichash(master_key,
  "SHC-Guard/v0.6/state-encryption" ‖ hw_ctr_at_save) via libsodium.
  The record header carries hw_at_save in plaintext, authenticated as
  AAD of the record AEAD (tampering with the header fails verification).
- Boot: read header hw_at_save, derive the key, verify the AEAD, then
  apply the 4-case table comparing header hw vs actual hw counter.
- Send path: before deriving any message key, verify actual hw ==
  stored hw; mismatch → refuse to send + QUARANTINED.
- Limit (stated): this binds the state file and the send operation to
  the counter value in the reference's software check; a real TPM must
  enforce the check in hardware. A fully compromised device can bypass
  a software check — residual, §14.

## 9. Other decisions (v0.6 decision log continues: D-19…)
- D-19: consumed handshake IDs are retained for the LIFETIME of the
  identity record (not 7 days) — AT-08 (replayed transcript after 7
  days) must be rejected by permanent state, not by the clock. Storage
  cost is accepted; the change from v0.5 §13.6 is a security choice.
- D-20: if the reorder buffer drops the message that would complete
  the contiguous prefix (overflow), the session enters SUSPECT +
  challenge instead of stalling silently (AT-09).
- D-21: sends are serialized by a single-writer lock on the session
  state (threading.Lock in the reference); a second concurrent send
  with the same counter is refused, never executed (AT-10).
- D-22: a compromised signer presenting a false but well-signed CP is
  NOT rejected as "invalid device" — the session is flagged
  "attestation-only, not device-integrity" and the app is told the
  check proves consistency with available evidence only (AT-12).
  No false claim of device integrity is made.
- Unified CP verification: one function used by both the §6.3 path and
  the §7.2 challenge path (ChatGPT §7 contradiction).

## 10. Tests (extend v0.5 suite; keep all 87 passing unless a v0.5
##     behaviour was deliberately changed — then update the test and log it)
- New adversarial tests AT-01…AT-12 (ChatGPT §11), each mapped to its
  finding: AT-01 both-parties rollback → test asserts the anchor-absent
  warning / non-detection (documents the residual, does not claim
  detection); AT-02 fork outside window → SUSPECT+challenge path;
  AT-03 tx_epoch/rx_epoch mismatch → reject; AT-04 stale CP after CP
  loss → SUSPECT/QUARANTINED; AT-05 concurrent challenges, nonces not
  cross-accepted; AT-06 crash between challenge commit and ACTIVE →
  SUSPECT-with-proof-pending or ACTIVE-with-proof, never ACTIVE
  without proof; AT-07 new session while old ACTIVE → old CLOSED
  atomically; AT-08 transcript replay after 7 days → rejected;
  AT-09 buffer overflow drops the gap-bridging message → SUSPECT;
  AT-10 concurrent sends, same counter → second refused; AT-11
  rollback with peer's CPs lost → degraded-mode warning surfaced, no
  false detection claim; AT-12 compromised signer, false CP → flagged
  attestation-only.
- New test vectors (JSON, TEST-ONLY) for: split-epoch CP, prev_cp_hash
  chain, anchor entry/receipt, direction-specific init values,
  generation in AAD, challenge table persistence.

## 11. Formal model
- Update shc_guard.spthy to split epochs, CP chaining, challenge
  lifecycle, generation. FIRST try a BOUNDED-session variant (≤2
  sessions, small message counts) and attempt at least one lemma on
  this machine; if it still does not finish, state NOT machine-checked
  again with the exact runtimes. Never present an unrun model as verified.

## 12. Deliverables and layout (workspace/shc-guard-v06/)
- DESIGN_FREEZE_v06.md (this file) at the top; spec/SHC-Guard-v0.6.md
  (integrated §§1–14 + Decision Log D-19…, supersedes v0.5 in full);
  reference/ (updated package + demo + requirements); reference/tests/
  + reference/vectors/; formal/shc_guard.spthy (+ README note);
  README.md; REPORT.md (done / failed / needs-human-review, with
  explicit residual list: P0-1 external anchor still a stand-in,
  first-trust UX, Tamarin status).
- Every file header: «تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية».
