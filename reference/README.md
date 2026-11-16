تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية

# SHC-Guard v0.6 — Reference Implementation

**Reference / تجريبي only. NOT audited, NOT production crypto. Do not use
to protect real data.**

State-guard layer (see `../DESIGN_FREEZE_v06.md`, the single source of
truth — it supersedes the v0.5 freeze in full): hybrid handshake
(Ed25519 + ML-DSA-65 identities, X25519 + ML-KEM-768), XChaCha20-Poly1305
AEAD with v0.6 AAD, rx/tx digest chains (SHA-512) with direction-specific
init values, signed split-epoch checkpoints with CP chaining and a
stand-in anchor, SUSPECT challenge protocol with per-direction challenge
tables and atomic commit, double journal + hw-bound state key (software
check only), outbox with caps, revocation-list check, TOFU +
out-of-band fingerprint gate, one-session policy with generation,
state machine (ACTIVE / SUSPECT / QUARANTINED / REKEYING / CLOSED).

**v0.6 is WIRE-INCOMPATIBLE with v0.5 by design**: labels v0.6, CP
format changed (split epochs, prev_cp_hash, anchor_head, generation),
position format changed. A v0.5 peer and a v0.6 peer MUST NOT
interoperate; the handshake rejects a peer offering v0.5.

## Run

```sh
# venv: /home/hatch/.venvs/shc-guard (Python 3.12.3)
# liboqs 0.16.0 is installed MINIMALLY at $HOME/_oqs (ML-KEM-768 +
# ML-DSA-65 only). No env vars needed:
/home/hatch/.venvs/shc-guard/bin/python -m pytest tests/ -q
/home/hatch/.venvs/shc-guard/bin/python demo.py --allow-level-b
/home/hatch/.venvs/shc-guard/bin/python demo.py --allow-level-b --suspect-demo
/home/hatch/.venvs/shc-guard/bin/python generate_vectors.py  # regen vectors/
```

## Layout

- `shc_guard/` — the package:
  `tlv.py` (canonical TLV), `common.py` (labels, SHA-512),
  `pq.py` (the ONLY module that touches liboqs — all PQ calls isolated
  here; raises `PQUnavailableError` if liboqs is missing),
  `identity.py` (records, fingerprints, TOFU TrustStore, rotation),
  `transcript.py`, `handshake.py` (generation, D-19 lifetime consumed
  IDs, v0.5 rejection), `ratchet.py`
  (MINIMAL DEMONSTRATION DH ratchet — NOT Signal, NOT Triple Ratchet),
  `aead.py` (v0.6 AAD: generation, tx_epoch, ack_rx_epoch),
  `chains.py` (direction-specific init values),
  `checkpoint.py` (split-epoch CP, prev_cp_hash chain, anchor-head
  extension, checkpoint-challenge domain separator),
  `anchor.py` (LocalAnchor — file-based, hash-chained, append-only
  STAND-IN log, separate file from session state),
  `suspect.py` (per-direction ChallengeTable, persisted consumed /
  superseded records, atomic-commit support),
  `journal.py` (double journal + SIMULATED counter + hw-bound state
  key: `derive_state_key` / `seal_state_record` / `unseal_state_record`),
  `outbox.py` (caps + `fail_all`), `revocation.py`,
  `session.py` (state machine + rules 1–7 + crash hooks +
  `SessionRegistry` one-session policy).
- `tests/` — pytest suite: the v0.5 suite (updated where v0.6
  deliberately changed behaviour — see below), plus
  `test_v06_adversarial.py` (AT-01…AT-12) and
  `test_v06_features.py` (anchor, TOFU, hw key, v0.5 rejection,
  rotation, challenge persistence).
- `vectors/` — deterministic TEST-ONLY vectors (JSON) generated from
  the code by `generate_vectors.py`, including the six new v0.6 files.
- `demo.py` — two-party end-to-end demo (fingerprint verification,
  anchor registration, generation shown, optional SUSPECT demo).
- `requirements.txt` — pinned versions.

## `--allow-level-b` (test-only)

guard_level B is an advisory self-signed claim, NOT hardware
attestation (freeze §7, Decision D-2). The reference defaults to Level
B because no hardware counter exists here; production policy MUST be
REJECT_B. The demo refuses to run without `--allow-level-b`.

## What changed vs v0.5

1. **Split epochs (§2):** send position `(tx_epoch, tx_ctr)` and
   receive position `(rx_epoch, rx_ctr)` advance independently. AAD is
   `(session_id, sender, generation, tx_epoch, tx_ctr, ack_rx_epoch,
   ack_ctr, ack_digest)`; the ack refers to MY receive position. CP
   verification compares `CP.rx_digest` against the local tx_digest at
   `(CP.rx_epoch, CP.rx_ctr_max)` — never the CP's tx_epoch.
2. **Direction-specific init values (§2):** init =
   `SHA-512(label || session_id || direction || sender || "init")`.
3. **New CP format (§2):** `generation, cp_seq, tx_epoch, tx_ctr,
   rx_epoch, rx_ctr_max, rx_digest, guard_level, prev_cp_hash,
   anchor_head, challenge_nonce`. CP chaining: a new CP is accepted
   only if `prev_cp_hash` equals the stored CP hash. Anchor-head
   extension: a new CP is accepted only if its `anchor_head` extends
   the stored head (checked against the LocalAnchor log, refreshed
   from disk before verification).
4. **LocalAnchor (§3):** file-based, hash-chained, append-only log in
   a SEPARATE file from session state; chain verified on load; a
   truncated/rewritten log is refused, never silently repaired
   (tail-truncation is detectable only against a stored tip — see
   Residuals). It is a STAND-IN, not a trusted third party.
   `anchor_head` in a CP is the head known when the CP was built (the
   previous entry); the CP hash is registered with the anchor BEFORE
   the CP-bearing message is sent, so the next CP's head includes it.
   This avoids a self-referential digest.
5. **One-session policy (§4):** `SessionRegistry` — one ACTIVE session
   per (user pair, device pair); generation increments per new
   session and is carried in the handshake, every AAD and every CP;
   messages/CPs from an older generation are rejected. Registering a
   new session atomically closes the old one (CLOSED + outbox
   fail-notify + best-effort key erasure) in the same call.
6. **TOFU + fingerprint gate (§5):** a new identity starts
   TRUSTED-UNVERIFIED; `Session.send_app` refuses until the peer
   fingerprint is verified out-of-band (`verify_peer_fingerprint`),
   unless the explicit test-only `allow_unverified` flag is passed.
   Identity rotation records (old signs new, new signs old
   fingerprint, version +1) and revocation fail-closed are in
   `identity.py` / `revocation.py`.
7. **Rule 4 revised (§6):** old position, no record → SUSPECT +
   challenge (was: silent reject + anomaly counter). Fork detection
   is GUARANTEED only inside the 1000-message window; outside it,
   detection runs through the challenge and is NOT guaranteed.
8. **Challenge lifecycle (§7):** one outstanding challenge per
   session PER DIRECTION (two independent tables: `issued` /
   `received`); `challenge_id` monotonic per session; issuing
   supersedes the old nonce explicitly (recorded as superseded);
   consumed records persist (serialised into the session snapshot /
   journal) and survive restart; late responses are rejected and the
   session stays QUARANTINED; challenge success (nonce consumption +
   CP storage + ACTIVE) is one journal write when a journal is
   configured, with a crash hook (`challenge:commit_before_write`)
   before it — a crash there leaves SUSPECT with the nonce NOT
   consumed. A retransmitted CP-bearing message whose first delivery
   crashed mid-commit is re-processed on replay (otherwise the
   session would strand in SUSPECT). The checkpoint-challenge label
   IS the domain separator: the canonical CP's label field is
   `checkpoint-challenge` when `challenge_nonce != 0`.
9. **hw-bound state key (§8):** `state_key =
   BLAKE2b-generichash(master_key, label || hw_ctr_at_save)` via
   libsodium; the record header carries `hw_at_save` in plaintext,
   authenticated as AAD. The send path verifies actual hw ==
   stored hw before deriving any message key; mismatch → refuse to
   send + QUARANTINED. This is a SOFTWARE check in the reference; a
   real TPM must enforce it in hardware (residual).
10. **D-19:** consumed handshake IDs are retained for the LIFETIME of
    the identity record (no 7-day purge). **D-20:** reorder-buffer
    overflow dropping the gap-bridging message (lowest buffered
    position) → SUSPECT + challenge. **D-21:** sends serialised by a
    single-writer lock; a second concurrent send is refused, never
    executed. **D-22:** a compromised signer presenting a false but
    well-signed CP is flagged `attestation-only, not
    device-integrity` (`Session.flag_attestation_only`), not rejected
    as "invalid device".

## v0.5 tests changed (deliberate freeze changes only)

| Test | Change | Reason |
|---|---|---|
| `test_chains_aead.test_chain_initial_value_matches_freeze` | Expected init now includes direction + sender | §2 direction-specific init |
| `test_chains_aead.test_aead_round_trip_and_aad_binding` | AAD constructor takes generation + split epochs | §2 new AAD |
| `test_checkpoint._cp` helper + CP constructions in `test_cp_rule_d`, `test_cp_digest_mismatch_*` | New CP fields (generation, tx_epoch, rx_epoch, prev_cp_hash, anchor_head) | §2 new CP format |
| `test_rules.test_rule4_old_position_no_record` | Now expects SUSPECT + challenge, not rejected | §6 revised rule 4 |
| `test_rules.test_buffer_overflow_drops_oldest_no_quarantine` → renamed `test_buffer_overflow_drops_gap_bridging_is_suspect` | Overflow dropping the gap-bridging message now enters SUSPECT | D-20 |
| `test_rules.test_rollback_below_checkpoint` | Regressed CP now carries `prev_cp_hash` of the stored CP | §2 CP chaining |
| `test_suspect.test_suspect_rolled_back_cp_fails_challenge` | Challenge-answer CP now carries `prev_cp_hash` of the stored CP | §2 CP chaining |
| `test_vectors.test_vector_checkpoint`, `test_vector_aead` | New CP/AAD fields asserted | §2 formats |
| `test_vectors` (transcript/handshake/chains/identity) | Regenerated vectors (v0.6 labels, generation field, new init) | §1/§2/§4 |

All other v0.5 tests pass unchanged.

## What was tested

- pytest suite (121 tests): the full v0.5 suite as updated above, plus
  AT-01…AT-12 and the v0.6 feature tests. AT-01 asserts the
  anchor-absent warning / non-detection (documents the residual, does
  not claim detection); AT-02 asserts SUSPECT+challenge outside the
  window; AT-11 asserts the degraded-mode warning with no false
  detection claim; AT-12 asserts the attestation-only flag.
  Vectors are recomputed from stored inputs, including the six new
  v0.6 vector files.
- Crash at every send/receive point plus the new
  `challenge:commit_before_write` point (AT-06).

## What was NOT tested

- No formal verification (no Tamarin/ProVerif run — see `../formal/`,
  owned by the coordinator).
- No real hardware counter (simulation only), no TPM attestation; the
  hw binding is a software check.
- No real external anchor / notary (LocalAnchor is a stand-in).
- No network transport, no persistence across process restarts beyond
  the journal unit tests (challenge-table serialisation is tested at
  the manager level).
- No side-channel, timing, or fault-attack resistance.
- The demonstration ratchet is NOT Signal and has NOT been audited.

## Known deviations from DESIGN_FREEZE_v06.md

1. **tx_digest label (§2, retained from v0.5):** the tx chain uses the
   same formula/label (`rx-chain`) as the peer's rx chain, because
   §2's own checks (CP.rx_digest == local tx_digest, rule 7) require
   the sender's tx_digest to EQUAL the peer's rx_digest over the same
   ciphertexts — impossible with different labels. See `chains.py`.
2. **ack_ctr / rx_ctr_max are COUNTS** (0 = none received), not
   0-based positions; the digest after N messages is the digest at
   position N−1 (initial digest when N=0). Documented in
   `session.py` / `checkpoint.py` (retained from v0.5).
3. **No skipped-key store:** out-of-order messages are buffered raw
   and decrypted in order; there is no separate skipped-keys table, so
   the "delete oldest skipped keys >1000" step is realised by the
   1000-message buffer cap instead (retained from v0.5).
4. **Rule-5/6/7 violating messages are not committed** (no digest
   advance, no delivery); the session transitions (SUSPECT /
   QUARANTINED) still apply (retained from v0.5).
5. **anchor_head semantics:** the freeze says a CP carries "the hash
   of the latest anchor-log entry known to the signer" and the signer
   registers the CP hash "BEFORE sending". Read literally together,
   that is self-referential (the registered hash would have to cover
   a head that includes itself). Interpretation implemented and
   documented in `session.py`: `anchor_head` is the head known when
   the CP was built (the previous entry); registration precedes the
   send, so the next CP's head includes this one. Chain continuity
   and monotonic extension still hold.
6. **Rekey epochs:** a rekey is session-wide and advances BOTH
   tx_epoch and rx_epoch together (it is not a per-direction DH
   ratchet step, which advances only one direction's epoch).
   Documented in `session.py::complete_rekey`.
7. **Atomic replacement (one journal write):** `SessionRegistry`
   performs close + fail-notify + key erasure in a single call; the
   new session's journal write is that call's persistence step when a
   journal is configured. There is no cross-process transaction
   manager in the reference.
8. **liboqs is a MINIMAL build** (0.16.0, ML-KEM-768 + ML-DSA-65
   only, installed at `$HOME/_oqs`): the full `pip install`
   auto-build failed on this VM (mqom compile error); only the two
   algorithms the freeze needs are present. `oqs.get_enabled_*`
   confirms exactly those two.

## Residuals (NOT claimed solved)

- **P0-1 external anchor still a stand-in:** simultaneous rollback of
  session state AND the anchor log together is UNDETECTED (AT-01).
  A tail-truncated anchor log is detectable only against a stored
  tip. Production needs a real external notary (RFC 3161 / transparency
  log) implementing the same interface.
- **First-trust UX:** TOFU verification is a manual out-of-band step;
  the reference only gates sending until it happens.
- **Fork detection outside the 1000-message window is NOT guaranteed**
  (AT-02); it runs through the challenge.
- **hw binding is software-only** (residual §8): a fully compromised
  device can bypass a software check.
- Header/AAD metadata leak (header encryption still open).
- Clock-sync assumption for the ±5 min handshake window (no NTP).
- Attacker dropping messages disables detection (declared limit).
- A CP proves consistency with available evidence only — never device
  integrity (D-22).
