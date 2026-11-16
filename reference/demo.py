# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""SHC-Guard v0.6 demo — full two-party session end to end.

  handshake (generation 1) -> out-of-band fingerprint verification
  -> messages both directions -> checkpoint (registered with the
  stand-in anchor BEFORE sending) -> (optional) SUSPECT challenge
  demo.

Usage (from reference/):
  /home/hatch/.venvs/shc-guard/bin/python demo.py [--allow-level-b]
                                                  [--suspect-demo]

--allow-level-b is TEST-ONLY: it permits guard_level B (no hardware).
Production policy MUST be REJECT_B (freeze §7, Decision D-2). The demo
refuses to run without the flag and says so loudly.

The anchor here is LocalAnchor, a STAND-IN file log, not a trusted
third party (freeze §3, residual P0-1). Both parties share one
stand-in log file in this demo only.

Reference / تجريبي only — NOT audited, NOT production crypto.
"""

import argparse
import sys
import tempfile
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from shc_guard import pq  # noqa: E402
from shc_guard.anchor import LocalAnchor  # noqa: E402
from shc_guard.handshake import (  # noqa: E402
    ConsumedHandshakeIDs, initiator_confirm, initiator_finish,
    initiator_start, responder_finish, responder_reply,
)
from shc_guard.identity import Identity  # noqa: E402
from shc_guard.revocation import (  # noqa: E402
    RevocationChecker, generate_test_operator,
)
from shc_guard.session import (  # noqa: E402
    STATE_ACTIVE, STATE_SUSPECT, Session,
)


def build_pair(allow_level_b: bool, anchor=None):
    """Run the hybrid handshake for two fresh identities.

    Returns (session_a, session_b). Fingerprints are verified
    out-of-band (freeze §5) BEFORE any application message is sent:
    the demo prints both fingerprints and compares them, standing in
    for the user comparing them in person / on a second channel.
    """
    if not pq.is_available():
        raise SystemExit("liboqs unavailable — cannot run the demo "
                         "(see pq.PQUnavailableError)")
    alice = Identity.generate("alice", pq.random_bytes(32))
    bob = Identity.generate("bob", pq.random_bytes(32))
    op_sk, op_list = generate_test_operator()
    from nacl.signing import VerifyKey

    checker_a = RevocationChecker(VerifyKey(bytes(op_sk.verify_key)), op_list)
    checker_b = RevocationChecker(VerifyKey(bytes(op_sk.verify_key)), op_list)
    consumed = ConsumedHandshakeIDs()

    offer, pend_a = initiator_start(alice, allow_level_b=allow_level_b)
    reply, pend_b = responder_reply(offer, bob, checker_b, consumed,
                                    allow_level_b=allow_level_b)
    finish, mat_a = initiator_finish(reply, pend_a, checker_a, consumed)
    confirm, mat_b = responder_finish(finish, pend_b, consumed)
    initiator_confirm(confirm, mat_a)

    sess_a = Session(mat_a, consumed_ids=consumed, anchor=anchor)
    sess_b = Session(mat_b, consumed_ids=consumed, anchor=anchor)
    sess_a.save()  # handshake_id recorded as consumed ONLY after save
    sess_b.save()

    print("fingerprints (verify out-of-band before sending):")
    fp_a = alice.fingerprint().hex()
    fp_b = bob.fingerprint().hex()
    print("  alice:", fp_a[:32] + "…")
    print("  bob:  ", fp_b[:32] + "…")
    assert sess_a.verify_peer_fingerprint(fp_b)
    assert sess_b.verify_peer_fingerprint(fp_a)
    print("  both fingerprints verified -> peer VERIFIED (TOFU, freeze §5)")
    return sess_a, sess_b


def exchange(a: Session, b: Session, text_a: str, text_b: str):
    w = a.send_app(text_a.encode())
    print("  A→B:", b.receive(w)["status"], "| B got:", b.delivered[-1])
    w = b.send_app(text_b.encode())
    print("  B→A:", a.receive(w)["status"], "| A got:", a.delivered[-1])


def main() -> int:
    ap = argparse.ArgumentParser(description="SHC-Guard v0.6 demo (تجريبي)")
    ap.add_argument("--allow-level-b", action="store_true",
                    help="TEST-ONLY: allow guard_level B (no hardware)")
    ap.add_argument("--suspect-demo", action="store_true",
                    help="also demonstrate a SUSPECT challenge round-trip")
    args = ap.parse_args()

    print("SHC-Guard v0.6 demo — تجريبي، غير مدقق، لا يُستخدم لحماية "
          "بيانات حقيقية")
    if not args.allow_level_b:
        print("REFUSED: guard_level B requires --allow-level-b (test-only).")
        print("Production policy MUST be REJECT_B (freeze §7, D-2).")
        return 2
    print("WARNING: --allow-level-b given (test-only). Level B is an "
          "advisory claim, NOT hardware attestation.")

    with tempfile.TemporaryDirectory() as td:
        anchor = LocalAnchor(td + "/anchor.log")
        t0 = time.time()
        a, b = build_pair(allow_level_b=True, anchor=anchor)
        print(f"handshake done in {time.time() - t0:.2f}s; "
              f"session {a.session_id.hex()[:16]}…; generation={a.generation}; "
              f"tx_epoch A={a.tx_epoch} rx_epoch B={b.rx_epoch}; "
              f"state A={a.state} B={b.state}")

        print("messages:")
        exchange(a, b, "hello from A", "hello from B")
        exchange(a, b, "second from A", "second from B")

        print("checkpoint (A→B, registered with the anchor first):")
        w = a.send_checkpoint()
        print("  B:", b.receive(w))
        print("  anchor entries:", len(anchor),
              "| head:", anchor.head.hex()[:16] + "…")

        if args.suspect_demo:
            print("SUSPECT demo: B enters SUSPECT (gap) and A answers "
                  "the challenge with a CP")
            b._enter_suspect("demo")
            print("  B state:", b.state, "| challenge issued")
            chal = b.pending_challenge_wire
            print("  A receives challenge:", a.receive(chal)["status"])
            resp = a.respond_to_challenge()
            print("  B receives response:", b.receive(resp))
            print("  B state after challenge:", b.state)
            assert b.state == STATE_ACTIVE, \
                "challenge should resolve to ACTIVE"

        print("final: A=%s B=%s | delivered A=%d B=%d | anchor entries=%d" % (
            a.state, b.state, len(a.delivered), len(b.delivered),
            len(anchor)))
    print("demo OK (reference only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
