# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Deterministic test-vector generator (TEST-ONLY keys, fixed seeds).

Writes JSON vectors under reference/vectors/:
  identity_fingerprint.json, transcript.json, checkpoint.json,
  chains.json, aead.json, handshake.json

ML-KEM-768 encapsulation is randomised in liboqs, and ML-DSA-65
keygen has NO seed API in liboqs-python 0.16 (only the KEM exposes
generate_keypair_seed) — so "deterministic" here means: FIXED stored
inputs → fixed recorded outputs. The generator stores the randomly
generated TEST-ONLY keys/ciphertext in the vector files, and the test
suite recomputes every derived value from those stored inputs and
asserts equality. Nothing here is a production key.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nacl.public import PrivateKey  # noqa: E402

from shc_guard import aead, pq  # noqa: E402
from shc_guard.aead import AAD  # noqa: E402
from shc_guard.chains import (  # noqa: E402
    DIRECTION_A_TO_B, make_rx_chain, make_tx_chain,
)
from shc_guard.anchor import LocalAnchor  # noqa: E402
from shc_guard.checkpoint import Checkpoint, pack_signed_checkpoint  # noqa: E402
from shc_guard.suspect import ChallengeTable  # noqa: E402
from shc_guard.common import H  # noqa: E402
from shc_guard.handshake import (  # noqa: E402
    ConsumedHandshakeIDs, initiator_confirm, initiator_finish,
    initiator_start, responder_finish, responder_reply,
)
from shc_guard.identity import Identity  # noqa: E402
from shc_guard.revocation import RevocationChecker, generate_test_operator  # noqa: E402
from shc_guard.transcript import Transcript  # noqa: E402

VECTORS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "vectors")

DISCLAIMER = "تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية"


def _write(name, obj):
    obj = {"_disclaimer": DISCLAIMER + " — TEST-ONLY vectors", **obj}
    path = os.path.join(VECTORS_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
    print("wrote", path)


def main():
    assert pq.is_available(), "liboqs unavailable — cannot generate vectors"
    os.makedirs(VECTORS_DIR, exist_ok=True)

    # ---- fixed TEST-ONLY identities ---------------------------------------
    ed_seed_a = bytes(range(32))
    ed_seed_b = bytes([0xFF - i for i in range(32)])
    mldsa_pk_a, mldsa_sk_a = pq.sig_keypair()
    mldsa_pk_b, mldsa_sk_b = pq.sig_keypair()
    alice = Identity.from_ed_seed("alice", b"A" * 32, ed_seed_a,
                                  mldsa_pk_a, mldsa_sk_a)
    bob = Identity.from_ed_seed("bob", b"B" * 32, ed_seed_b,
                                mldsa_pk_b, mldsa_sk_b)

    _write("identity_fingerprint.json", {
        "user_id": "alice",
        "device_id": (b"A" * 32).hex(),
        "record_version": 1,
        "ed_seed": ed_seed_a.hex(),
        "ed_public_key": alice.ed_public_key.hex(),
        "mldsa_public_key": mldsa_pk_a.hex(),
        "mldsa_secret_key": mldsa_sk_a.hex(),
        "guard_level": 0x42,
        "canonical_record": alice.canonical_record().hex(),
        "fingerprint": alice.fingerprint().hex(),
    })

    # ---- deterministic handshake (fixed ephemerals / ids / nonces) ---------
    clock_now = int(time.time())
    op_sk, op_list = generate_test_operator()
    from nacl.signing import VerifyKey
    checker = RevocationChecker(VerifyKey(bytes(op_sk.verify_key)), op_list)
    consumed = ConsumedHandshakeIDs()
    eph_a = PrivateKey(bytes([0x11] * 32))
    eph_b = PrivateKey(bytes([0x22] * 32))
    offer, pend_a = initiator_start(
        alice, eph_private=eph_a, handshake_id=b"H" * 32,
        nonce=b"N" * 32, timestamp=clock_now)
    reply, pend_b = responder_reply(
        offer, bob, checker, consumed, eph_private=eph_b,
        nonce=b"M" * 32)
    finish, mat_a = initiator_finish(reply, pend_a, checker, consumed)
    confirm, mat_b = responder_finish(finish, pend_b, consumed)
    initiator_confirm(confirm, mat_a)

    _write("handshake.json", {
        "version": "SHC-Guard/v0.6",
        "generation": mat_a.generation,
        "handshake_id": (b"H" * 32).hex(),
        "initiator_eph_seed": bytes([0x11] * 32).hex(),
        "responder_eph_seed": bytes([0x22] * 32).hex(),
        "initiator_nonce": (b"N" * 32).hex(),
        "responder_nonce": (b"M" * 32).hex(),
        "timestamp": clock_now,
        "kem_public_key": mat_a.transcript.kem_public_key.hex(),
        "kem_ciphertext": mat_a.transcript.kem_ciphertext.hex(),
        "kem_shared_secret": mat_a.shared_secret[32:].hex(),
        "x25519_shared_secret": mat_a.shared_secret[:32].hex(),
        "transcript": mat_a.transcript_bytes.hex(),
        "transcript_digest": mat_a.transcript.digest().hex(),
        "session_id": mat_a.session_id.hex(),
        "root_key": mat_a.root_key.hex(),
        "key_confirmation_mac_initiator": finish["key_confirmation_mac"].hex(),
        "key_confirmation_mac_responder": confirm["key_confirmation_mac"].hex(),
        "initiator_ed_sig": finish["ed_sig"].hex(),
        "initiator_mldsa_sig": finish["mldsa_sig"].hex(),
    })

    _write("transcript.json", {
        "canonical": mat_a.transcript_bytes.hex(),
        "digest": mat_a.transcript.digest().hex(),
        "parsed_handshake_id": Transcript.parse(
            mat_a.transcript_bytes).handshake_id.hex(),
        "guard_level": mat_a.transcript.guard_level,
        "timestamp": mat_a.transcript.timestamp,
    })

    # ---- checkpoint ---------------------------------------------------------
    cp = Checkpoint(session_id=mat_a.session_id, device_id=b"A" * 32,
                    generation=1, cp_seq=7, tx_epoch=0, tx_ctr=41,
                    rx_epoch=0, rx_ctr_max=40,
                    rx_digest=bytes(range(64)), guard_level=0x42,
                    prev_cp_hash=bytes(range(64)),
                    anchor_head=bytes([0xAB] * 64))
    blob = cp.sign(alice)
    _write("checkpoint.json", {
        "session_id": mat_a.session_id.hex(),
        "device_id": (b"A" * 32).hex(),
        "cp_seq": 7, "generation": 1, "tx_epoch": 0, "tx_ctr": 41,
        "rx_epoch": 0, "rx_ctr_max": 40,
        "prev_cp_hash": bytes(range(64)).hex(),
        "anchor_head": bytes([0xAB] * 64).hex(),
        "rx_digest": bytes(range(64)).hex(),
        "guard_level": 0x42,
        "challenge_nonce": (bytes(32)).hex(),
        "canonical": cp.canonical().hex(),
        "digest": cp.digest().hex(),
        "packed": pack_signed_checkpoint(cp, blob).hex(),
        "ed_sig": blob[:64].hex(),
        "mldsa_sig": blob[68:].hex(),
        "verifies": cp.verify_signatures(alice.record(), blob),
    })

    # ---- chains ---------------------------------------------------------------
    sid = mat_a.session_id
    cts = [("ciphertext-%d" % i).encode() for i in range(5)]
    rx = make_rx_chain(sid, b"A" * 32, DIRECTION_A_TO_B)
    tx = make_tx_chain(sid, b"A" * 32, DIRECTION_A_TO_B)
    steps = []
    for i, ct in enumerate(cts):
        rx.advance(0, i, ct)
        tx.advance(0, i, ct)
        steps.append({"ctr": i, "ciphertext": ct.hex(),
                      "ciphertext_sha512": H(ct).hex(),
                      "rx_digest": rx.digest.hex(),
                      "tx_digest": tx.digest.hex()})
    _write("chains.json", {
        "session_id": sid.hex(),
        "sender_device_id": (b"A" * 32).hex(),
        "direction": DIRECTION_A_TO_B,
        "initial_rx_digest": rx.initial_digest.hex(),
        "initial_tx_digest": tx.initial_digest.hex(),
        "steps": steps,
    })

    # ---- AEAD -----------------------------------------------------------------
    key = bytes(range(32))
    nonce = bytes(range(24))
    aad = AAD(sid, b"A" * 32, 1, 0, 3, 0, 2, bytes(range(64)))
    pt = b"vector plaintext"
    ct = aead.encrypt(key, nonce, pt, aad)
    _write("aead.json", {
        "generation": 1, "tx_epoch": 0, "tx_ctr": 3, "ack_rx_epoch": 0,
        "key": key.hex(), "nonce": nonce.hex(),
        "aad_canonical": aad.canonical().hex(),
        "session_id": sid.hex(),
        "plaintext": pt.hex(),
        "ciphertext": ct.hex(),
        "decrypts": aead.decrypt(key, nonce, ct, aad) == pt,
    })
    # ---- v0.6 new vectors ---------------------------------------------------
    import tempfile

    # Split-epoch CP: tx_epoch and rx_epoch differ; digest is checked
    # against the tx_digest at (rx_epoch, rx_ctr_max).
    cp2 = Checkpoint(session_id=sid, device_id=b"A" * 32, generation=3,
                     cp_seq=4, tx_epoch=2, tx_ctr=9, rx_epoch=5,
                     rx_ctr_max=7, rx_digest=bytes(range(64)),
                     guard_level=0x42, prev_cp_hash=bytes([0x11] * 64),
                     anchor_head=bytes([0x22] * 64))
    blob2 = cp2.sign(alice)
    _write("split_epoch_cp.json", {
        "generation": 3, "cp_seq": 4, "tx_epoch": 2, "tx_ctr": 9,
        "rx_epoch": 5, "rx_ctr_max": 7,
        "prev_cp_hash": bytes([0x11] * 64).hex(),
        "anchor_head": bytes([0x22] * 64).hex(),
        "canonical": cp2.canonical().hex(),
        "digest": cp2.digest().hex(),
        "packed": pack_signed_checkpoint(cp2, blob2).hex(),
        "verifies": cp2.verify_signatures(alice.record(), blob2),
    })

    # prev_cp_hash chain: three CPs, each chained from the previous.
    chain = []
    prev = bytes(64)
    for i in range(1, 4):
        cpi = Checkpoint(session_id=sid, device_id=b"A" * 32, generation=1,
                         cp_seq=i, tx_epoch=0, tx_ctr=i * 10, rx_epoch=0,
                         rx_ctr_max=i, rx_digest=bytes([i] * 64),
                         guard_level=0x42, prev_cp_hash=prev)
        chain.append({"cp_seq": i, "tx_ctr": i * 10,
                      "prev_cp_hash": prev.hex(),
                      "canonical": cpi.canonical().hex(),
                      "digest": cpi.digest().hex()})
        prev = cpi.digest()
    _write("prev_cp_hash_chain.json", {"cps": chain})

    # Anchor entry/receipt: three CP hashes registered in a stand-in log.
    with tempfile.TemporaryDirectory() as td:
        anchor = LocalAnchor(os.path.join(td, "anchor.log"))
        receipts = []
        for i, h in enumerate([bytes([0x31] * 64), bytes([0x32] * 64),
                               bytes([0x33] * 64)], start=1):
            r = anchor.register(h)
            receipts.append({"anchor_seq": r.anchor_seq,
                             "cp_hash": r.cp_hash.hex(),
                             "entry_hash": r.entry_hash.hex(),
                             "signature": r.signature.hex(),
                             "verifies": anchor.verify_receipt(r)})
        _write("anchor.json", {
            "anchor_public_key": anchor.public_key.hex(),
            "head": anchor.head.hex(), "entries": len(anchor),
            "receipts": receipts})

    # Direction-specific init values.
    from shc_guard.chains import DIRECTION_B_TO_A
    _write("direction_init.json", {
        "session_id": sid.hex(), "sender_device_id": (b"A" * 32).hex(),
        "a_to_b": make_rx_chain(sid, b"A" * 32,
                                DIRECTION_A_TO_B).initial_digest.hex(),
        "b_to_a": make_rx_chain(sid, b"A" * 32,
                                DIRECTION_B_TO_A).initial_digest.hex(),
        "a_to_b_other_sender": make_rx_chain(
            sid, b"B" * 32, DIRECTION_A_TO_B).initial_digest.hex(),
    })

    # Generation in AAD: same fields, different generation -> different AAD.
    aad1 = AAD(sid, b"A" * 32, 1, 0, 3, 0, 2, bytes(range(64)))
    aad2 = AAD(sid, b"A" * 32, 2, 0, 3, 0, 2, bytes(range(64)))
    _write("generation_aad.json", {
        "generation_1": aad1.canonical().hex(),
        "generation_2": aad2.canonical().hex(),
    })

    # Challenge table persistence: issue, supersede, consume, serialize.
    tbl = ChallengeTable("issued", clock=lambda: 1000.0)
    n1 = tbl.issue().nonce
    n2 = tbl.issue().nonce  # supersedes n1
    tbl.consume(n2)
    _write("challenge_table.json", {
        "first_nonce": n1.hex(), "second_nonce": n2.hex(),
        "first_superseded": tbl.is_superseded(n1),
        "second_consumed": tbl.is_consumed(n2),
        "serialized": tbl.serialize(),
    })
    print("vector generation done")


if __name__ == "__main__":
    main()
