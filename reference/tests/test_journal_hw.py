# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""Hardware-counter boot cases (freeze §6) + double journal tests.

The counter is a SIMULATION (file-backed, fsync'd) — NOT hardware.
"""
import json
import os

import pytest

from shc_guard.journal import (
    BOOT_ADOPTED, BOOT_RESET, BOOT_ROLLBACK, BOOT_SOUND,
    DoubleJournal, JournalRecord, SimulatedHwCounter, boot_case,
)


def test_boot_case_table():
    assert boot_case(5, 5) == BOOT_SOUND
    assert boot_case(6, 5) == BOOT_ADOPTED
    assert boot_case(7, 5) == BOOT_ROLLBACK
    assert boot_case(100, 5) == BOOT_ROLLBACK
    assert boot_case(4, 5) == BOOT_RESET
    assert boot_case(0, 5) == BOOT_RESET


def _write_journal(tmp_path, key, seq, hw_ctr, payload=b"state"):
    j = DoubleJournal(str(tmp_path / "j"), key)
    j.append_with_meta(JournalRecord(seq=seq, hw_ctr=hw_ctr,
                                     payload=payload))
    return j


def _set_counter(tmp_path, value):
    with open(str(tmp_path / "hw.json"), "w") as fh:
        json.dump({"hw_ctr": value}, fh)


def test_boot_sound_hw_eq_saved(tmp_path):
    key = b"K" * 32
    _write_journal(tmp_path, key, seq=1, hw_ctr=5)
    _set_counter(tmp_path, 5)
    j = DoubleJournal(str(tmp_path / "j"), key)
    hw = SimulatedHwCounter(str(tmp_path / "hw.json"))
    case, rec = j.boot(hw)
    assert case == BOOT_SOUND
    assert rec.payload == b"state"
    assert hw.read() == 5


def test_boot_adopted_hw_eq_saved_plus_1(tmp_path):
    key = b"K" * 32
    _write_journal(tmp_path, key, seq=1, hw_ctr=5)
    _set_counter(tmp_path, 6)  # crash between increment and write
    j = DoubleJournal(str(tmp_path / "j"), key)
    hw = SimulatedHwCounter(str(tmp_path / "hw.json"))
    case, rec = j.boot(hw)
    assert case == BOOT_ADOPTED
    assert rec.payload == b"state"  # stored record adopted AS-IS
    assert hw.read() == 6  # stored hw_ctr := hw


def test_boot_rollback_hw_gt_saved_plus_1(tmp_path):
    key = b"K" * 32
    _write_journal(tmp_path, key, seq=1, hw_ctr=5)
    _set_counter(tmp_path, 8)
    j = DoubleJournal(str(tmp_path / "j"), key)
    hw = SimulatedHwCounter(str(tmp_path / "hw.json"))
    case, _rec = j.boot(hw)
    assert case == BOOT_ROLLBACK


def test_boot_reset_hw_lt_saved(tmp_path):
    key = b"K" * 32
    _write_journal(tmp_path, key, seq=1, hw_ctr=5)
    _set_counter(tmp_path, 3)  # counter reset / new device
    j = DoubleJournal(str(tmp_path / "j"), key)
    hw = SimulatedHwCounter(str(tmp_path / "hw.json"))
    case, _rec = j.boot(hw)
    assert case == BOOT_RESET


def test_double_journal_highest_seq_wins(tmp_path):
    key = b"K" * 32
    j = DoubleJournal(str(tmp_path / "j"), key)
    j.append_with_meta(JournalRecord(seq=1, hw_ctr=1, payload=b"one"))
    j.append_with_meta(JournalRecord(seq=2, hw_ctr=2, payload=b"two"))
    best = DoubleJournal(str(tmp_path / "j"), key).load_best()
    assert best.seq == 2 and best.payload == b"two"


def test_double_journal_torn_write_repaired_from_other_copy(tmp_path):
    key = b"K" * 32
    j = DoubleJournal(str(tmp_path / "j"), key)
    j.append_with_meta(JournalRecord(seq=1, hw_ctr=1, payload=b"one"))
    j.append_with_meta(JournalRecord(seq=2, hw_ctr=2, payload=b"two"))
    # Corrupt the newest slot (B): the older copy must repair the read.
    path_b = str(tmp_path / "j.B")
    with open(path_b, "wb") as fh:
        fh.write(b"\x00" * 10)
    best = DoubleJournal(str(tmp_path / "j"), key).load_best()
    assert best is not None
    assert best.seq == 1 and best.payload == b"one"


def test_journal_aead_bound_to_hw_ctr(tmp_path):
    key = b"K" * 32
    j = DoubleJournal(str(tmp_path / "j"), key)
    j.append_with_meta(JournalRecord(seq=1, hw_ctr=1, payload=b"one"))
    # Tamper with the hw_ctr sidecar → the AEAD check must fail.
    with open(str(tmp_path / "j.A.meta"), "w") as fh:
        json.dump({"seq": 1, "hw_ctr": 999}, fh)
    assert DoubleJournal(str(tmp_path / "j"), key).load_best() is None


def test_simulated_counter_increments_and_fsyncs(tmp_path):
    hw = SimulatedHwCounter(str(tmp_path / "hw.json"))
    assert hw.read() == 0
    assert hw.increment() == 1
    assert hw.increment() == 2
    # A fresh handle reads the persisted value.
    assert SimulatedHwCounter(str(tmp_path / "hw.json")).read() == 2
