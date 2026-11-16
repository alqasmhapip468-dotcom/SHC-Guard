# تجريبي، غير مدقق، لا يُستخدم لحماية بيانات حقيقية
"""pytest configuration: make the reference package importable, and
provide the shared fixtures (FakeClock + a fresh ACTIVE pair)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.helpers import FakeClock, build_pair  # noqa: E402


@pytest.fixture()
def clock():
    return FakeClock()


@pytest.fixture()
def pair(clock):
    """A fresh, saved, ACTIVE pair (a, b) sharing one consumed-ID set."""
    return build_pair(clock)
