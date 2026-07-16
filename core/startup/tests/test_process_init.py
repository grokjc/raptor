"""Tests for core.startup.process_init."""

from __future__ import annotations

import faulthandler
import signal
import sys


def test_init_enables_faulthandler():
    from core.startup.process_init import init

    init()
    assert faulthandler.is_enabled()


def test_init_registers_sigusr1(monkeypatch):
    """SIGUSR1 handler is registered on platforms that support it."""
    from core.startup.process_init import init

    if not hasattr(signal, "SIGUSR1"):
        return

    registered = {}

    def fake_register(signum, **kwargs):
        registered["signum"] = signum
        registered.update(kwargs)

    monkeypatch.setattr(faulthandler, "register", fake_register)
    init()
    assert registered.get("signum") == signal.SIGUSR1
    assert registered.get("all_threads") is True
    assert registered.get("file") is sys.stderr


def test_init_idempotent():
    """Calling init() twice does not raise."""
    from core.startup.process_init import init

    init()
    init()
    assert faulthandler.is_enabled()
