"""The optional-import guards in soulguard/__init__.py must only tolerate ImportError.

A real bug inside soulguard.identity (anything other than a missing optional
dependency) has to surface at import time instead of silently removing SoulKey
from the package.

Run with: python -m pytest tests/test_optional_imports.py
"""
import importlib
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest


def _fresh_import_with_identity(identity_module):
    """Import soulguard from scratch with soulguard.identity replaced."""
    saved = {k: v for k, v in sys.modules.items() if k == "soulguard" or k.startswith("soulguard.")}
    for k in saved:
        del sys.modules[k]
    try:
        if identity_module is not None:
            sys.modules["soulguard.identity"] = identity_module
        return importlib.import_module("soulguard")
    finally:
        for k in [k for k in sys.modules if k == "soulguard" or k.startswith("soulguard.")]:
            del sys.modules[k]
        sys.modules.update(saved)


class _BrokenIdentity(types.ModuleType):
    """A stand-in module whose attribute access fails with a non-import bug."""

    def __getattr__(self, name):
        raise RuntimeError("simulated bug inside soulguard.identity")


class _MissingDepIdentity(types.ModuleType):
    """A stand-in module that behaves like an optional dependency is absent."""

    def __getattr__(self, name):
        raise ImportError("simulated missing optional dependency")


def test_non_import_error_in_identity_propagates():
    with pytest.raises(RuntimeError, match="simulated bug"):
        _fresh_import_with_identity(_BrokenIdentity("soulguard.identity"))


def test_missing_optional_dependency_is_tolerated():
    sg = _fresh_import_with_identity(_MissingDepIdentity("soulguard.identity"))
    assert "SoulKey" not in sg.__all__
    assert "HybridSoulKey" not in sg.__all__
    assert "TamperEvidentMemory" in sg.__all__
