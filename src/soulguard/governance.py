"""Capability-scoped governance — just-in-time, least-privilege tokens for agent actions.

Even a partially-compromised agent cannot exceed its sanctioned authority undetected:
every tool action requires an unforgeable, short-lived, scope-bound capability token.
Pure standard library (hmac/hashlib).
"""
from __future__ import annotations
import hmac
import hashlib
import json
import time
import base64
from typing import Iterable


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_token(secret: bytes, agent_id: str, scopes: Iterable[str], ttl_seconds: int = 300,
                now: float | None = None) -> str:
    """Mint a least-privilege capability token (default TTL 300s)."""
    now = now if now is not None else time.time()
    body = {"agent": agent_id, "scopes": sorted(set(scopes)), "exp": int(now + ttl_seconds)}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret, raw, hashlib.sha256).digest()
    return f"{_b64(raw)}.{_b64(sig)}"


def verify_token(secret: bytes, token: str, required_scope: str, now: float | None = None) -> bool:
    """True only if the token is authentic, unexpired, and grants required_scope."""
    now = now if now is not None else time.time()
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw, sig = _unb64(raw_b64), _unb64(sig_b64)
    except Exception:
        return False
    expected = hmac.new(secret, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):   # forged/altered token
        return False
    body = json.loads(raw)
    if now > body.get("exp", 0):                  # expired
        return False
    return required_scope in body.get("scopes", [])
