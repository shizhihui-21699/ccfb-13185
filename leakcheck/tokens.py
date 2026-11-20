"""Self-authenticating probe tokens.

A token is what ties every observation back to one self-check session, and it
travels through channels we do not fully control (DNS labels, URLs, page JS).
So it is an HMAC-signed opaque blob: the DNS and STUN listeners can accept it
without a database round-trip, and a third party cannot forge tokens to inject
observations.

Layout: ``base32(payload(9 bytes) || hmac-truncated(8 bytes))`` lowercased with
padding stripped -> 28 characters, valid as a DNS label and URL path segment.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

PAYLOAD_LEN = 9
SIG_LEN = 8
TOKEN_LEN = 28
_ALPHABET_OK = set("abcdefghijklmnopqrstuvwxyz234567")


class TokenError(ValueError):
    """Raised for malformed or forged tokens."""


def _b32encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def _b32decode(text: str) -> bytes:
    padded = text.upper() + "=" * (-len(text) % 8)
    return base64.b32decode(padded)


def _sign(secret: bytes, payload: bytes) -> bytes:
    return hmac.new(secret, b"leakcheck-token-v1:" + payload, hashlib.sha256).digest()[:SIG_LEN]


def new_token(secret: bytes, issued_at: float | None = None) -> str:
    """Mint a fresh token; the first 4 bytes carry the issue time for TTL checks."""
    issued = int(issued_at if issued_at is not None else time.time())
    payload = issued.to_bytes(4, "big") + secrets.token_bytes(PAYLOAD_LEN - 4)
    token = _b32encode(payload + _sign(secret, payload))
    assert len(token) == TOKEN_LEN, len(token)
    return token


def issued_at(secret: bytes, token: str) -> float:
    payload, _ = _split(secret, token)
    return float(int.from_bytes(payload[:4], "big"))


def is_valid(secret: bytes, token: str, max_age: float | None = None,
             now: float | None = None) -> bool:
    try:
        payload, _ = _split(secret, token)
    except TokenError:
        return False
    if max_age is not None:
        stamp = int.from_bytes(payload[:4], "big")
        current = now if now is not None else time.time()
        # Tolerate a little clock skew in either direction.
        if stamp - current > 120 or current - stamp > max_age:
            return False
    return True


def _split(secret: bytes, token: str) -> tuple[bytes, bytes]:
    text = (token or "").strip().lower()
    if len(text) != TOKEN_LEN or any(ch not in _ALPHABET_OK for ch in text):
        raise TokenError("令牌格式不正确")
    raw = _b32decode(text)
    payload, signature = raw[:PAYLOAD_LEN], raw[PAYLOAD_LEN:]
    if not hmac.compare_digest(signature, _sign(secret, payload)):
        raise TokenError("令牌签名校验失败")
    return payload, signature


def normalise(token: str) -> str:
    return (token or "").strip().lower()
