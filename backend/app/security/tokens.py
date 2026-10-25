"""Token management (spec section 24).

* **Access tokens** are short-lived JWTs signed with the installation secret.
  The algorithm is pinned (no ``alg: none`` / algorithm confusion).
* **Refresh tokens** are opaque random strings; only a SHA-256 hash is stored,
  so a leaked database cannot be replayed against the API. They are revocable
  individually or per user.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from ..config.logging_config import get_logger

logger = get_logger(__name__)

ALLOWED_ALGORITHMS = {"HS256", "HS384", "HS512"}
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_BYTES = 48


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired or has a bad signature."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(
    *,
    subject: str,
    role: str,
    secret: str,
    algorithm: str = "HS256",
    expires_minutes: int = 30,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, datetime]:
    """Create a signed access token and return it with its expiry."""
    if algorithm not in ALLOWED_ALGORITHMS:
        raise TokenError(f"unsupported signing algorithm {algorithm!r}")
    issued = _now()
    expires = issued + timedelta(minutes=int(expires_minutes))
    payload: dict[str, Any] = {
        "sub": str(subject),
        "role": role,
        "type": ACCESS_TOKEN_TYPE,
        "iat": int(issued.timestamp()),
        "nbf": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_urlsafe(12),
        "iss": "mini-soc",
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, secret, algorithm=algorithm)
    return token, expires


def decode_access_token(token: str, *, secret: str, algorithms: set[str] | None = None) -> dict[str, Any]:
    """Validate and decode an access token."""
    if not token:
        raise TokenError("missing token")
    allowed = algorithms or ALLOWED_ALGORITHMS
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=sorted(allowed),
            issuer="mini-soc",
            options={"require": ["exp", "sub", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError(f"invalid token: {exc}") from exc
    if payload.get("type") != ACCESS_TOKEN_TYPE:
        raise TokenError("not an access token")
    return payload


def generate_refresh_token() -> str:
    """Create a new opaque refresh token (returned to the client once)."""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """Hash a refresh token for storage/lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def refresh_expiry(days: int) -> datetime:
    return _now().replace(tzinfo=None) + timedelta(days=max(int(days), 1))


def token_fingerprint(token: str) -> str:
    """Short, non-reversible token id for audit logs."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "ACCESS_TOKEN_TYPE",
    "ALLOWED_ALGORITHMS",
    "REFRESH_TOKEN_BYTES",
    "TokenError",
    "create_access_token",
    "decode_access_token",
    "generate_refresh_token",
    "hash_refresh_token",
    "refresh_expiry",
    "token_fingerprint",
]
