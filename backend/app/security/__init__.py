"""Authentication, authorisation and hardening primitives."""

from __future__ import annotations

from .passwords import (
    PasswordPolicyError,
    ensure_password,
    generate_password,
    hash_password,
    needs_rehash,
    validate_password_strength,
    verify_password,
)
from .ratelimit import RateLimitResult, SlidingWindowLimiter
from .tokens import (
    TokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
    refresh_expiry,
    token_fingerprint,
)

__all__ = [
    "PasswordPolicyError",
    "RateLimitResult",
    "SlidingWindowLimiter",
    "TokenError",
    "create_access_token",
    "decode_access_token",
    "ensure_password",
    "generate_password",
    "generate_refresh_token",
    "hash_password",
    "hash_refresh_token",
    "needs_rehash",
    "refresh_expiry",
    "token_fingerprint",
    "validate_password_strength",
    "verify_password",
]
