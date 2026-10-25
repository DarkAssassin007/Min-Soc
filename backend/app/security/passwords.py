"""Password hashing and policy (spec section 24/25).

bcrypt with a configurable cost factor. Passwords are never logged, never
stored in plain text, and are checked against a small policy before hashing so
an operator cannot bootstrap an administrator with ``admin123``.
"""

from __future__ import annotations

import re
import secrets
import string

import bcrypt

#: Cost factor. 12 is a reasonable 2026 default for interactive logins.
DEFAULT_ROUNDS = 12
MAX_PASSWORD_BYTES = 72  # bcrypt truncates beyond this

MIN_LENGTH = 12
_COMMON_PASSWORDS = {
    "password",
    "password123",
    "admin123",
    "administrator",
    "letmein",
    "welcome1",
    "qwerty123",
    "changeme",
    "minisoc",
    "mini-soc",
    "soc12345",
}


class PasswordPolicyError(ValueError):
    """Raised when a password does not satisfy the policy."""


def hash_password(password: str, *, rounds: int = DEFAULT_ROUNDS) -> str:
    """Hash a password with bcrypt (returns the modular crypt string)."""
    if not isinstance(password, str) or not password:
        raise PasswordPolicyError("password must be a non-empty string")
    payload = password.encode("utf-8")[:MAX_PASSWORD_BYTES]
    return bcrypt.hashpw(payload, bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verification; never raises on malformed hashes."""
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:MAX_PASSWORD_BYTES], password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def needs_rehash(password_hash: str, *, rounds: int = DEFAULT_ROUNDS) -> bool:
    try:
        return bcrypt.checkpw(b"x", password_hash.encode("ascii")) or _rounds_of(password_hash) < rounds
    except (ValueError, TypeError):
        return True


def _rounds_of(password_hash: str) -> int:
    match = re.match(r"^\$2[aby]\$(\d{2})\$", password_hash)
    return int(match.group(1)) if match else 0


def validate_password_strength(password: str, *, username: str | None = None) -> list[str]:
    """Return the list of policy violations (empty list == acceptable)."""
    problems: list[str] = []
    if len(password or "") < MIN_LENGTH:
        problems.append(f"password must be at least {MIN_LENGTH} characters")
    if not re.search(r"[A-Z]", password or ""):
        problems.append("password must contain an uppercase letter")
    if not re.search(r"[a-z]", password or ""):
        problems.append("password must contain a lowercase letter")
    if not re.search(r"\d", password or ""):
        problems.append("password must contain a digit")
    if not re.search(r"[^A-Za-z0-9]", password or ""):
        problems.append("password must contain a symbol")
    lowered = (password or "").lower()
    if lowered in _COMMON_PASSWORDS:
        problems.append("password is a well-known default and is not acceptable")
    if username and username.lower() in lowered:
        problems.append("password must not contain the username")
    return problems


def ensure_password(password: str, *, username: str | None = None) -> str:
    problems = validate_password_strength(password, username=username)
    if problems:
        raise PasswordPolicyError("; ".join(problems))
    return password


def generate_password(length: int = 20) -> str:
    """Generate a strong random password for bootstrapping an install."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(max(length, MIN_LENGTH)))
        if not validate_password_strength(candidate):
            return candidate


__all__ = [
    "DEFAULT_ROUNDS",
    "MIN_LENGTH",
    "MAX_PASSWORD_BYTES",
    "PasswordPolicyError",
    "ensure_password",
    "generate_password",
    "hash_password",
    "needs_rehash",
    "validate_password_strength",
    "verify_password",
]
