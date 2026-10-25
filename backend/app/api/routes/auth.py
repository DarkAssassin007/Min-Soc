"""Authentication routes: login, refresh, logout, current user, bootstrap."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ...config.logging_config import get_logger
from ...database.base import utcnow
from ...database.enums import LogCategory, UserRole
from ...database.models import User
from ...database.repository import Repository
from ...security.passwords import validate_password_strength, verify_password
from ...security.tokens import (
    TokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
    refresh_expiry,
)
from ...services.audit import audit, security_event
from ...services.bootstrap import Runtime
from ..deps import CurrentUser, client_key, get_db, get_runtime
from ..schemas import (
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    RefreshRequest,
    TokenResponse,
    UserOut,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])

#: Failed logins before the account is temporarily locked.
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _issue_tokens(repository: Repository, runtime: Runtime, user: User, request: Request) -> TokenResponse:
    settings = runtime.settings
    access_token, expires_at = create_access_token(
        subject=user.username,
        role=user.role,
        secret=settings.resolved_jwt_secret(),
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.access_token_minutes,
        extra_claims={"uid": user.id},
    )
    refresh_token = generate_refresh_token()
    repository.store_refresh_token(
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
        expires_at=refresh_expiry(settings.refresh_token_days).replace(tzinfo=None),
        ip_address=client_key(request),
        user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=int(settings.access_token_minutes * 60),
        expires_at=expires_at,
        user=UserOut(**user.public_dict()),
    )


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> TokenResponse:
    """Authenticate a user and issue an access/refresh token pair."""
    repository = Repository(session)
    user = repository.get_user_by_username(payload.username)

    # Uniform failure response - no user enumeration.
    def _reject(reason: str, extra: dict | None = None) -> HTTPException:
        security_event(
            f"login failed for {payload.username!r}: {reason}",
            actor=payload.username,
            source=client_key(request),
            details={"reason": reason, **(extra or {})},
        )
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_credentials", "message": "invalid username or password"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user is None:
        raise _reject("unknown user")
    if not user.is_active:
        raise _reject("inactive account", {"user_id": user.id})
    if user.locked_until and user.locked_until > utcnow():
        security_event(
            f"login blocked for {payload.username!r}: account locked",
            actor=payload.username,
            source=client_key(request),
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "error": "account_locked",
                "message": "account temporarily locked after repeated failed logins",
                "locked_until": user.locked_until.isoformat(),
            },
        )
    if not verify_password(payload.password, user.password_hash):
        repository.touch_login(user, success=False)
        if (user.failed_login_attempts or 0) >= MAX_FAILED_ATTEMPTS:
            from datetime import timedelta

            user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            security_event(
                f"account locked for {payload.username!r} after {user.failed_login_attempts} failures",
                actor=payload.username,
                source=client_key(request),
                level="ERROR",
            )
        session.commit()
        raise _reject("bad password")

    repository.touch_login(user, success=True)
    session.commit()
    tokens = _issue_tokens(repository, runtime, user, request)
    session.commit()
    audit(
        f"user {user.username!r} logged in",
        category=LogCategory.AUTH.value,
        actor=user.username,
        actor_id=user.id,
        source=client_key(request),
    )
    return tokens


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    payload: RefreshRequest,
    request: Request,
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> TokenResponse:
    """Exchange a valid refresh token for a new token pair (rotation)."""
    repository = Repository(session)
    token_hash = hash_refresh_token(payload.refresh_token)
    stored = repository.get_refresh_token(token_hash)
    if stored is None or stored.revoked_at is not None:
        security_event(
            "refresh attempted with unknown or revoked token",
            source=client_key(request),
            level="WARNING",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": "refresh token is not valid"},
        )
    if stored.expires_at < utcnow():
        repository.revoke_refresh_token(stored)
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "token_expired", "message": "refresh token expired"},
        )
    user = repository.get_user(int(stored.user_id))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": "user is not active"},
        )
    repository.revoke_refresh_token(stored)  # rotation: single use
    tokens = _issue_tokens(repository, runtime, user, request)
    session.commit()
    audit(
        f"token refreshed for {user.username!r}",
        category=LogCategory.AUTH.value,
        actor=user.username,
        actor_id=user.id,
    )
    return tokens


@router.post("/logout", response_model=MessageResponse)
def logout(
    payload: LogoutRequest,
    user: CurrentUser,
    session: Annotated[Session, Depends(get_db)],
) -> MessageResponse:
    """Revoke the presented refresh token."""
    repository = Repository(session)
    stored = repository.get_refresh_token(hash_refresh_token(payload.refresh_token))
    if stored is not None and stored.user_id == user.id:
        repository.revoke_refresh_token(stored)
        session.commit()
    audit(
        f"user {user.username!r} logged out",
        category=LogCategory.AUTH.value,
        actor=user.username,
        actor_id=user.id,
    )
    return MessageResponse(message="logged out")


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> UserOut:
    return UserOut(**user.public_dict())


@router.post("/bootstrap", response_model=TokenResponse)
def bootstrap_admin(
    payload: LoginRequest,
    request: Request,
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> TokenResponse:
    """Create the very first administrator (only while no user exists).

    This exists so a fresh installation can be secured from the dashboard
    without shell access. It is a one-shot endpoint: as soon as any user exists
    it returns 409 and can never be used again.
    """
    repository = Repository(session)
    if repository.list_users():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "already_initialised", "message": "an account already exists"},
        )
    problems = validate_password_strength(payload.password, username=payload.username)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "weak_password", "messages": problems},
        )
    from ...security.passwords import hash_password

    user = repository.create_user(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=UserRole.ADMIN.value,
        email=runtime.settings.admin_email,
    )
    tokens = _issue_tokens(repository, runtime, user, request)
    session.commit()
    audit(
        f"bootstrap administrator {user.username!r} created",
        category=LogCategory.AUTH.value,
        actor=user.username,
        actor_id=user.id,
        source=client_key(request),
        level="WARNING",
    )
    return tokens


__all__ = ["router"]
