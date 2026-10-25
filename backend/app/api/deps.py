"""FastAPI dependencies: runtime access, authentication and RBAC helpers."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..config.logging_config import get_logger
from ..database.connection import get_session as _get_session
from ..database.enums import UserRole
from ..database.models import User
from ..database.repository import Repository
from ..security.tokens import TokenError, decode_access_token
from ..services.bootstrap import Runtime

logger = get_logger(__name__)

#: ``auto_error=False`` lets us emit our own 401 with a consistent body.
bearer_scheme = HTTPBearer(auto_error=False)


def get_runtime(request: Request) -> Runtime:
    """Return the runtime assembled during application startup."""
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:  # pragma: no cover - only when startup failed
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "service_unavailable", "message": "runtime not initialised"},
        )
    return runtime


def get_db(request: Request) -> Iterator[Session]:
    """Request-scoped database session."""
    yield from _get_session()


def get_repository(session: Annotated[Session, Depends(get_db)]) -> Repository:
    return Repository(session)


def get_settings_from_runtime(runtime: Annotated[Runtime, Depends(get_runtime)]):
    return runtime.settings


def client_key(request: Request) -> str:
    """Identify a client for rate limiting (proxy-aware but not spoofable)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> User:
    """Resolve the authenticated user from a bearer token."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "not_authenticated", "message": "missing bearer token"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(
            credentials.credentials,
            secret=runtime.settings.resolved_jwt_secret(),
            algorithms={runtime.settings.jwt_algorithm},
        )
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": str(exc)},
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    repository = Repository(session)
    user = repository.get_user_by_username(str(payload.get("sub") or ""))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": "user no longer active"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.user = user
    request.state.token_claims = payload
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: str):
    """Dependency factory enforcing role-based authorisation."""
    allowed = {role.upper() for role in roles}

    async def _checker(user: CurrentUser) -> User:
        if allowed and user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "forbidden",
                    "message": f"role {user.role} may not perform this action",
                    "required_roles": sorted(allowed),
                },
            )
        return user

    return _checker


RequireViewer = Depends(require_roles(UserRole.VIEWER.value, UserRole.ANALYST.value, UserRole.ADMIN.value))
RequireAnalyst = Depends(require_roles(UserRole.ANALYST.value, UserRole.ADMIN.value))
RequireAdmin = Depends(require_roles(UserRole.ADMIN.value))


def get_optional_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> User | None:
    """Best-effort user resolution (used by WebSocket handshakes)."""
    if credentials is None or not credentials.credentials:
        return None
    try:
        payload = decode_access_token(
            credentials.credentials,
            secret=runtime.settings.resolved_jwt_secret(),
            algorithms={runtime.settings.jwt_algorithm},
        )
    except TokenError:
        return None
    user = Repository(session).get_user_by_username(str(payload.get("sub") or ""))
    return user if user and user.is_active else None


def pagination(limit: int = 100, offset: int = 0) -> dict[str, int]:
    """Clamp pagination parameters to safe bounds."""
    return {"limit": max(1, min(int(limit), 500)), "offset": max(0, int(offset))}


__all__ = [
    "CurrentUser",
    "RequireAdmin",
    "RequireAnalyst",
    "RequireViewer",
    "bearer_scheme",
    "client_key",
    "get_current_user",
    "get_db",
    "get_optional_user",
    "get_repository",
    "get_runtime",
    "get_settings_from_runtime",
    "pagination",
    "require_roles",
]
