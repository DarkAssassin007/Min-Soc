"""API schemas.

Request models are strict (``extra="forbid"``) so unexpected or malicious
fields are rejected instead of being silently ignored — the first line of
defence for input validation (spec section 25). Response models are permissive
and mostly pass through the ``public_dict`` helpers on the ORM models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..database.enums import (
    AlertStatus,
    IncidentStatus,
    SeverityLevel,
    UserRole,
)

SeverityLiteral = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# --------------------------------------------------------------------------
# authentication
# --------------------------------------------------------------------------
class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=16, max_length=512)


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=16, max_length=512)


class UserOut(BaseModel):
    id: int
    username: str
    email: str | None = None
    role: str
    is_active: bool
    last_login_at: str | None = None
    created_at: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    expires_at: datetime
    user: UserOut


# --------------------------------------------------------------------------
# users / administration
# --------------------------------------------------------------------------
class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: Literal["ADMIN", "ANALYST", "VIEWER"] = UserRole.VIEWER.value
    email: str | None = Field(default=None, max_length=255)


class UserUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["ADMIN", "ANALYST", "VIEWER"] | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)
    email: str | None = Field(default=None, max_length=255)


# --------------------------------------------------------------------------
# alerts / incidents
# --------------------------------------------------------------------------
class AlertUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    resolution: str | None = Field(default=None, max_length=2000)
    note: str | None = Field(default=None, max_length=4000)

    @field_validator("status")
    @classmethod
    def _known_status(cls, value: str) -> str:
        if not AlertStatus.has(value):
            raise ValueError(f"unknown alert status {value!r}")
        return value


class AlertAssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(ge=1)


class IncidentUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
    resolution: str | None = Field(default=None, max_length=2000)
    note: str | None = Field(default=None, max_length=4000)

    @field_validator("status")
    @classmethod
    def _known_status(cls, value: str) -> str:
        if not IncidentStatus.has(value):
            raise ValueError(f"unknown incident status {value!r}")
        return value


class NoteCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str = Field(min_length=1, max_length=4000)
    action_taken: str | None = Field(default=None, max_length=64)


class IncidentCreateRequest(BaseModel):
    """Manual incident creation (analysts escalating a group of alerts)."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=3, max_length=255)
    summary: str | None = Field(default=None, max_length=4000)
    severity: SeverityLiteral = SeverityLevel.MEDIUM.value
    alert_ids: list[str] = Field(default_factory=list, max_length=200)


# --------------------------------------------------------------------------
# rules / models
# --------------------------------------------------------------------------
class RuleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    threshold: float | None = Field(default=None, ge=0, le=1_000_000_000)
    window_seconds: int | None = Field(default=None, ge=10, le=86_400)
    params: dict[str, Any] | None = None


class ModelActivateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1, max_length=64)


# --------------------------------------------------------------------------
# read models
# --------------------------------------------------------------------------
class EventOut(BaseModel):
    model_config = ConfigDict(extra="allow")


class AlertOut(BaseModel):
    model_config = ConfigDict(extra="allow")


class IncidentOut(BaseModel):
    model_config = ConfigDict(extra="allow")


class Page[T](BaseModel):
    """Generic paginated envelope."""

    items: list[T]
    total: int | None = None
    limit: int = 100
    offset: int = 0
    has_more: bool = False


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "error"]
    version: str
    environment: str
    uptime_seconds: float
    components: dict[str, Any] = Field(default_factory=dict)


class MessageResponse(BaseModel):
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "AlertAssignRequest",
    "AlertOut",
    "AlertUpdateRequest",
    "EventOut",
    "HealthResponse",
    "IncidentCreateRequest",
    "IncidentOut",
    "IncidentUpdateRequest",
    "LoginRequest",
    "LogoutRequest",
    "MessageResponse",
    "ModelActivateRequest",
    "NoteCreateRequest",
    "Page",
    "RefreshRequest",
    "RuleUpdateRequest",
    "SeverityLiteral",
    "TokenResponse",
    "UserCreateRequest",
    "UserOut",
    "UserUpdateRequest",
]
