"""User administration (ADMIN only)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...database.enums import UserRole
from ...database.repository import Repository, RepositoryError
from ...security.passwords import hash_password, validate_password_strength
from ...services.audit import audit
from ...services.bootstrap import Runtime
from ..deps import CurrentUser, RequireAdmin, get_db, get_runtime
from ..schemas import MessageResponse, Page, UserCreateRequest, UserOut, UserUpdateRequest

router = APIRouter(prefix="/users", tags=["administration"])


@router.get("", response_model=Page[UserOut])
def list_users(
    admin: Annotated[Any, RequireAdmin],
    session: Annotated[Session, Depends(get_db)],
) -> Page[UserOut]:
    users = Repository(session).list_users()
    return Page[UserOut](
        items=[UserOut(**user.public_dict()) for user in users], total=len(users), limit=len(users) or 1
    )


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateRequest,
    admin: Annotated[Any, RequireAdmin],
    session: Annotated[Session, Depends(get_db)],
) -> UserOut:
    problems = validate_password_strength(payload.password, username=payload.username)
    if problems:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "weak_password", "messages": problems},
        )
    repository = Repository(session)
    try:
        user = repository.create_user(
            username=payload.username,
            password_hash=hash_password(payload.password),
            role=payload.role,
            email=payload.email,
        )
    except RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "conflict", "message": str(exc)},
        ) from exc
    session.commit()
    audit(
        f"user {user.username!r} created with role {user.role}",
        actor=admin.username,
        actor_id=admin.id,
        details={"username": user.username, "role": user.role},
    )
    return UserOut(**user.public_dict())


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    admin: Annotated[Any, RequireAdmin],
    session: Annotated[Session, Depends(get_db)],
    runtime: Annotated[Runtime, Depends(get_runtime)],
) -> UserOut:
    repository = Repository(session)
    user = repository.get_user(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"user {user_id} not found"},
        )
    if payload.role is not None:
        if user.id == admin.id and payload.role != UserRole.ADMIN.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "self_demotion", "message": "an administrator cannot demote themselves"},
            )
        user.role = payload.role
    if payload.is_active is not None:
        if user.id == admin.id and not payload.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "self_disable", "message": "an administrator cannot disable themselves"},
            )
        user.is_active = payload.is_active
        if not payload.is_active:
            repository.revoke_user_tokens(user.id)
    if payload.email is not None:
        user.email = payload.email
    if payload.password is not None:
        problems = validate_password_strength(payload.password, username=user.username)
        if problems:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "weak_password", "messages": problems},
            )
        user.password_hash = hash_password(payload.password)
        repository.revoke_user_tokens(user.id)
    session.commit()
    audit(
        f"user {user.username!r} updated",
        actor=admin.username,
        actor_id=admin.id,
        details={"user_id": user_id, "role": user.role, "is_active": user.is_active},
    )
    return UserOut(**user.public_dict())


@router.post("/{user_id}/revoke-tokens", response_model=MessageResponse)
def revoke_tokens(
    user_id: int,
    admin: Annotated[Any, RequireAdmin],
    session: Annotated[Session, Depends(get_db)],
) -> MessageResponse:
    repository = Repository(session)
    if repository.get_user(user_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found", "message": f"user {user_id} not found"},
        )
    revoked = repository.revoke_user_tokens(user_id)
    session.commit()
    audit(
        f"refresh tokens revoked for user {user_id}",
        actor=admin.username,
        actor_id=admin.id,
        details={"revoked": revoked},
    )
    return MessageResponse(message="tokens revoked", detail={"revoked": revoked})


@router.get("/me/permissions")
def my_permissions(user: CurrentUser) -> dict[str, Any]:
    """What the current role is allowed to do (used by the dashboard UI)."""
    role = user.role
    return {
        "username": user.username,
        "role": role,
        "permissions": {
            "read": True,
            "investigate": role in {UserRole.ANALYST.value, UserRole.ADMIN.value},
            "manage_rules": role == UserRole.ADMIN.value,
            "manage_users": role == UserRole.ADMIN.value,
            "manage_models": role == UserRole.ADMIN.value,
            "run_simulator": role == UserRole.ADMIN.value,
        },
    }


__all__ = ["router"]
