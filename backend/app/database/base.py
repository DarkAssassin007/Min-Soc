"""Declarative base, naming conventions and shared column mixins."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

#: Deterministic constraint names - required for future Alembic migrations.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    """Timezone-naive UTC timestamp (SQLite friendly, Postgres compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    """Base class for every ORM model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def to_dict(self, *, exclude: set[str] | None = None) -> dict:
        """Serialise the model's mapped columns into a plain dict."""
        exclude = exclude or set()
        result: dict = {}
        for column in self.__table__.columns:
            if column.name in exclude:
                continue
            result[column.name] = getattr(self, column.key)
        return result

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        pk = getattr(self, "id", None)
        return f"<{type(self).__name__} id={pk}>"


class TimestampMixin:
    """Adds created/updated timestamps to a model."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


__all__ = ["Base", "NAMING_CONVENTION", "TimestampMixin", "utcnow"]
