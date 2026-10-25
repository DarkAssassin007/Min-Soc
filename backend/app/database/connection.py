"""Database engine, session management and schema bootstrap.

SQLite is the default so a Mini SOC runs with zero external services, while
PostgreSQL is a first-class option through ``MINI_SOC_DATABASE_URL``.

SQLite tuning: WAL journaling (readers never block the writer), a busy timeout
so concurrent API reads do not raise "database is locked", and enforced foreign
keys for referential integrity.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from ..config.logging_config import get_logger
from ..config.settings import Settings, get_settings
from .base import Base

logger = get_logger(__name__)

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None
_lock = threading.RLock()

#: Serialises writers when running on SQLite (single-writer engine).
write_lock = threading.RLock()


def _is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")


def _resolve_sqlite_file(url, settings: Settings):
    """Resolve a relative SQLite path against the Mini SOC home directory.

    Keeps `./data/mini_soc.db` working no matter which directory the process
    was started from, and creates the parent folder if needed.
    """
    database = url.database or ""
    if not database or database == ":memory:" or database.startswith("file:"):
        return url
    candidate = Path(database)
    if not candidate.is_absolute():
        candidate = (settings.paths.home / database).resolve()
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return url.set(database=str(candidate))


def _build_engine(settings: Settings) -> Engine:
    url = make_url(settings.database_url)
    kwargs: dict[str, Any] = {"echo": settings.db_echo, "future": True}

    if url.get_backend_name() == "sqlite":
        url = _resolve_sqlite_file(url, settings)

    if url.get_backend_name() == "sqlite":
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    else:
        kwargs.update(
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,
        )

    engine = create_engine(url, **kwargs)

    if url.get_backend_name() == "sqlite":

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.execute("PRAGMA temp_store=MEMORY")
                cursor.execute("PRAGMA cache_size=-40000")  # ~40 MB page cache
            except Exception as exc:  # pragma: no cover - non-fatal tuning
                logger.debug("sqlite pragma setup failed", extra={"error": str(exc)})
            finally:
                cursor.close()

    return engine


def configure_engine(
    url: str | None = None, settings: Settings | None = None, *, echo: bool | None = None
) -> Engine:
    """(Re)create the global engine. Used by tests and by the CLI."""
    global _engine, _session_factory

    settings = settings or get_settings()
    if url is not None:
        settings = settings.model_copy(update={"database_url": url})
    if echo is not None:
        settings = settings.model_copy(update={"db_echo": echo})

    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = _build_engine(settings)
        _session_factory = sessionmaker(
            bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False
        )
        logger.info(
            "database engine configured",
            extra={"backend": _engine.url.get_backend_name(), "database": _engine.url.database},
        )
        return _engine


def resolved_url(settings: Settings) -> str:
    """Return the effective database URL for a settings object (SQLite path resolved)."""
    url = make_url(settings.database_url)
    if url.get_backend_name() == "sqlite":
        url = _resolve_sqlite_file(url, settings)
    return url.render_as_string(hide_password=False)


def get_engine(settings: Settings | None = None) -> Engine:
    """Return the global engine bound to ``settings``.

    If the configured database differs from the engine currently in use (for
    example ``MINI_SOC_DATABASE_URL`` changed, or a test supplied its own home
    directory) the engine is rebuilt instead of silently using the stale one.
    """
    settings = settings or get_settings()
    if _engine is None or _engine.url.render_as_string(hide_password=False) != resolved_url(settings):
        return configure_engine(settings=settings)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    if _session_factory is None:
        configure_engine()
    assert _session_factory is not None
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session scope: commit on success, rollback on error."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a read/write session."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def init_db(*, settings: Settings | None = None, drop: bool = False) -> Engine:
    """Create the schema (idempotent) and return the engine."""
    settings = settings or get_settings()
    settings.ensure_directories()
    engine = get_engine(settings)
    if drop:
        Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    logger.info(
        "database schema ready",
        extra={"tables": len(Base.metadata.tables), "database_url": engine.url.render_as_string(False)},
    )
    return engine


def healthcheck() -> dict:
    """Cheap database liveness probe used by /health and /ready."""
    try:
        with session_scope() as session:
            session.execute(text("SELECT 1"))
        engine = get_engine()
        return {
            "status": "ok",
            "backend": engine.url.get_backend_name(),
            "database": engine.url.database,
        }
    except Exception as exc:
        logger.error("database healthcheck failed", extra={"error": str(exc)})
        return {"status": "error", "error": str(exc)}


def dispose_engine() -> None:
    """Dispose of the engine (used on shutdown and between tests)."""
    global _engine, _session_factory
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _session_factory = None


def reset_for_tests(url: str, *, create_schema: bool = True) -> Engine:
    """Point the application at a throwaway database."""
    engine = configure_engine(url)
    if create_schema:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
    return engine


__all__ = [
    "configure_engine",
    "dispose_engine",
    "get_engine",
    "get_session",
    "get_session_factory",
    "healthcheck",
    "init_db",
    "reset_for_tests",
    "session_scope",
    "write_lock",
]
