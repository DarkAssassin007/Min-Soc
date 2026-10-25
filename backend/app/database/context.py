"""Thread-local repository binding.

Long-lived services (alert manager, incident manager, correlator, rule
registry) need a repository, but SQLAlchemy sessions are *not* thread-safe and
worker threads create a fresh session per batch. Instead of passing a session
through every call, services hold a :class:`RepositoryProxy` and the pipeline
binds the current batch's repository for the duration of the batch.

Unbound access raises immediately with a clear message rather than silently
using a closed session.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from collections.abc import Iterator
from typing import Any

from .repository import Repository


class RepositoryProxy:
    """Forwards attribute access to the repository bound to this thread."""

    def __init__(self, repository: Repository | None = None) -> None:
        self._local = threading.local()
        if repository is not None:
            self.bind(repository)

    # ------------------------------------------------------------ binding
    def bind(self, repository: Repository) -> "RepositoryProxy":
        self._local.repository = repository
        return self

    def unbind(self) -> None:
        self._local.__dict__.pop("repository", None)

    @property
    def bound(self) -> bool:
        return getattr(self._local, "repository", None) is not None

    @property
    def current(self) -> Repository:
        repository = getattr(self._local, "repository", None)
        if repository is None:
            raise RuntimeError(
                "no repository bound to this thread; "
                "the pipeline must bind a session before calling data-access services"
            )
        return repository

    # ----------------------------------------------------------- forwarding
    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.current, name)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RepositoryProxy bound={self.bound}>"


@contextmanager
def bind_repository(proxy: RepositoryProxy, repository: Repository) -> Iterator[Repository]:
    """Bind a repository for the duration of a block."""
    proxy.bind(repository)
    try:
        yield repository
    finally:
        proxy.unbind()


def current_repository(proxy: RepositoryProxy) -> Repository:
    return proxy.current


__all__ = ["RepositoryProxy", "bind_repository", "current_repository"]
