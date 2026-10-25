"""Filesystem layout resolution for Mini SOC.

Every writable directory is derived from a single *home* directory so that a
fresh checkout, a service install and a container all behave the same way.

Resolution order for the home directory:

1. ``MINI_SOC_HOME`` environment variable (explicit override, used by the
   installer/service wrapper and by tests).
2. The repository root (the directory containing ``backend/``) when the
   application is run from a source checkout.
3. ``%PROGRAMDATA%/MiniSOC`` (Windows) or ``/var/lib/mini-soc`` (POSIX) as a
   last resort when the repository is not writable.

Nothing here ever writes outside the resolved home directory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

HOME_ENV = "MINI_SOC_HOME"

#: Marker file/dir that identifies a source checkout root.
_REPO_MARKER = "backend"


def repo_root() -> Path:
    """Return the repository root inferred from this file's location."""
    # .../mini-soc/backend/app/config/paths.py -> parents[3] == .../mini-soc
    return Path(__file__).resolve().parents[3]


def _fallback_home() -> Path:
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "MiniSOC"
    return Path("/var/lib/mini-soc")


def resolve_home(env: dict[str, str] | None = None) -> Path:
    """Resolve the Mini SOC home directory (see module docstring)."""
    env = os.environ if env is None else env
    override = env.get(HOME_ENV, "").strip()
    if override:
        return Path(override).expanduser()

    candidate = repo_root()
    if (candidate / _REPO_MARKER).is_dir():
        return candidate
    return _fallback_home()


@dataclass(frozen=True)
class AppPaths:
    """Immutable set of application directories."""

    home: Path

    @property
    def data(self) -> Path:
        return self.home / "data"

    @property
    def logs(self) -> Path:
        return self.home / "logs"

    @property
    def secrets(self) -> Path:
        return self.data / "secrets"

    @property
    def artifacts(self) -> Path:
        return self.home / "ml" / "artifacts"

    @property
    def rules(self) -> Path:
        return self.home / "detection-rules"

    @property
    def config(self) -> Path:
        return self.home / "backend" / "app" / "config"

    def ensure(self) -> "AppPaths":
        """Create every writable directory (idempotent)."""
        for directory in (self.data, self.logs, self.secrets, self.artifacts):
            directory.mkdir(parents=True, exist_ok=True)
        return self

    def sqlite_file(self, database_url: str) -> Path | None:
        """Return the on-disk file backing a SQLite URL, if it is SQLite."""
        prefix = "sqlite"
        if not database_url.startswith(prefix):
            return None
        _, _, tail = database_url.partition("///")
        if not tail or tail == ":memory:" or tail.startswith(":memory:"):
            return None
        raw = tail.split("?", 1)[0]
        path = Path(raw)
        if not path.is_absolute():
            path = (self.home / raw).resolve()
        return path


def default_paths() -> AppPaths:
    """Convenience accessor used by application bootstrap and tests."""
    return AppPaths(home=resolve_home())


__all__ = ["AppPaths", "HOME_ENV", "default_paths", "repo_root", "resolve_home"]
