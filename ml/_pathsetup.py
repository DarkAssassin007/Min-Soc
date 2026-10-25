"""Import path bootstrap for the standalone training pipeline.

The training pipeline lives beside the backend rather than inside it (spec
section 30), so when it is executed directly (``python -m ml.train``) or on
behalf of the backend it has to make the backend package importable without
requiring an editable install.
"""

from __future__ import annotations

import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def ensure_backend_importable() -> Path:
    """Put ``<repo>/backend`` and ``<repo>`` on ``sys.path`` (idempotent)."""
    root = repo_root()
    for candidate in (root / "backend", root):
        text = str(candidate)
        if text not in sys.path:
            sys.path.insert(0, text)
    return root


__all__ = ["ensure_backend_importable", "repo_root"]
