"""Development entry point: ``python -m app``.

Equivalent to running uvicorn directly:

    python -m app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import argparse

from .config.settings import get_settings


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Run the Mini SOC API and collector pipeline")
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--reload", action="store_true", help="auto-reload (development only)")
    parser.add_argument("--log-level", default=settings.log_level.lower())
    parser.add_argument(
        "--no-collection",
        action="store_true",
        help="run the API without starting collectors (useful for API-only deployments)",
    )
    args = parser.parse_args(argv)

    import uvicorn

    if args.no_collection:
        import os

        os.environ.setdefault("MINI_SOC_COLLECTOR_NETWORK_ENABLED", "false")
        os.environ.setdefault("MINI_SOC_COLLECTOR_SYSLOG_ENABLED", "false")
        os.environ.setdefault("MINI_SOC_SIMULATOR_ENABLED", "false")

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
