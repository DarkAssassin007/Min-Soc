"""FastAPI application factory (spec sections 20, 24, 25, 27).

    uvicorn app.main:app --host 127.0.0.1 --port 8000

Responsibilities of this module:

* assemble the runtime (collectors, pipeline, detection, alerts) on startup and
  shut it down cleanly;
* attach the security middleware: request correlation ids, rate limiting,
  secure response headers, CORS and trusted hosts;
* expose consistent, non-leaking error responses;
* optionally serve the built SOC dashboard so a deployment is a single process.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .api.routes import api_router
from .api.websocket import routes as websocket_routes
from .api.websocket.manager import ConnectionManager
from .config.logging_config import get_logger, request_id_var, setup_logging
from .config.paths import default_paths
from .config.settings import Settings, get_settings
from .database.connection import healthcheck as db_healthcheck
from .database.models import Event
from .database.repository import Repository
from .security.ratelimit import SlidingWindowLimiter
from .services.bootstrap import Runtime, build_runtime

logger = get_logger(__name__)

#: Paths excluded from rate limiting (probes must never be throttled).
RATE_LIMIT_EXEMPT = {"/health", "/ready", "/api/v1/system/health", "/api/v1/system/ready"}
#: Paths classed as authentication for the stricter limit.
AUTH_PATHS = ("/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/bootstrap")

SECURE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)
#: How often aggregate network statistics are pushed on /ws/network.
NETWORK_PUSH_SECONDS = 5.0


def _frontend_dist() -> Path | None:
    """Return the built dashboard directory when it exists."""
    candidate = default_paths().home / "frontend" / "dist"
    if (candidate / "index.html").exists():
        return candidate
    return None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start the runtime and background tasks; tear everything down on exit."""
    settings: Settings = app.state.settings
    loop = asyncio.get_running_loop()
    manager: ConnectionManager = app.state.websocket_manager
    manager.bind_loop(loop)

    runtime: Runtime | None = None
    network_task: asyncio.Task | None = None
    try:
        runtime = build_runtime(
            settings,
            broadcaster=manager.broadcast_threadsafe,
            start_collection=app.state.start_collection,
        )
        runtime.websocket_manager = manager
        app.state.runtime = runtime

        async def _network_publisher() -> None:
            """Push network aggregates to /ws/network subscribers."""
            from .database.connection import session_scope

            while True:
                await asyncio.sleep(NETWORK_PUSH_SECONDS)
                if manager.count("network") == 0:
                    continue
                try:
                    with session_scope() as session:
                        repository = Repository(session)
                        payload = {
                            "type": "network.update",
                            "data": {
                                "events_per_second": repository.events_per_second(seconds=60),
                                "top_sources": repository.top_source_ips(minutes=60, limit=10),
                                "by_protocol": repository.event_volume_by_protocol(minutes=60),
                                "over_time": repository.timeseries(
                                    Event, "timestamp", minutes=60, buckets=12
                                ),
                            },
                        }
                    manager.publish("network", payload)
                except asyncio.CancelledError:  # pragma: no cover - shutdown
                    raise
                except Exception as exc:  # pragma: no cover - never kill the publisher
                    logger.warning("network publisher failed", extra={"error": str(exc)})

        network_task = asyncio.create_task(_network_publisher())
        logger.info(
            "Mini SOC started",
            extra={
                "version": __version__,
                "environment": settings.env,
                "collection": app.state.start_collection,
                "collectors": [getattr(c, "name", "?") for c in runtime.pipeline.collectors],
            },
        )
        yield
    finally:
        if network_task is not None:
            network_task.cancel()
            try:
                await network_task
            except (asyncio.CancelledError, Exception):  # pragma: no cover
                pass
        if runtime is not None:
            runtime.shutdown()
        await manager.close_all()
        logger.info("Mini SOC stopped")


def create_app(
    settings: Settings | None = None,
    *,
    start_collection: bool = True,
    serve_frontend: bool = True,
) -> FastAPI:
    """Build the application (tests call this with their own settings)."""
    settings = settings or get_settings()
    setup_logging(settings)
    settings.ensure_directories()

    app = FastAPI(
        title="Mini SOC",
        description="Real-time network security monitoring and threat detection platform",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.start_collection = start_collection
    app.state.websocket_manager = ConnectionManager(max_connections=settings.ws_max_connections)
    app.state.rate_limiter = SlidingWindowLimiter()
    app.state.runtime = None
    app.state.started_at = time.time()

    # ------------------------------------------------------------ middleware
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
            expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
        )
    if settings.trusted_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.trusted_hosts + (["testserver"] if settings.env != "production" else []),
        )

    @app.middleware("http")
    async def _context_middleware(request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request_id_var.set(request_id)
        started = time.perf_counter()

        # --------------------------------------------------- rate limiting
        path = request.url.path
        if not settings.rate_limit_per_minute or path in RATE_LIMIT_EXEMPT:
            limit_response = None
        else:
            limiter: SlidingWindowLimiter = app.state.rate_limiter
            from .api.deps import client_key  # local import avoids a cycle at module load

            key = client_key(request)
            if any(path.startswith(prefix) for prefix in AUTH_PATHS):
                result = limiter.check(
                    f"auth:{key}", limit=settings.login_rate_limit_per_minute, window_seconds=60
                )
            else:
                result = limiter.check(
                    f"api:{key}", limit=settings.rate_limit_per_minute, window_seconds=60
                )
            limit_response = None if result.allowed else result

        if limit_response is not None:
            logger.warning(
                "rate limit exceeded",
                extra={"client": limit_response.key, "path": path},
            )
            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "rate_limited",
                    "message": "too many requests",
                    "retry_after_seconds": int(limit_response.reset_after_seconds) + 1,
                },
            )
            _apply_headers(response, request_id, settings, None)
            response.headers.update(limit_response.headers())
            response.headers["Retry-After"] = str(int(limit_response.reset_after_seconds) + 1)
            return response

        try:
            response = await call_next(request)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "unhandled error in request",
                extra={"path": path, "error": f"{type(exc).__name__}: {exc}"},
                exc_info=True,
            )
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"error": "internal_error", "message": "internal server error", "request_id": request_id},
            )

        duration_ms = (time.perf_counter() - started) * 1000.0
        _apply_headers(response, request_id, settings, duration_ms)
        if request.method != "OPTIONS":
            logger.info(
                "request",
                extra={
                    "method": request.method,
                    "path": path,
                    "status": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                    "client": request.client.host if request.client else None,
                },
            )
        return response

    # ------------------------------------------------------- error handlers
    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict):
            content = detail
        else:
            content = {"error": "http_error", "message": str(detail)}
        content.setdefault("request_id", request_id_var.get())
        response = JSONResponse(status_code=exc.status_code, content=content)
        _apply_headers(response, request_id_var.get(), settings, None)
        return response

    @app.exception_handler(RequestValidationError)
    async def _validation_exception(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Only the location and message are returned - never the submitted value,
        # so a rejected password is not echoed back into logs or responses.
        problems = [
            {"field": ".".join(str(part) for part in error.get("loc", [])[1:]), "message": error.get("msg")}
            for error in exc.errors()[:20]
        ]
        response = JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "validation_error",
                "message": "request validation failed",
                "problems": problems,
                "request_id": request_id_var.get(),
            },
        )
        _apply_headers(response, request_id_var.get(), settings, None)
        return response

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:  # pragma: no cover
        logger.error(
            "unhandled exception",
            extra={"path": request.url.path, "error": f"{type(exc).__name__}: {exc}"},
            exc_info=True,
        )
        response = JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_error",
                "message": "internal server error",
                "request_id": request_id_var.get(),
            },
        )
        _apply_headers(response, request_id_var.get(), settings, None)
        return response

    # ---------------------------------------------------------------- routes
    app.include_router(api_router(), prefix=settings.api_prefix)
    app.include_router(websocket_routes.router)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, Any]:
        database = db_healthcheck()
        return {
            "status": "ok" if database["status"] == "ok" else "error",
            "version": __version__,
            "database": database["status"],
            "uptime_seconds": round(time.time() - app.state.started_at, 1),
        }

    @app.get("/ready", tags=["system"])
    async def ready() -> JSONResponse:
        database = db_healthcheck()
        code = status.HTTP_200_OK if database["status"] == "ok" else status.HTTP_503_SERVICE_UNAVAILABLE
        return JSONResponse(status_code=code, content={"status": "ready" if code == 200 else "not_ready"})

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, Any]:
        return {
            "name": "Mini SOC",
            "version": __version__,
            "api": settings.api_prefix,
            "docs": "/api/docs",
            "health": "/api/v1/system/health",
            "dashboard": "/app" if _frontend_dist() else "run the frontend dev server on :5173",
        }

    # ------------------------------------------------------------- dashboard
    dist = _frontend_dist() if serve_frontend else None
    if dist is not None:
        assets = dist / "assets"
        # Hashed bundles are referenced relative to the Vite ``base``. Serve both
        # the ``/app/assets`` (base=/app/) and plain ``/assets`` (base=/) layouts
        # so either build works when the API serves the dashboard itself.
        if assets.is_dir():
            app.mount("/app/assets", StaticFiles(directory=str(assets)), name="dashboard-assets")
            app.mount("/assets", StaticFiles(directory=str(assets)), name="dashboard-assets-root")

        @app.get("/app", include_in_schema=False)
        @app.get("/app/{path:path}", include_in_schema=False)
        async def dashboard_spa(path: str = "") -> Response:
            """Serve the SPA shell so client-side routes survive a refresh."""
            if path:
                candidate = (dist / path).resolve()
                if candidate.is_file() and dist.resolve() in candidate.parents:
                    return FileResponse(candidate)
            return FileResponse(dist / "index.html")

        logger.info("dashboard mounted", extra={"dist": str(dist)})

    return app


def _apply_headers(
    response: Response,
    request_id: str,
    settings: Settings,
    duration_ms: float | None,
) -> None:
    response.headers["X-Request-ID"] = request_id
    if duration_ms is not None:
        response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
    if settings.secure_headers:
        for header, value in SECURE_HEADERS.items():
            response.headers.setdefault(header, value)
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        if response.headers.get("content-type", "").startswith("application/json"):
            response.headers.setdefault("Cache-Control", "no-store")
        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )


#: Module-level application used by ``uvicorn app.main:app``.
app = create_app()


__all__ = ["app", "create_app", "lifespan"]
