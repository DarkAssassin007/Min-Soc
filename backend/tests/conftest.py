"""Shared fixtures for the Mini SOC backend test suite.

Every test gets an isolated home directory and its own SQLite database, so the
suite never touches a developer's real data directory and tests can run in any
order (or in parallel) without interfering.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config.settings import Settings  # noqa: E402
from app.database.connection import configure_engine, dispose_engine  # noqa: E402
from app.database.models import Base  # noqa: E402
from app.database.repository import Repository  # noqa: E402
from app.security.passwords import hash_password  # noqa: E402

#: Credentials used by the bootstrap/login helpers in tests.
ADMIN_USERNAME = "admin-test"
ADMIN_PASSWORD = "MiniSOC-Test-2026!"


@pytest.fixture()
def temp_home(tmp_path: Path) -> Path:
    home = tmp_path / "mini-soc-home"
    (home / "data").mkdir(parents=True, exist_ok=True)
    (home / "ml" / "artifacts").mkdir(parents=True, exist_ok=True)
    (home / "detection-rules").mkdir(parents=True, exist_ok=True)
    return home


@pytest.fixture()
def settings(temp_home: Path) -> Settings:
    return Settings(
        home=str(temp_home),
        database_url=f"sqlite+pysqlite:///{temp_home / 'data' / 'test.db'}",
        env="development",
        log_level="WARNING",
        log_json=False,
        collector_network_enabled=False,
        collector_syslog_enabled=False,
        collector_system_enabled=False,
        simulator_enabled=False,
        anomaly_enabled=False,
        db_write_batch_size=25,
        ws_max_connections=25,
    )


@pytest.fixture()
def engine(settings: Settings) -> Iterator:
    engine = configure_engine(settings=settings)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    dispose_engine()


@pytest.fixture()
def session(settings: Settings, engine) -> Iterator[Session]:
    from app.database.connection import get_session_factory

    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def repository(session: Session) -> Repository:
    return Repository(session)


@pytest.fixture()
def admin_user(settings: Settings, engine):
    from app.database.connection import session_scope

    with session_scope() as session:
        repository = Repository(session)
        return repository.create_user(
            username=ADMIN_USERNAME,
            password_hash=hash_password(ADMIN_PASSWORD),
            role="ADMIN",
            email="admin@example.invalid",
        )


@pytest.fixture()
def rules_synced(settings: Settings, engine) -> dict:
    """Load the real rule packs into the test database."""
    from app.database.connection import session_scope
    from app.services.bootstrap import sync_detection_rules

    with session_scope() as session:
        return sync_detection_rules(settings, Repository(session))


@pytest.fixture()
def client(settings: Settings) -> Iterator[TestClient]:
    """API client with the runtime assembled but collectors stopped."""
    from app.main import create_app

    application = create_app(settings, start_collection=False)
    with TestClient(application) as test_client:
        yield test_client


@pytest.fixture()
def auth_headers(client: TestClient, admin_user) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture()
def analyst_headers(client: TestClient, admin_user) -> dict[str, str]:
    from app.database.connection import session_scope

    with session_scope() as session:
        Repository(session).create_user(
            username="analyst-test",
            password_hash=hash_password("MiniSOC-Analyst-2026!"),
            role="ANALYST",
        )
    response = client.post(
        "/api/v1/auth/login", json={"username": "analyst-test", "password": "MiniSOC-Analyst-2026!"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture()
def viewer_headers(client: TestClient, admin_user) -> dict[str, str]:
    from app.database.connection import session_scope

    with session_scope() as session:
        Repository(session).create_user(
            username="viewer-test",
            password_hash=hash_password("MiniSOC-Viewer-2026!"),
            role="VIEWER",
        )
    response = client.post(
        "/api/v1/auth/login", json={"username": "viewer-test", "password": "MiniSOC-Viewer-2026!"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


# --------------------------------------------------------------------------
# helpers shared by detection/pipeline tests
# --------------------------------------------------------------------------
@pytest.fixture()
def make_record():
    """Build a RawRecord for pipeline tests."""

    def _make(**overrides):
        from datetime import datetime, timezone

        from app.processors.models import RawRecord

        payload = {
            "source_ip": "192.168.50.10",
            "destination_ip": "192.168.50.1",
            "source_port": 40000,
            "destination_port": 443,
            "protocol": "TCP",
            "bytes": 800,
            "packet_count": 5,
            "connection_state": "ESTABLISHED",
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None),
        }
        payload.update(overrides.pop("payload", {}))
        return RawRecord(
            collector=overrides.pop("collector", "synthetic"),
            received_at=datetime.now(timezone.utc).replace(tzinfo=None),
            event_type=overrides.pop("event_type", "NETWORK_CONNECTION"),
            payload=payload,
            interface=overrides.pop("interface", None),
        )

    return _make


@pytest.fixture()
def make_event():
    """Build a NormalizedEvent directly (bypasses collectors)."""

    def _make(source_ip="192.168.50.10", **overrides):
        from datetime import datetime, timezone

        from app.processors.models import NormalizedEvent

        payload = {
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None),
            "source_ip": source_ip,
            "destination_ip": "192.168.50.1",
            "source_port": 40000,
            "destination_port": 22,
            "protocol": "TCP",
            "packet_count": 1,
            "bytes": 120,
            "connection_state": "FAILED",
            "event_type": "NETWORK_CONNECTION",
            "direction": "internal",
            "collector": "synthetic",
            "metadata": {},
            "network": {},
        }
        payload.update(overrides)
        return NormalizedEvent(**payload)

    return _make
