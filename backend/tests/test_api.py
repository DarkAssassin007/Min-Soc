"""HTTP API integration tests (spec section 23)."""

from __future__ import annotations

import pytest

from app.database.connection import session_scope
from app.database.models import Alert, Event, Incident
from app.database.repository import Repository

PUBLIC_PATHS = ["/api/v1/system/health", "/health", "/ready", "/"]


class TestPublicEndpoints:
    @pytest.mark.parametrize("path", PUBLIC_PATHS)
    def test_public_paths_answer_without_authentication(self, client, path) -> None:
        response = client.get(path)
        assert response.status_code == 200
        assert response.json()

    def test_health_reports_components(self, client) -> None:
        body = client.get("/api/v1/system/health").json()
        assert body["status"] in {"ok", "degraded"}
        assert "database" in body["components"]
        assert body["version"]

    def test_readiness_probe(self, client) -> None:
        assert client.get("/api/v1/system/ready").json()["status"] == "ready"

    def test_protected_endpoints_require_a_token(self, client) -> None:
        for path in ["/api/v1/events", "/api/v1/alerts", "/api/v1/incidents", "/api/v1/dashboard/summary"]:
            assert client.get(path).status_code == 401

    def test_openapi_schema_is_served(self, client) -> None:
        assert client.get("/api/openapi.json").status_code == 200


class TestAuthentication:
    def test_login_returns_tokens_and_user(self, client, admin_user) -> None:
        from conftest import ADMIN_PASSWORD, ADMIN_USERNAME

        body = client.post(
            "/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        ).json()
        assert body["access_token"] and body["refresh_token"]
        assert body["token_type"] == "bearer"
        assert body["user"]["role"] == "ADMIN"
        assert "password" not in str(body)

    def test_wrong_password_is_rejected_without_user_enrichment(self, client, admin_user) -> None:
        from conftest import ADMIN_USERNAME

        response = client.post("/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": "nope"})
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_credentials"

    def test_unknown_user_is_rejected_identically(self, client, admin_user) -> None:
        response = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "nope"})
        assert response.status_code == 401
        assert response.json()["message"] == "invalid username or password"

    def test_me_returns_the_current_user(self, client, auth_headers) -> None:
        body = client.get("/api/v1/auth/me", headers=auth_headers).json()
        assert body["username"]
        assert body["role"] == "ADMIN"

    def test_bootstrap_is_only_possible_once(self, client, admin_user) -> None:
        response = client.post(
            "/api/v1/auth/bootstrap", json={"username": "other", "password": "MiniSOC-Other-2026!"}
        )
        assert response.status_code == 409

    def test_bootstrap_rejects_weak_passwords(self, settings) -> None:
        from fastapi.testclient import TestClient

        from app.main import create_app

        application = create_app(settings, start_collection=False)
        with TestClient(application) as fresh:
            response = fresh.post(
                "/api/v1/auth/bootstrap", json={"username": "admin", "password": "password123"}
            )
        assert response.status_code == 422
        assert response.json()["error"] == "weak_password"


class TestEventsApi:
    @pytest.fixture(autouse=True)
    def seed_events(self, engine):
        from app.database.base import utcnow

        with session_scope() as session:
            repository = Repository(session)
            for index in range(5):
                repository.add_event(
                    Event(
                        event_id=f"EVT-{index:06d}",
                        timestamp=utcnow(),
                        source_ip=f"10.0.0.{index + 1}",
                        destination_ip="10.0.0.250",
                        destination_port=443,
                        protocol="TCP",
                        event_type="NETWORK_CONNECTION",
                        severity="HIGH" if index == 0 else "LOW",
                        risk_score=70 if index == 0 else 5,
                    )
                )

    def test_list_returns_pagination_envelope(self, client, auth_headers) -> None:
        body = client.get("/api/v1/events", headers=auth_headers).json()
        assert body["total"] == 5
        assert len(body["items"]) == 5
        assert body["has_more"] is False

    def test_filter_by_source_and_severity(self, client, auth_headers) -> None:
        assert client.get("/api/v1/events?source_ip=10.0.0.1", headers=auth_headers).json()["total"] == 1
        assert client.get("/api/v1/events?severity=HIGH", headers=auth_headers).json()["total"] == 1
        assert client.get("/api/v1/events?min_risk=60", headers=auth_headers).json()["total"] == 1

    def test_search_and_pagination_clamping(self, client, auth_headers) -> None:
        body = client.get("/api/v1/events?search=10.0.0.250&limit=1000", headers=auth_headers).json()
        assert body["total"] == 5
        assert body["limit"] <= 500

    def test_detail_includes_detections_and_network_block(self, client, auth_headers) -> None:
        body = client.get("/api/v1/events/EVT-000000", headers=auth_headers).json()
        assert body["event_id"] == "EVT-000000"
        assert "detections" in body
        assert "network" in body

    def test_unknown_event_returns_404(self, client, auth_headers) -> None:
        response = client.get("/api/v1/events/EVT-999999", headers=auth_headers)
        assert response.status_code == 404
        assert response.json()["error"] == "not_found"

    def test_related_events_endpoint(self, client, auth_headers) -> None:
        body = client.get("/api/v1/events/EVT-000000/related", headers=auth_headers).json()
        assert isinstance(body["items"], list)


class TestAlertsApi:
    @pytest.fixture(autouse=True)
    def seed_alert(self, engine):
        from app.database.base import utcnow

        with session_scope() as session:
            session.add(
                Alert(
                    alert_id="ALT-000001",
                    first_seen=utcnow(),
                    last_seen=utcnow(),
                    source_ip="192.168.50.201",
                    destination_ip="192.168.50.1",
                    detection_type="PORT_SCAN",
                    rule_key="PORT_SCAN",
                    engine="RULE",
                    risk_score=72.5,
                    severity="HIGH",
                    confidence=0.8,
                    description="Port scan detected",
                    evidence={"reasons": ["PORT_SCAN matched"], "classification": "RECONNAISSANCE"},
                    recommended_action="isolate the host",
                    status="NEW",
                    dedupe_key="PORT_SCAN|192.168.50.201|192.168.50.1",
                    event_count=3,
                )
            )

    def test_list_and_filters(self, client, auth_headers) -> None:
        assert client.get("/api/v1/alerts", headers=auth_headers).json()["total"] == 1
        assert client.get("/api/v1/alerts?severity=HIGH", headers=auth_headers).json()["total"] == 1
        assert client.get("/api/v1/alerts?severity=LOW", headers=auth_headers).json()["total"] == 0
        assert client.get("/api/v1/alerts?status=NEW", headers=auth_headers).json()["total"] == 1
        assert client.get("/api/v1/alerts?source_ip=192.168.50.201", headers=auth_headers).json()["total"] == 1

    def test_detail_contains_trace_and_recommendation(self, client, auth_headers) -> None:
        body = client.get("/api/v1/alerts/ALT-000001", headers=auth_headers).json()
        assert body["detections"] == []
        assert body["evidence"]["classification"] == "RECONNAISSANCE"
        assert body["recommended_action"]

    def test_statistics_endpoint(self, client, auth_headers) -> None:
        body = client.get("/api/v1/alerts/statistics", headers=auth_headers).json()
        assert body["totals"]["total"] == 1
        assert body["by_detection_type"]

    def test_lifecycle_update_then_illegal_transition(self, client, auth_headers) -> None:
        ack = client.patch(
            "/api/v1/alerts/ALT-000001", headers=auth_headers, json={"status": "ACKNOWLEDGED"}
        )
        assert ack.status_code == 200
        assert ack.json()["status"] == "ACKNOWLEDGED"
        resolved = client.patch(
            "/api/v1/alerts/ALT-000001",
            headers=auth_headers,
            json={"status": "RESOLVED", "resolution": "isolated", "note": "handled"},
        )
        assert resolved.status_code == 200
        assert resolved.json()["resolution"] == "isolated"
        blocked = client.patch(
            "/api/v1/alerts/ALT-000001", headers=auth_headers, json={"status": "ACKNOWLEDGED"}
        )
        assert blocked.status_code == 409

    def test_invalid_status_is_a_validation_error(self, client, auth_headers) -> None:
        response = client.patch(
            "/api/v1/alerts/ALT-000001", headers=auth_headers, json={"status": "ON_FIRE"}
        )
        assert response.status_code == 422
        assert response.json()["error"] == "validation_error"

    def test_notes_can_be_added_and_listed(self, client, auth_headers) -> None:
        created = client.post(
            "/api/v1/alerts/ALT-000001/notes",
            headers=auth_headers,
            json={"note": "checked the switch logs", "action_taken": "ANALYST_NOTE"},
        )
        assert created.status_code == 200
        listing = client.get("/api/v1/alerts/ALT-000001/notes", headers=auth_headers).json()
        assert listing["items"][0]["note"] == "checked the switch logs"

    def test_assignment_requires_an_existing_user(self, client, auth_headers) -> None:
        assert (
            client.post(
                "/api/v1/alerts/ALT-000001/assign", headers=auth_headers, json={"user_id": 999}
            ).status_code
            == 404
        )
        body = client.get("/api/v1/auth/me", headers=auth_headers).json()
        assigned = client.post(
            "/api/v1/alerts/ALT-000001/assign", headers=auth_headers, json={"user_id": body["id"]}
        )
        assert assigned.status_code == 200
        assert assigned.json()["assignee_id"] == body["id"]

    def test_unknown_alert_returns_404(self, client, auth_headers) -> None:
        assert client.get("/api/v1/alerts/ALT-999999", headers=auth_headers).status_code == 404


class TestIncidentsApi:
    @pytest.fixture(autouse=True)
    def seed_incident(self, engine):
        from app.database.base import utcnow

        with session_scope() as session:
            session.add(
                Incident(
                    incident_id="INC-0001",
                    title="Reconnaissance activity from 192.168.50.201",
                    summary="opened from alert ALT-000001",
                    severity="HIGH",
                    risk_score=80.0,
                    status="OPEN",
                    source_entities=["192.168.50.201"],
                    destination_entities=["192.168.50.1"],
                    detection_types=["PORT_SCAN"],
                    timeline=[{"timestamp": utcnow().isoformat(), "event": "incident_created", "description": "seeded"}],
                    alert_count=1,
                )
            )

    def test_list_and_detail(self, client, auth_headers) -> None:
        assert client.get("/api/v1/incidents", headers=auth_headers).json()["total"] == 1
        body = client.get("/api/v1/incidents/INC-0001", headers=auth_headers).json()
        assert body["alerts"] == []
        assert body["timeline"]

    def test_lifecycle_and_notes(self, client, auth_headers) -> None:
        assert (
            client.patch(
                "/api/v1/incidents/INC-0001", headers=auth_headers, json={"status": "INVESTIGATING"}
            ).status_code
            == 200
        )
        note = client.post(
            "/api/v1/incidents/INC-0001/notes", headers=auth_headers, json={"note": "blocked the source"}
        )
        assert note.status_code == 200
        done = client.patch(
            "/api/v1/incidents/INC-0001",
            headers=auth_headers,
            json={"status": "RESOLVED", "resolution": "source blocked"},
        )
        assert done.json()["resolution"] == "source blocked"

    def test_manual_incident_creation_with_unknown_alert_is_rejected(self, client, auth_headers) -> None:
        response = client.post(
            "/api/v1/incidents",
            headers=auth_headers,
            json={"title": "Manual incident", "severity": "HIGH", "alert_ids": ["ALT-404"]},
        )
        assert response.status_code == 404


class TestAnalyticsAndNetworkApi:
    def test_dashboard_summary_shape(self, client, auth_headers) -> None:
        body = client.get("/api/v1/dashboard/summary", headers=auth_headers).json()
        for key in ("events", "alerts", "incidents", "network_activity", "threat_activity", "recent_alerts"):
            assert key in body
        assert set(body["alerts"]) >= {"total", "active", "critical"}

    def test_network_endpoints(self, client, auth_headers) -> None:
        traffic = client.get("/api/v1/network/traffic", headers=auth_headers).json()
        assert "events_over_time" in traffic
        statistics = client.get("/api/v1/network/statistics", headers=auth_headers).json()
        assert "protocol_distribution" in statistics

    def test_threats_and_analytics_endpoints(self, client, auth_headers) -> None:
        threats = client.get("/api/v1/threats", headers=auth_headers).json()
        assert "top_threat_sources" in threats
        analytics = client.get("/api/v1/analytics", headers=auth_headers).json()
        assert {"events_over_time", "alerts_over_time", "rule_frequency"} <= set(analytics)

    def test_asset_upsert_validates_the_address(self, client, auth_headers) -> None:
        created = client.put(
            "/api/v1/network/assets/192.168.50.10",
            headers=auth_headers,
            json={"hostname": "app-01", "importance": 5},
        )
        assert created.status_code == 200
        assert created.json()["importance"] == 5
        assert (
            client.put("/api/v1/network/assets/not-an-ip", headers=auth_headers, json={}).status_code == 422
        )


class TestRulesAndModelsApi:
    def test_rules_are_listed_from_the_packs(self, client, auth_headers, rules_synced) -> None:
        body = client.get("/api/v1/rules", headers=auth_headers).json()
        keys = {item["rule_key"] for item in body["items"]}
        assert "PORT_SCAN" in keys and "BRUTE_FORCE" in keys

    def test_rule_update_requires_admin(self, client, analyst_headers, rules_synced) -> None:
        response = client.patch(
            "/api/v1/rules/PORT_SCAN", headers=analyst_headers, json={"threshold": 99}
        )
        assert response.status_code == 403

    def test_rule_update_changes_configuration_and_version(self, client, auth_headers, rules_synced) -> None:
        before = client.get("/api/v1/rules/PORT_SCAN", headers=auth_headers).json()
        updated = client.patch(
            "/api/v1/rules/PORT_SCAN",
            headers=auth_headers,
            json={"threshold": 42, "window_seconds": 120, "params": {"unique_ports": 42}},
        )
        assert updated.status_code == 200
        body = updated.json()
        assert body["threshold"] == 42
        assert body["window_seconds"] == 120
        assert body["params"]["unique_ports"] == 42
        assert body["version"] > before["version"]

    def test_rule_can_be_disabled_and_reenabled(self, client, auth_headers, rules_synced) -> None:
        assert (
            client.patch("/api/v1/rules/DNS_ANOMALY", headers=auth_headers, json={"enabled": False})
            .json()["enabled"]
            is False
        )
        assert (
            client.patch("/api/v1/rules/DNS_ANOMALY", headers=auth_headers, json={"enabled": True})
            .json()["enabled"]
            is True
        )

    def test_unknown_rule_returns_404(self, client, auth_headers, rules_synced) -> None:
        assert client.get("/api/v1/rules/NOPE", headers=auth_headers).status_code == 404

    def test_models_endpoint_reports_detector_state(self, client, auth_headers) -> None:
        body = client.get("/api/v1/models", headers=auth_headers).json()
        assert "detector" in body
        assert "artifacts" in body

    def test_activating_an_unknown_model_is_rejected(self, client, auth_headers) -> None:
        response = client.post("/api/v1/models/activate", headers=auth_headers, json={"version": "v99"})
        assert response.status_code == 404


class TestAdministrationApi:
    def test_users_listing_requires_admin(self, client, viewer_headers) -> None:
        assert client.get("/api/v1/users", headers=viewer_headers).status_code == 403

    def test_user_creation_and_update(self, client, auth_headers) -> None:
        created = client.post(
            "/api/v1/users",
            headers=auth_headers,
            json={"username": "soc.analyst", "password": "MiniSOC-Analyst-2026!", "role": "ANALYST"},
        )
        assert created.status_code == 201
        user_id = created.json()["id"]
        updated = client.patch(
            f"/api/v1/users/{user_id}", headers=auth_headers, json={"is_active": False}
        )
        assert updated.json()["is_active"] is False
        assert client.get("/api/v1/users", headers=auth_headers).json()["total"] >= 2

    def test_weak_passwords_are_refused(self, client, auth_headers) -> None:
        response = client.post(
            "/api/v1/users", headers=auth_headers, json={"username": "weak", "password": "password123"}
        )
        assert response.status_code == 422

    def test_duplicate_username_conflicts(self, client, auth_headers) -> None:
        client.post(
            "/api/v1/users",
            headers=auth_headers,
            json={"username": "dupe", "password": "MiniSOC-Conflict-2026!", "role": "VIEWER"},
        )
        response = client.post(
            "/api/v1/users",
            headers=auth_headers,
            json={"username": "dupe", "password": "MiniSOC-Conflict-2026!", "role": "VIEWER"},
        )
        assert response.status_code == 409

    def test_system_logs_and_audit_require_admin(self, client, auth_headers, analyst_headers) -> None:
        assert client.get("/api/v1/system/logs", headers=analyst_headers).status_code == 403
        logs = client.get("/api/v1/system/logs", headers=auth_headers).json()
        assert isinstance(logs["items"], list)
        audit = client.get("/api/v1/system/audit", headers=auth_headers).json()
        assert isinstance(audit["items"], list)

    def test_metrics_endpoint_reports_pipeline_state(self, client, auth_headers) -> None:
        body = client.get("/api/v1/system/metrics", headers=auth_headers).json()
        assert "pipeline" in body
        assert "detection" in body
        assert "latency" in body

    def test_retention_purge_dry_run_is_available_to_admins(self, client, auth_headers) -> None:
        response = client.post("/api/v1/system/maintenance/purge?days=30&dry_run=true", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["detail"]["dry_run"] is True

    def test_simulator_is_refused_in_real_time_only_deployments(
        self, client, auth_headers, analyst_headers
    ) -> None:
        """No synthetic data path exists unless the operator explicitly opts in."""
        assert (
            client.post("/api/v1/system/simulator?scenario=normal", headers=analyst_headers).status_code == 403
        )
        refused = client.post(
            "/api/v1/system/simulator?scenario=normal&eps=20", headers=auth_headers
        )
        assert refused.status_code == 403
        assert refused.json()["error"] == "simulator_disabled"

    def test_simulator_control_requires_admin_and_validates_scenario(self, settings, admin_user) -> None:
        from fastapi.testclient import TestClient

        from app.main import create_app
        from conftest import ADMIN_PASSWORD, ADMIN_USERNAME

        lab_settings = settings.model_copy(update={"simulator_enabled": True})
        application = create_app(lab_settings, start_collection=False)
        with TestClient(application) as lab:
            login = lab.post(
                "/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
            )
            assert login.status_code == 200
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

            assert lab.post("/api/v1/system/simulator?scenario=nope", headers=headers).status_code == 422
            started = lab.post("/api/v1/system/simulator?scenario=normal&eps=20", headers=headers)
            assert started.status_code == 200
            stopped = lab.post("/api/v1/system/simulator?action=stop", headers=headers)
            assert stopped.json()["message"] == "simulator stopped"
