"""Security tests (spec section 25/28): auth, RBAC, limits, headers, input."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.security.passwords import (
    PasswordPolicyError,
    ensure_password,
    generate_password,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.security.ratelimit import SlidingWindowLimiter
from app.security.tokens import (
    TokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME


class TestPasswordHandling:
    def test_hashes_are_salted_and_verifiable(self) -> None:
        first = hash_password("MiniSOC-Secret-2026!")
        second = hash_password("MiniSOC-Secret-2026!")
        assert first != second
        assert first.startswith("$2")
        assert verify_password("MiniSOC-Secret-2026!", first)
        assert not verify_password("wrong", first)

    def test_malformed_hash_never_raises(self) -> None:
        assert verify_password("x", "not-a-hash") is False
        assert verify_password("", "") is False

    @pytest.mark.parametrize(
        "password",
        ["short1!", "alllowercase123!", "ALLUPPERCASE123!", "NoDigitsHere!!", "NoSymbols12345", "password123"],
    )
    def test_policy_rejects_weak_passwords(self, password) -> None:
        assert validate_password_strength(password)

    def test_policy_rejects_password_containing_the_username(self) -> None:
        assert validate_password_strength("MiniSOC-Admin-2026!", username="admin")

    def test_policy_accepts_a_strong_password(self) -> None:
        assert validate_password_strength("MiniSOC-Core-2026!") == []
        assert ensure_password("MiniSOC-Core-2026!")

    def test_generated_passwords_satisfy_the_policy(self) -> None:
        for _ in range(5):
            assert validate_password_strength(generate_password()) == []

    def test_policy_error_is_raised_by_ensure(self) -> None:
        with pytest.raises(PasswordPolicyError):
            ensure_password("weak")


class TestTokens:
    def test_access_token_round_trip(self) -> None:
        token, expires = create_access_token(subject="analyst", role="ANALYST", secret="s" * 32)
        payload = decode_access_token(token, secret="s" * 32)
        assert payload["sub"] == "analyst"
        assert payload["role"] == "ANALYST"
        assert payload["exp"] > payload["iat"]
        assert expires is not None

    def test_wrong_secret_is_rejected(self) -> None:
        token, _ = create_access_token(subject="a", role="ADMIN", secret="s" * 32)
        with pytest.raises(TokenError):
            decode_access_token(token, secret="other" * 8)

    def test_tampered_token_is_rejected(self) -> None:
        token, _ = create_access_token(subject="a", role="VIEWER", secret="s" * 32)
        header, payload, signature = token.split(".")
        forged = f"{header}.{payload}.{'A' * len(signature)}"
        with pytest.raises(TokenError):
            decode_access_token(forged, secret="s" * 32)

    def test_expired_token_is_rejected(self) -> None:
        token, _ = create_access_token(
            subject="a", role="ADMIN", secret="s" * 32, expires_minutes=-1
        )
        with pytest.raises(TokenError):
            decode_access_token(token, secret="s" * 32)

    def test_refresh_tokens_are_opaque_and_hashed_for_storage(self) -> None:
        token = generate_refresh_token()
        digest = hash_refresh_token(token)
        assert token not in digest
        assert len(digest) == 64
        assert digest == hash_refresh_token(token)


class TestRateLimiter:
    def test_limit_is_enforced_within_the_window(self) -> None:
        limiter = SlidingWindowLimiter()
        for _ in range(3):
            assert limiter.check("k", limit=3, window_seconds=60).allowed
        blocked = limiter.check("k", limit=3, window_seconds=60)
        assert blocked.allowed is False
        assert blocked.reset_after_seconds > 0
        assert blocked.headers()["X-RateLimit-Remaining"] == "0"

    def test_zero_limit_disables_throttling(self) -> None:
        assert SlidingWindowLimiter().check("k", limit=0, window_seconds=60).allowed

    def test_window_expiry_allows_new_requests(self) -> None:
        limiter = SlidingWindowLimiter()
        assert limiter.check("k", limit=1, window_seconds=0.05).allowed
        assert limiter.check("k", limit=1, window_seconds=0.05).allowed is False
        time.sleep(0.1)
        assert limiter.check("k", limit=1, window_seconds=0.05).allowed


class TestApiThrottling:
    def test_repeated_logins_are_throttled(self, temp_home) -> None:
        from app.main import create_app

        settings = Settings(
            home=str(temp_home),
            database_url=f"sqlite+pysqlite:///{temp_home / 'data' / 'throttle.db'}",
            env="development",
            login_rate_limit_per_minute=3,
            rate_limit_per_minute=20,
            log_level="ERROR",
            log_json=False,
            collector_network_enabled=False,
            collector_syslog_enabled=False,
            collector_system_enabled=False,
            simulator_enabled=False,
            anomaly_enabled=False,
        )
        application = create_app(settings, start_collection=False)
        with TestClient(application) as client:
            statuses = [
                client.post(
                    "/api/v1/auth/login", json={"username": "nobody", "password": "wrong"}
                ).status_code
                for _ in range(5)
            ]
        assert 429 in statuses
        assert statuses.count(429) >= 1

    def test_rate_limited_response_advertises_retry_after(self, temp_home) -> None:
        from app.main import create_app

        settings = Settings(
            home=str(temp_home),
            database_url=f"sqlite+pysqlite:///{temp_home / 'data' / 'throttle2.db'}",
            env="development",
            login_rate_limit_per_minute=1,
            log_level="ERROR",
            log_json=False,
            collector_network_enabled=False,
            collector_syslog_enabled=False,
            collector_system_enabled=False,
            simulator_enabled=False,
            anomaly_enabled=False,
        )
        application = create_app(settings, start_collection=False)
        with TestClient(application) as client:
            client.post("/api/v1/auth/login", json={"username": "nobody", "password": "wrong"})
            blocked = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "wrong"})
        assert blocked.status_code == 429
        assert blocked.headers["Retry-After"]
        assert blocked.json()["error"] == "rate_limited"


class TestResponseHardening:
    def test_security_headers_are_present(self, client) -> None:
        response = client.get("/api/v1/system/health")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["X-Request-ID"]

    def test_api_responses_are_not_cached(self, client, auth_headers) -> None:
        response = client.get("/api/v1/dashboard/summary", headers=auth_headers)
        assert response.headers.get("Cache-Control") == "no-store"

    def test_errors_do_not_leak_internals(self, client) -> None:
        response = client.get("/api/v1/events/EVT-does-not-exist")
        body = response.text
        assert response.status_code in {401, 404}
        for leak in ("Traceback", "sqlite", "SQLAlchemy", "SELECT ", "site-packages"):
            assert leak not in body

    def test_validation_errors_do_not_echo_values(self, client, auth_headers) -> None:
        response = client.post("/api/v1/users", headers=auth_headers, json={"username": "x", "password": "y"})
        assert response.status_code == 422
        body = response.text
        assert "y" not in response.json().get("problems", [{}])[0].get("message", "")
        assert "Traceback" not in body

    def test_unexpected_fields_are_rejected(self, client, auth_headers) -> None:
        response = client.patch(
            "/api/v1/alerts/ALT-1", headers=auth_headers, json={"status": "ACKNOWLEDGED", "admin": True}
        )
        assert response.status_code == 422


class TestAccessControl:
    def test_viewer_cannot_change_alert_state(self, client, viewer_headers, engine) -> None:
        from app.database.base import utcnow
        from app.database.connection import session_scope
        from app.database.models import Alert

        with session_scope() as session:
            session.add(
                Alert(
                    alert_id="ALT-000777",
                    first_seen=utcnow(),
                    last_seen=utcnow(),
                    detection_type="PORT_SCAN",
                    dedupe_key="k",
                    severity="HIGH",
                    risk_score=70,
                )
            )
        assert client.get("/api/v1/alerts", headers=viewer_headers).status_code == 200
        response = client.patch(
            "/api/v1/alerts/ALT-000777", headers=viewer_headers, json={"status": "ACKNOWLEDGED"}
        )
        assert response.status_code == 403
        assert response.json()["error"] == "forbidden"

    def test_viewer_cannot_run_privileged_operations(self, client, viewer_headers) -> None:
        for path, payload in [
            ("/api/v1/rules/PORT_SCAN", {"threshold": 1}),
            ("/api/v1/system/simulator?scenario=normal", None),
        ]:
            method = client.patch if payload else client.post
            response = method(path, headers=viewer_headers, json=payload) if payload else method(path, headers=viewer_headers)
            assert response.status_code == 403

    def test_analyst_can_triage_but_not_administer(self, client, analyst_headers, engine, rules_synced) -> None:
        from app.database.base import utcnow
        from app.database.connection import session_scope
        from app.database.models import Alert

        with session_scope() as session:
            session.add(
                Alert(
                    alert_id="ALT-000888",
                    first_seen=utcnow(),
                    last_seen=utcnow(),
                    detection_type="BRUTE_FORCE",
                    dedupe_key="kb",
                    severity="HIGH",
                    risk_score=70,
                )
            )
        assert (
            client.patch(
                "/api/v1/alerts/ALT-000888", headers=analyst_headers, json={"status": "ACKNOWLEDGED"}
            ).status_code
            == 200
        )
        assert client.get("/api/v1/users", headers=analyst_headers).status_code == 403
        assert (
            client.patch(
                "/api/v1/rules/PORT_SCAN", headers=analyst_headers, json={"threshold": 1}
            ).status_code
            == 403
        )


class TestAuthHardening:
    def test_account_locks_after_repeated_failures(self, client, admin_user) -> None:
        for _ in range(6):
            client.post("/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": "wrong"})
        response = client.post(
            "/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        )
        assert response.status_code == 423
        assert response.json()["error"] == "account_locked"

    def test_refresh_tokens_rotate_and_cannot_be_reused(self, client, admin_user) -> None:
        first = client.post(
            "/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        ).json()
        refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert refreshed.status_code == 200
        replay = client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert replay.status_code == 401

    def test_logout_revokes_the_refresh_token(self, client, admin_user) -> None:
        tokens = client.post(
            "/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        ).json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        assert (
            client.post(
                "/api/v1/auth/logout",
                headers=headers,
                json={"refresh_token": tokens["refresh_token"]},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            ).status_code
            == 401
        )

    def test_tampered_access_token_is_rejected(self, client, admin_user) -> None:
        tokens = client.post(
            "/api/v1/auth/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
        ).json()
        forged = tokens["access_token"][:-4] + "AAAA"
        assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401

    def test_deactivated_user_token_is_refused(self, client, admin_user, auth_headers) -> None:
        from app.database.connection import session_scope
        from app.database.repository import Repository

        me = client.get("/api/v1/auth/me", headers=auth_headers).json()
        with session_scope() as session:
            user = Repository(session).get_user(me["id"])
            user.is_active = False
        assert client.get("/api/v1/auth/me", headers=auth_headers).status_code == 401


class TestInjectionResistance:
    @pytest.mark.parametrize(
        "payload",
        [
            "' OR 1=1 --",
            "'; DROP TABLE events; --",
            "1' UNION SELECT password_hash FROM users --",
            "<script>alert(1)</script>",
            "../../etc/passwd",
        ],
    )
    def test_search_filters_are_parameterised(self, client, auth_headers, payload) -> None:
        response = client.get("/api/v1/events", headers=auth_headers, params={"search": payload})
        assert response.status_code == 200
        assert response.json()["items"] == []

    def test_event_id_path_traversal_is_not_resolved(self, client, auth_headers) -> None:
        response = client.get("/api/v1/events/..%2F..%2Fetc%2Fpasswd", headers=auth_headers)
        assert response.status_code in {404, 422}
        assert "root:" not in response.text
