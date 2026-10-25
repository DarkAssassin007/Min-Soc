"""Alert management, deduplication, lifecycle and incident correlation."""

from __future__ import annotations

import pytest

from app.alerts.incident import IncidentManager
from app.alerts.manager import AlertManager
from app.database.context import RepositoryProxy
from app.database.enums import AlertStatus, IncidentStatus
from app.database.models import Event
from app.database.repository import Repository, RepositoryError
from app.detection.correlation.correlator import Correlator
from app.detection.engine import DetectionResult
from app.detection.base import RuleResult
from app.processors.feature_engineering import FeatureExtractor
from app.risk.scoring import RiskAssessment


@pytest.fixture()
def proxy(session) -> RepositoryProxy:
    return RepositoryProxy(Repository(session))


@pytest.fixture()
def incidents(proxy, settings) -> IncidentManager:
    return IncidentManager(proxy, settings)


@pytest.fixture()
def correlator(proxy, incidents, settings) -> Correlator:
    return Correlator(proxy, incidents, settings)


@pytest.fixture()
def manager(proxy, settings, correlator) -> AlertManager:
    return AlertManager(proxy, settings, correlator=correlator, min_score=10.0)


def make_event_row(session, event_id="EVT-000001", **overrides) -> Event:
    from app.database.base import utcnow

    payload = {
        "event_id": event_id,
        "timestamp": utcnow(),
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.1",
        "destination_port": 22,
        "protocol": "TCP",
        "event_type": "AUTH_FAILURE",
        "severity": "MEDIUM",
        "risk_score": 45.0,
    }
    payload.update(overrides)
    event = Event(**payload)
    session.add(event)
    session.flush()
    return event


def detection_result(score=60.0, rule_key="BRUTE_FORCE", detection_type="BRUTE_FORCE") -> DetectionResult:
    return DetectionResult(
        rule_hits=[
            RuleResult(
                rule_key=rule_key,
                detection_type=detection_type,
                score=score,
                confidence=0.8,
                description="repeated authentication failures",
                evidence={"failed_authentications": 12},
                recommended_action="reset the password",
                severity_hint="HIGH",
            )
        ]
    )


def assessment(score=65.0, severity="HIGH") -> RiskAssessment:
    return RiskAssessment(
        score=score,
        severity=severity,
        confidence=0.8,
        classification="CREDENTIAL_ACCESS",
        components={"rule": score},
        reasons=["BRUTE_FORCE matched"],
    )


class TestAlertManager:
    def test_creates_an_alert_for_a_detection(
        self, session, manager, repository, make_event
    ) -> None:
        event = make_event_row(session)
        outcome = manager.process(event, make_event(), detection_result(), assessment(), [])
        assert outcome.created is True
        assert outcome.alert is not None
        assert outcome.alert.alert_id.startswith("ALT-")
        assert outcome.alert.status == AlertStatus.NEW.value
        assert outcome.alert.source_ip == "10.0.0.5"
        assert repository.get_alert(outcome.alert.alert_id) is not None

    def test_identical_detections_are_deduplicated(
        self, session, manager, make_event
    ) -> None:
        first = manager.process(make_event_row(session), make_event(), detection_result(), assessment(), [])
        second = manager.process(
            make_event_row(session, event_id="EVT-000002"), make_event(), detection_result(), assessment(), []
        )
        assert second.created is False
        assert second.updated is True
        assert second.alert.alert_id == first.alert.alert_id
        assert second.alert.event_count == 2
        assert manager.statistics()["deduplicated_updates"] == 1

    def test_scores_below_the_threshold_are_suppressed(self, session, manager, make_event) -> None:
        outcome = manager.process(
            make_event_row(session), make_event(), detection_result(score=30), assessment(score=5), []
        )
        assert outcome.alert is None
        assert "below alert threshold" in outcome.reason

    def test_no_detection_means_no_alert(self, session, manager, make_event) -> None:
        outcome = manager.process(
            make_event_row(session), make_event(), DetectionResult(), assessment(), []
        )
        assert outcome.alert is None

    def test_lifecycle_transitions_are_enforced(self, session, manager, make_event, admin_user) -> None:
        outcome = manager.process(make_event_row(session), make_event(), detection_result(), assessment(), [])
        alert_id = outcome.alert.alert_id
        manager.set_status(alert_id, AlertStatus.ACKNOWLEDGED.value, actor_id=admin_user.id)
        manager.set_status(alert_id, AlertStatus.INVESTIGATING.value, actor_id=admin_user.id)
        resolved = manager.set_status(
            alert_id, AlertStatus.RESOLVED.value, actor_id=admin_user.id, resolution="password rotated", note="done"
        )
        assert resolved.status == AlertStatus.RESOLVED.value
        assert resolved.resolved_at is not None
        with pytest.raises(RepositoryError):
            manager.set_status(alert_id, AlertStatus.ACKNOWLEDGED.value)
        notes = Repository(session).list_notes(alert_id=alert_id)
        assert any(note.note == "done" for note in notes)

    def test_invalid_status_is_rejected(self, session, manager, make_event) -> None:
        outcome = manager.process(make_event_row(session), make_event(), detection_result(), assessment(), [])
        with pytest.raises(RepositoryError):
            manager.set_status(outcome.alert.alert_id, "ON_FIRE")

    def test_listeners_receive_created_and_updated_events(self, session, manager, make_event) -> None:
        seen = []
        manager.add_listener(lambda action, payload: seen.append((action, payload["alert_id"])))
        manager.process(make_event_row(session), make_event(), detection_result(), assessment(), [])
        manager.process(
            make_event_row(session, event_id="EVT-000009"), make_event(), detection_result(), assessment(), []
        )
        assert [action for action, _ in seen] == ["alert.created", "alert.updated"]

    def test_detections_are_linked_to_the_alert(self, session, manager, make_event) -> None:
        from app.database.models import Detection

        detection = Detection(
            detection_id="DET-000001",
            event_id="EVT-000001",
            rule_key="BRUTE_FORCE",
            detection_type="BRUTE_FORCE",
            rule_score=60,
            confidence=0.8,
        )
        session.add(detection)
        event = make_event_row(session)
        outcome = manager.process(event, make_event(), detection_result(), assessment(), [detection])
        assert detection.alert_id == outcome.alert.alert_id

    def test_audit_entry_is_written_for_created_alerts(self, session, manager, make_event) -> None:
        manager.process(make_event_row(session), make_event(), detection_result(), assessment(), [])
        logs = Repository(session).list_system_logs(limit=10)
        assert any("alert" in entry.message for entry in logs)


class TestCorrelator:
    def test_high_severity_alert_opens_an_incident(self, session, manager, make_event, proxy) -> None:
        outcome = manager.process(
            make_event_row(session), make_event(), detection_result(), assessment(score=85, severity="CRITICAL"), []
        )
        assert outcome.alert.incident_id is not None
        incident = Repository(session).get_incident(outcome.alert.incident_id)
        assert incident is not None
        assert incident.alert_count == 1
        assert incident.status == IncidentStatus.OPEN.value
        assert incident.timeline

    def test_medium_alert_without_correlation_stays_standalone(self, session, manager, make_event) -> None:
        outcome = manager.process(
            make_event_row(session), make_event(), detection_result(), assessment(score=45, severity="MEDIUM"), []
        )
        assert outcome.alert.incident_id is None

    def test_multiple_detection_types_from_one_source_open_an_incident(
        self, session, manager, make_event, repository
    ) -> None:
        # Three medium alerts, two distinct detection types, same source. Each
        # event targets a different destination so the two PORT_SCAN detections
        # are not folded together by alert deduplication.
        for index, detection_type in enumerate(["PORT_SCAN", "PORT_SCAN", "FAILED_CONNECTIONS"]):
            outcome = manager.process(
                make_event_row(session, event_id=f"EVT-1000{index}", destination_port=1000 + index),
                make_event(destination_ip=f"10.0.0.{index + 2}"),
                detection_result(score=50, detection_type=detection_type),
                assessment(score=45, severity="MEDIUM"),
                [],
            )
        alerts = repository.list_alerts(limit=10)
        assert any(alert.incident_id for alert in alerts)

    def test_new_alerts_join_an_open_incident_for_the_same_source(self, session, manager, make_event, proxy) -> None:
        first = manager.process(
            make_event_row(session), make_event(), detection_result(), assessment(score=88, severity="CRITICAL"), []
        )
        second = manager.process(
            make_event_row(session, event_id="EVT-000500", destination_port=3389),
            make_event(),
            detection_result(rule_key="SUSPICIOUS_PROTOCOL", detection_type="SUSPICIOUS_PROTOCOL"),
            assessment(score=70, severity="HIGH"),
            [],
        )
        assert second.alert.incident_id == first.alert.incident_id
        incident = Repository(session).get_incident(first.alert.incident_id)
        assert incident.alert_count == 2
        assert len(incident.detection_types) == 2


class TestIncidentManager:
    def test_status_lifecycle_and_notes(self, session, incidents, admin_user) -> None:
        incident = incidents.create(
            title="Suspicious activity",
            severity="HIGH",
            risk_score=70,
            summary="test",
            source_entities=["10.0.0.5"],
        )
        incidents.set_status(incident.incident_id, IncidentStatus.INVESTIGATING.value, actor_id=admin_user.id)
        incidents.note(incident.incident_id, "reviewed the firewall logs", author_id=admin_user.id)
        resolved = incidents.set_status(
            incident.incident_id,
            IncidentStatus.RESOLVED.value,
            actor_id=admin_user.id,
            resolution="host isolated",
            note="done",
        )
        assert resolved.resolution == "host isolated"
        assert resolved.closed_at is not None
        assert len(resolved.timeline) >= 4
        with pytest.raises(RepositoryError):
            incidents.set_status(incident.incident_id, IncidentStatus.OPEN.value)

    def test_merge_moves_alerts_and_closes_the_other(self, session, incidents) -> None:
        from app.database.models import Alert

        target = incidents.create(title="Primary", severity="HIGH", risk_score=80, source_entities=["10.0.0.5"])
        other = incidents.create(title="Secondary", severity="MEDIUM", risk_score=50, source_entities=["10.0.0.5"])
        alert = Alert(
            alert_id="ALT-000042",
            detection_type="PORT_SCAN",
            dedupe_key="k",
            severity="HIGH",
            risk_score=80,
            source_ip="10.0.0.5",
        )
        session.add(alert)
        session.flush()
        incidents.attach_alert(other, alert)
        incidents.merge(target, other)
        assert alert.incident_id == target.incident_id
        assert other.status == IncidentStatus.CLOSED.value
        assert "merged into" in (other.resolution or "")
        assert incidents.statistics()["created"] == 2
