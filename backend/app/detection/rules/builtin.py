"""Threshold and behavioural detection rules (spec section 8)."""

from __future__ import annotations

from datetime import timedelta

from ...database.enums import ConnectionState, EventType, Protocol, SeverityLevel
from ...processors.normalizer import is_private
from ..base import BaseRule, RuleContext, RuleResult


class PortScanRule(BaseRule):
    """One source touching many destination ports in a short window."""

    rule_key = "PORT_SCAN"
    detection_type = "PORT_SCAN"
    default_severity_hint = SeverityLevel.HIGH.value
    default_params = {
        "unique_ports": 15,
        "unique_destinations": 1,
        "min_connections": 15,
        "syn_ratio": 0.5,
        "score_ceiling": 80,
    }
    default_recommended_action = (
        "Identify the scanning host, confirm whether the scan was authorised "
        "(vulnerability scanner or inventory tool) and isolate the host if not."
    )

    def evaluate(self, context: RuleContext) -> RuleResult | None:
        event, features = context.event, context.features
        params = self.params(context)
        if event.event_type not in {
            EventType.NETWORK_CONNECTION.value,
            EventType.FIREWALL_DENY.value,
        }:
            return None

        unique_ports = features.unique_destination_ports
        threshold = int(params["unique_ports"])
        if unique_ports < threshold:
            return None
        if features.connection_count < int(params["min_connections"]):
            return None

        syn_like = 0
        if features.connection_count:
            syn_like = int(features.connection_count * float(params.get("syn_ratio", 0.0)))
        score = self.scaled_score(unique_ports, threshold, int(params.get("score_ceiling", 80)) * 2)
        if syn_like and event.connection_state == ConnectionState.SYN_SENT.value:
            score = min(100.0, score + 5)

        destinations = max(features.unique_destination_ips, 1)
        confidence = min(0.95, 0.5 + 0.05 * (unique_ports / max(threshold, 1)))
        if destinations > int(params.get("unique_destinations", 1)):
            confidence = min(0.95, confidence + 0.05)

        return self.result(
            context,
            score=score,
            confidence=confidence,
            description=(
                f"Possible port scan from {features.source_ip}: "
                f"{unique_ports} unique destination ports touched in "
                f"{features.window_seconds}s across {destinations} host(s)"
            ),
            evidence={
                "source_ip": features.source_ip,
                "unique_destination_ports": unique_ports,
                "unique_destination_ips": destinations,
                "connections": features.connection_count,
                "window_seconds": features.window_seconds,
                "sample_destination_port": event.destination_port,
                "sample_destination_ip": event.destination_ip,
                "threshold": threshold,
            },
        )


class BruteForceRule(BaseRule):
    """Repeated authentication failures from one source."""

    rule_key = "BRUTE_FORCE"
    detection_type = "BRUTE_FORCE"
    default_severity_hint = SeverityLevel.HIGH.value
    default_params = {
        "failures": 5,
        "score_ceiling": 20,
        "count_from_database": True,
    }
    default_recommended_action = (
        "Check the targeted account for lockout, force a password reset, block the "
        "source address and review the authentication log around the window."
    )

    def evaluate(self, context: RuleContext) -> RuleResult | None:
        event, features = context.event, context.features
        params = self.params(context)
        if event.event_type != EventType.AUTH_FAILURE.value:
            return None

        threshold = int(params["failures"])
        observed = features.auth_failures
        if params.get("count_from_database") and context.repository is not None and features.source_ip:
            observed = max(
                observed,
                context.repository.count_events(
                    source_ip=features.source_ip,
                    event_type=EventType.AUTH_FAILURE.value,
                    start=event.timestamp.replace(microsecond=0)
                    - timedelta(seconds=context.window_seconds),
                ),
            )
        if observed < threshold:
            return None

        score = self.scaled_score(observed, threshold, int(params.get("score_ceiling", 20)))
        confidence = min(0.95, 0.55 + 0.04 * (observed - threshold + 1))
        return self.result(
            context,
            score=score,
            confidence=confidence,
            description=(
                f"Brute force suspected against {event.destination_ip or 'authentication service'}: "
                f"{observed} failed authentications from {features.source_ip} in {context.window_seconds}s"
            ),
            evidence={
                "source_ip": features.source_ip,
                "destination_ip": event.destination_ip,
                "failed_authentications": observed,
                "window_seconds": context.window_seconds,
                "username": (event.metadata or {}).get("username"),
                "threshold": threshold,
                "message": (event.metadata or {}).get("message"),
            },
        )


class FailedConnectionsRule(BaseRule):
    """Repeated connection failures - typical of scanning or a broken service."""

    rule_key = "FAILED_CONNECTIONS"
    detection_type = "REPEATED_FAILED_CONNECTIONS"
    default_severity_hint = SeverityLevel.MEDIUM.value
    default_params = {"failures": 10, "min_failure_ratio": 0.5, "score_ceiling": 40}
    default_recommended_action = (
        "Confirm whether the destination service is reachable, then check the source "
        "host for malware or misconfiguration."
    )

    def evaluate(self, context: RuleContext) -> RuleResult | None:
        features = context.features
        params = self.params(context)
        if features.failed_connections < int(params["failures"]):
            return None
        ratio = features.failed_connections / max(features.connection_count, 1)
        if ratio < float(params.get("min_failure_ratio", 0.0)):
            return None
        score = self.scaled_score(
            features.failed_connections, int(params["failures"]), int(params.get("score_ceiling", 40))
        )
        return self.result(
            context,
            score=score,
            confidence=min(0.9, 0.5 + ratio / 2),
            description=(
                f"{features.failed_connections} failed connections from {features.source_ip} "
                f"({ratio:.0%} of its traffic) in {features.window_seconds}s"
            ),
            evidence={
                "source_ip": features.source_ip,
                "failed_connections": features.failed_connections,
                "total_connections": features.connection_count,
                "failure_ratio": round(ratio, 3),
                "window_seconds": features.window_seconds,
            },
        )


class ConnectionFloodRule(BaseRule):
    """Unusually high connection rate from a single source."""

    rule_key = "CONNECTION_FLOOD"
    detection_type = "CONNECTION_FLOOD"
    default_severity_hint = SeverityLevel.HIGH.value
    default_params = {"connections": 60, "events_per_minute": 120, "score_ceiling": 300}
    default_recommended_action = (
        "Rate-limit or block the source, and check the destination service for "
        "resource exhaustion."
    )

    def evaluate(self, context: RuleContext) -> RuleResult | None:
        features = context.features
        params = self.params(context)
        threshold = int(params["connections"])
        per_minute = float(params.get("events_per_minute", 0) or 0)
        if features.connection_count < threshold and features.events_per_minute < per_minute:
            return None
        score = self.scaled_score(
            max(features.connection_count, features.events_per_minute),
            max(threshold, per_minute),
            int(params.get("score_ceiling", 300)),
        )
        return self.result(
            context,
            score=score,
            confidence=0.65,
            description=(
                f"Connection flood from {features.source_ip}: {features.connection_count} connections "
                f"({features.events_per_minute:.1f}/min) in {features.window_seconds}s"
            ),
            evidence={
                "source_ip": features.source_ip,
                "connections": features.connection_count,
                "events_per_minute": features.events_per_minute,
                "unique_destination_ips": features.unique_destination_ips,
                "window_seconds": features.window_seconds,
                "threshold": threshold,
            },
        )


class SuspiciousProtocolRule(BaseRule):
    """Protocol/port combinations that should not normally appear."""

    rule_key = "SUSPICIOUS_PROTOCOL"
    detection_type = "SUSPICIOUS_PROTOCOL"
    default_severity_hint = SeverityLevel.MEDIUM.value
    default_params = {
        "suspicious_ports": [23, 135, 139, 445, 1433, 3389, 5900, 6667, 31337],
        "dns_ports": [53],
        "large_icmp_bytes": 4096,
        "external_only": True,
    }
    default_recommended_action = (
        "Validate the business need for this protocol/port combination and block it at "
        "the perimeter if it is not required."
    )

    def evaluate(self, context: RuleContext) -> RuleResult | None:
        event = context.event
        params = self.params(context)
        destination_port = event.destination_port
        reasons: list[str] = []

        watching_external = event.direction in {"outbound", "external"}
        if destination_port and destination_port in set(params.get("suspicious_ports", [])):
            if not params.get("external_only", True) or watching_external:
                reasons.append(f"destination port {destination_port} is a known risky service")
        if (
            event.protocol == Protocol.ICMP.value
            and int(event.bytes or 0) >= int(params.get("large_icmp_bytes", 4096))
        ):
            reasons.append("large ICMP payload - possible tunnelling")
        if (
            event.protocol == Protocol.UDP.value
            and destination_port in set(params.get("dns_ports", []))
            and not is_private(event.destination_ip)
            and not (event.network or {}).get("dns_query")
        ):
            reasons.append("DNS port used without a DNS question - possible tunnel")

        if not reasons:
            return None
        return self.result(
            context,
            score=55.0 if len(reasons) == 1 else 75.0,
            confidence=0.6 if len(reasons) == 1 else 0.75,
            description=(
                f"Suspicious protocol activity from {event.source_ip} to "
                f"{event.destination_ip}: " + "; ".join(reasons)
            ),
            evidence={
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "destination_port": destination_port,
                "protocol": event.protocol,
                "direction": event.direction,
                "reasons": reasons,
                "bytes": event.bytes,
            },
        )


class DnsAnomalyRule(BaseRule):
    """Abnormal DNS behaviour: extreme rate, or long/label-heavy query names."""

    rule_key = "DNS_ANOMALY"
    detection_type = "DNS_ANOMALY"
    default_severity_hint = SeverityLevel.MEDIUM.value
    default_params = {
        "queries": 100,
        "unique_query_ratio": 0.8,
        "max_query_length": 60,
        "score_ceiling": 400,
    }
    default_recommended_action = (
        "Inspect the queried domains for data exfiltration or DNS tunnelling and block "
        "the domain family at the resolver."
    )

    def evaluate(self, context: RuleContext) -> RuleResult | None:
        event, features = context.event, context.features
        params = self.params(context)
        if event.event_type != EventType.DNS_QUERY.value:
            return None

        query = str((event.network or {}).get("dns_query") or "")
        long_query = len(query) >= int(params.get("max_query_length", 60))
        high_rate = features.dns_requests >= int(params["queries"])
        mostly_unique = (
            features.dns_requests > 0
            and (features.unique_dns_queries / max(features.dns_requests, 1))
            >= float(params.get("unique_query_ratio", 0.8))
            and features.dns_requests >= max(int(params["queries"]) // 4, 5)
        )
        if not (long_query or high_rate or mostly_unique):
            return None

        reasons = []
        if long_query:
            reasons.append(f"query name length {len(query)}")
        if high_rate:
            reasons.append(f"{features.dns_requests} queries in window")
        if mostly_unique:
            reasons.append("almost all queries are unique")

        score = self.scaled_score(
            features.dns_requests if high_rate else len(query),
            int(params["queries"]) if high_rate else int(params.get("max_query_length", 60)),
            int(params.get("score_ceiling", 400)),
        )
        return self.result(
            context,
            score=score,
            confidence=0.6 if len(reasons) == 1 else 0.8,
            description=(
                f"Abnormal DNS activity from {features.source_ip}: " + "; ".join(reasons)
            ),
            evidence={
                "source_ip": features.source_ip,
                "query": query,
                "dns_requests": features.dns_requests,
                "unique_queries": features.unique_dns_queries,
                "window_seconds": features.window_seconds,
                "reasons": reasons,
            },
        )


class VolumeAnomalyRule(BaseRule):
    """Abnormally high transfer volume from one host."""

    rule_key = "VOLUME_ANOMALY"
    detection_type = "VOLUME_ANOMALY"
    default_severity_hint = SeverityLevel.MEDIUM.value
    default_params = {
        "bytes_total": 50_000_000,
        "bytes_per_second": 500_000,
        "score_ceiling": 500_000_000,
    }
    default_recommended_action = (
        "Confirm the transfer is expected (backup, update, streaming). If not, treat as "
        "possible exfiltration and preserve the flow records."
    )

    def evaluate(self, context: RuleContext) -> RuleResult | None:
        features = context.features
        params = self.params(context)
        total = features.bytes_total
        per_second = features.bytes_per_second
        if total < int(params["bytes_total"]) and per_second < float(params["bytes_per_second"]):
            return None
        score = self.scaled_score(
            max(total, per_second),
            max(float(params["bytes_total"]), float(params["bytes_per_second"])),
            float(params.get("score_ceiling", 500_000_000)),
        )
        return self.result(
            context,
            score=score,
            confidence=0.55,
            description=(
                f"Unusual traffic volume from {features.source_ip}: "
                f"{total / 1_000_000:.1f} MB in {features.window_seconds}s "
                f"({per_second / 1000:.1f} KB/s)"
            ),
            evidence={
                "source_ip": features.source_ip,
                "bytes_total": total,
                "bytes_per_second": per_second,
                "packets_total": features.packets_total,
                "window_seconds": features.window_seconds,
            },
        )


__all__ = [
    "BruteForceRule",
    "ConnectionFloodRule",
    "DnsAnomalyRule",
    "FailedConnectionsRule",
    "PortScanRule",
    "SuspiciousProtocolRule",
    "VolumeAnomalyRule",
]
