"""Syslog / firewall-log collector.

Accepts three flavours of datagram on one UDP socket:

1. **JSON** - anything starting with ``{``: field names are used as-is, which is
   how a modern firewall or a Linux host running ``rsyslog`` with a JSON
   template will send events.
2. **RFC5424** - ``<PRI>1 2026-08-18T22:30:12Z host app procid msgid - msg``.
3. **RFC3164** - ``<PRI>Aug 18 22:30:12 host app[pid]: msg``.

Authentication failures, firewall denies and other security relevant messages
are classified later by the parser, so the collector only has to be a faithful
transport. Messages are truncated before storage; no message content is ever
executed or interpreted beyond pattern matching.
"""

from __future__ import annotations

import json
import re
import socket
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from ...config.logging_config import get_logger
from ...database.enums import EventType
from ..base import Collector

logger = get_logger(__name__)

_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")
_RFC5424_RE = re.compile(
    r"^(?P<version>\d)\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?P<structured>-|\[[^\]]*\])\s?(?P<message>.*)$",
    re.DOTALL,
)
_RFC3164_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<app>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$",
    re.DOTALL,
)
_IP_RE = re.compile(r"(?:from|src[= ]|source[= ])\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)

_FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    9: "cron", 10: "authpriv", 16: "local0", 17: "local1", 18: "local2",
    19: "local3", 20: "local4", 21: "local5", 22: "local6", 23: "local7",
}
_SEVERITY_NAMES = {0: "emergency", 1: "alert", 2: "critical", 3: "error", 4: "warning",
                   5: "notice", 6: "info", 7: "debug"}


def parse_priority(priority: int | None) -> tuple[str | None, str | None]:
    if priority is None:
        return None, None
    facility = priority // 8
    severity = priority % 8
    return _FACILITY_NAMES.get(facility, str(facility)), _SEVERITY_NAMES.get(severity, str(severity))


def parse_syslog_line(line: str, *, host: str | None = None) -> dict[str, Any]:
    """Parse a syslog line into a payload dict (never raises)."""
    payload: dict[str, Any] = {"raw": line, "message": line, "host": host}
    text = line.strip()
    if not text:
        return payload

    if text.startswith("{"):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                payload.update({k: v for k, v in data.items() if not k.startswith("_")})
                payload.setdefault("message", str(data.get("message") or text))
                return payload
        except json.JSONDecodeError:
            payload["parse_error"] = "invalid json"

    match = _PRI_RE.match(text)
    if match:
        payload["priority"] = int(match.group("pri"))
        payload["facility"], payload["severity"] = parse_priority(payload["priority"])
        text = text[match.end():]

    match = _RFC5424_RE.match(text)
    if match:
        payload["version"] = int(match.group("version"))
        payload["timestamp"] = match.group("timestamp")
        payload["host"] = payload.get("host") or match.group("host")
        payload["app"] = match.group("app")
        payload["process_id"] = match.group("procid")
        payload["message_id"] = match.group("msgid")
        payload["message"] = match.group("message")[:4000]
        payload["structured_data"] = match.group("structured")
    else:
        match = _RFC3164_RE.match(text)
        if match:
            payload["timestamp"] = match.group("timestamp")
            payload["host"] = payload.get("host") or match.group("host")
            payload["app"] = match.group("app")
            payload["process_id"] = match.group("pid")
            payload["message"] = match.group("message")[:4000]
        else:
            payload["message"] = text[:4000]

    ip_match = _IP_RE.search(str(payload.get("message") or ""))
    if ip_match:
        payload.setdefault("source_ip", ip_match.group("ip"))
    return payload


def parse_timestamp(value: Any, *, now: datetime | None = None) -> datetime | None:
    """Parse RFC5424 / RFC3164 timestamps; RFC3164 has no year so assume the current one."""
    if not value or not isinstance(value, str):
        return None
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed
    except ValueError:
        pass
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
        try:
            # The year must be explicit: parsing a day-of-month without one is
            # ambiguous and deprecated (removed in Python 3.15).
            parsed = datetime.strptime(f"{now.year} {text}", f"%Y {fmt}")
            if parsed > now + timedelta(days=2):  # New Year boundary
                try:
                    parsed = parsed.replace(year=now.year - 1)
                except ValueError:  # 29 Feb does not exist in the previous year
                    parsed = parsed.replace(year=now.year - 1, day=28)
            return parsed
        except ValueError:
            continue
    return None


class SyslogCollector(Collector):
    """Listen for syslog/firewall datagrams on a UDP port."""

    name = "syslog"

    def source_label(self) -> str | None:
        """Provenance for received datagrams: the bound UDP endpoint."""
        return f"udp:{self.host}:{self.port}"

    def __init__(self, sink, **options: Any) -> None:
        super().__init__(sink, **options)
        self.host: str = str(options.get("host") or "0.0.0.0")
        self.port: int = int(options.get("port") or 5514)
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_datagram: datetime | None = None

    def _start(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.settimeout(1.0)
        except OSError as exc:
            self._last_error = f"bind failed on {self.host}:{self.port}: {exc}"
            return False
        self._socket = sock
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="syslog-collector", daemon=True)
        self._thread.start()
        self.set_detail(listen=f"{self.host}:{self.port}")
        return True

    def _stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:  # pragma: no cover
                pass
            self._socket = None

    def _run(self) -> None:  # pragma: no cover - socket loop
        assert self._socket is not None
        while not self._stop_event.is_set():
            try:
                data, address = self._socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                line = data.decode("utf-8", "ignore")
                payload = parse_syslog_line(line, host=address[0])
                payload.setdefault("source_ip", address[0])
                timestamp = parse_timestamp(payload.get("timestamp")) or datetime.now(
                    timezone.utc
                ).replace(tzinfo=None)
                self._last_datagram = timestamp
                self.emit(payload, event_type=EventType.SYSLOG_EVENT.value, timestamp=timestamp)
            except Exception as exc:  # pragma: no cover - defensive
                self.record_error(exc)

    def status(self) -> dict:
        status = super().status()
        status["detail"].update(
            {
                "listen": f"{self.host}:{self.port}",
                "last_datagram_at": self._last_datagram.isoformat() if self._last_datagram else None,
            }
        )
        return status


__all__ = ["SyslogCollector", "parse_priority", "parse_syslog_line", "parse_timestamp"]
