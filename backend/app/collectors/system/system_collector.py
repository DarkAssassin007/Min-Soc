"""Host-level collector: local connection table, optional log tail.

Two independent sources, both useful for a single-machine SOC deployment:

* **Connection snapshots** - ``psutil.net_connections`` is polled on an
  interval and only *new* connections are emitted, together with the owning
  process. This gives the platform visibility into what the monitored host
  itself is doing (the classic "was this box compromised" question).
* **Log tail** - optionally tails a text log (firewall/router/host security
  log written to disk) and emits each new line as a syslog-style event, which
  reuses the same classification rules as the UDP collector.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...config.logging_config import get_logger
from ...database.enums import ConnectionState, EventType
from ..base import Collector

logger = get_logger(__name__)

_STATUS_MAP = {
    "ESTABLISHED": ConnectionState.ESTABLISHED.value,
    "SYN_SENT": ConnectionState.SYN_SENT.value,
    "SYN_RECV": ConnectionState.SYN_SENT.value,
    "CLOSE_WAIT": ConnectionState.CLOSED.value,
    "TIME_WAIT": ConnectionState.CLOSED.value,
    "CLOSED": ConnectionState.CLOSED.value,
    "LISTEN": ConnectionState.UNKNOWN.value,
    "NONE": ConnectionState.UNKNOWN.value,
    "DELETE_TCB": ConnectionState.CLOSED.value,
}


def _is_loopback(address: str | None) -> bool:
    return bool(address) and (address.startswith("127.") or address in {"::1", "0.0.0.0", "::"})


class SystemCollector(Collector):
    """Poll the local connection table and optionally tail a log file."""

    name = "system"

    def source_label(self) -> str | None:
        """Host telemetry is always local to the sensor."""
        return "local host"

    def __init__(self, sink, **options: Any) -> None:
        super().__init__(sink, **options)
        self.interval: float = float(options.get("interval_seconds") or 15)
        self.log_path: str | None = options.get("log_path") or None
        self.include_listen: bool = bool(options.get("include_listen", False))
        self.local_address: str | None = options.get("local_address") or None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._seen: set[tuple] = set()
        self._seen_limit = 20000
        self._log_position = 0
        self._connections_emitted = 0
        self._log_lines = 0

    # ---------------------------------------------------------- lifecycle
    def _start(self) -> bool:
        try:
            import psutil  # noqa: F401  (import check only)
        except Exception as exc:  # pragma: no cover - psutil is a hard dependency
            self._last_error = f"psutil unavailable: {exc}"
            return False
        if not self.local_address:
            self.local_address = self._detect_primary_address()
        if self.log_path and not Path(self.log_path).exists():
            logger.warning(
                "log tail requested but file is missing",
                extra={"collector": self.name, "path": self.log_path},
            )
            self.log_path = None
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="system-collector", daemon=True)
        self._thread.start()
        self.set_detail(interval_seconds=self.interval, log_path=self.log_path or "")
        return True

    def _stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    @staticmethod
    def _detect_primary_address() -> str | None:
        try:
            import psutil

            stats = psutil.net_if_addrs()
            preferred = [name for name in stats if not name.lower().startswith(("lo", "loopback"))]
            for name in preferred:
                for address in stats[name]:
                    if getattr(address, "family", None) == 2 and not address.address.startswith("127."):
                        return address.address
        except Exception:  # pragma: no cover - best effort
            return None
        return None

    # ------------------------------------------------------------ polling
    def _run(self) -> None:  # pragma: no cover - timed loop
        while not self._stop_event.is_set():
            try:
                self._poll_connections()
                self._tail_log()
            except Exception as exc:
                self.record_error(exc)
            self._stop_event.wait(self.interval)

    def _poll_connections(self) -> None:
        import psutil

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as exc:
            self.record_error(exc)
            return

        current: set[tuple] = set()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for conn in connections:
            local_ip = getattr(conn.laddr, "ip", None) if conn.laddr else None
            local_port = getattr(conn.laddr, "port", None) if conn.laddr else None
            remote_ip = getattr(conn.raddr, "ip", None) if conn.raddr else None
            remote_port = getattr(conn.raddr, "port", None) if conn.raddr else None
            if not remote_ip and not self.include_listen:
                continue
            if _is_loopback(remote_ip) and _is_loopback(local_ip):
                continue
            key = (local_ip, local_port, remote_ip, remote_port, conn.status, conn.pid)
            current.add(key)
            if key in self._seen:
                continue
            self._seen.add(key)
            process_name = None
            try:
                if conn.pid:
                    process_name = psutil.Process(conn.pid).name()
            except Exception:
                process_name = None
            self._connections_emitted += 1
            self.emit(
                {
                    "timestamp": now,
                    "source_ip": local_ip if remote_ip else None,
                    "destination_ip": remote_ip,
                    "source_port": local_port,
                    "destination_port": remote_port,
                    "protocol": "TCP" if conn.type == 1 else "UDP",
                    "connection_state": _STATUS_MAP.get(str(conn.status).upper(), ConnectionState.UNKNOWN.value),
                    "packet_count": 1,
                    "bytes": 0,
                    "pid": conn.pid,
                    "process": process_name,
                    "message": f"local connection {local_ip}:{local_port} -> {remote_ip}:{remote_port} ({conn.status})",
                },
                event_type=EventType.NETWORK_CONNECTION.value,
                timestamp=now,
            )
        # keep the dedupe set bounded
        if len(self._seen) > self._seen_limit:
            self._seen = set(list(self._seen)[-self._seen_limit // 2 :])
        self._seen &= current | self._seen

    def _tail_log(self) -> None:
        if not self.log_path:
            return
        path = Path(self.log_path)
        try:
            size = path.stat().st_size
            if size < self._log_position:  # rotated
                self._log_position = 0
            if size == self._log_position:
                return
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                handle.seek(self._log_position)
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    self._log_lines += 1
                    self.emit(
                        {"message": line[:4000], "host": "local-file", "raw": line[:4000]},
                        event_type=EventType.SYSLOG_EVENT.value,
                    )
                self._log_position = handle.tell()
        except OSError as exc:
            self.record_error(exc)

    def status(self) -> dict:
        status = super().status()
        status["detail"].update(
            {
                "interval_seconds": self.interval,
                "connections_emitted": self._connections_emitted,
                "log_path": self.log_path or "",
                "log_lines": self._log_lines,
                "local_address": self.local_address,
                "pid": os.getpid(),
            }
        )
        return status


__all__ = ["SystemCollector"]
