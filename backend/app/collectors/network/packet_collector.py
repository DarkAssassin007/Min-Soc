"""Live packet collector (metadata only).

Design rules:

* **Metadata only.** Payload bytes are never stored, never logged and never
  forwarded. The only payload-derived fields kept are protocol headers that are
  inherently visible on the wire (TCP flags, DNS question, TLS SNI, HTTP
  method/Host) because they are what detection needs. Bodies and credentials
  are discarded inside the capture callback.
* **Fail soft.** Missing Npcap/libpcap, missing privileges or an unknown
  interface never crash the platform; the collector reports ``unavailable`` and
  the synthetic/system/syslog sources keep the pipeline fed.
* **Bounded.** Byte/volume counters are metadata extracted from headers only.
"""

from __future__ import annotations

import threading
from typing import Any

from ...config.logging_config import get_logger
from ...database.enums import EventType
from ..base import Collector

logger = get_logger(__name__)

#: Payload prefixes that identify plaintext HTTP requests (metadata extraction).
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def is_pcap_available() -> tuple[bool, str | None]:
    """Check whether live capture is possible on this host."""
    try:
        from scapy.all import conf  # type: ignore
    except Exception as exc:  # pragma: no cover - scapy always installed
        return False, f"scapy unavailable: {exc}"
    try:
        iface = conf.iface
        if iface is None:
            return False, "no capture interface detected"
    except Exception as exc:
        return False, f"capture interface error: {exc}"
    return True, None


def default_capture_interface() -> str | None:
    """Pick a sensible interface when none is configured.

    scapy's default is whatever Windows lists first, which on a laptop is often
    a disconnected Wi-Fi or a virtual adapter — capture then runs but sees no
    traffic. Prefer the first *up* interface that owns a routable IPv4 address;
    return ``None`` so the caller can fall back to scapy's own default.
    """
    try:
        import socket

        import psutil  # type: ignore

        stats = psutil.net_if_stats()
        for name, addresses in psutil.net_if_addrs().items():
            status = stats.get(name)
            if status is not None and not status.isup:
                continue
            for address in addresses:
                if address.family != socket.AF_INET:
                    continue
                ip = address.address or ""
                if ip.startswith(("127.", "169.254.")) or ip == "0.0.0.0":
                    continue
                if "loopback" in name.lower():
                    continue
                return name
    except Exception:  # pragma: no cover - defensive, fall back to scapy
        return None
    return None


def extract_http_metadata(payload: bytes) -> dict[str, Any]:
    """Extract only the request method and Host header from an HTTP payload."""
    result: dict[str, Any] = {}
    if not payload:
        return result
    if not payload.startswith(_HTTP_METHODS):
        return result
    try:
        head, _, _body = payload.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        if not lines:
            return result
        method = lines[0].split(b" ", 1)[0].decode("ascii", "ignore").upper()
        result["http_method"] = method
        for line in lines[1:20]:
            if line.lower().startswith(b"host:"):
                result["http_host"] = line.split(b":", 1)[1].strip().decode("ascii", "ignore")[:255]
                break
    except Exception:  # pragma: no cover - defensive, never fail a capture
        return result
    return result


def extract_tls_sni(payload: bytes) -> str | None:
    """Best-effort TLS ClientHello SNI extraction (returns None on anything odd)."""
    try:
        if len(payload) < 45 or payload[0] != 0x16:  # handshake record
            return None
        if payload[5] != 0x01:  # ClientHello
            return None
        index = 43  # record(5) + handshake header(4) + version(2) + random(32)
        if index >= len(payload):
            return None
        session_len = payload[index]
        index += 1 + session_len
        if index + 2 > len(payload):
            return None
        cipher_len = int.from_bytes(payload[index : index + 2], "big")
        index += 2 + cipher_len
        if index + 1 > len(payload):
            return None
        compression_len = payload[index]
        index += 1 + compression_len
        if index + 2 > len(payload):
            return None
        extensions_len = int.from_bytes(payload[index : index + 2], "big")
        index += 2
        end = min(index + extensions_len, len(payload))
        while index + 4 <= end:
            ext_type = int.from_bytes(payload[index : index + 2], "big")
            ext_len = int.from_bytes(payload[index + 2 : index + 4], "big")
            index += 4
            if ext_type == 0x00:  # server_name
                body = payload[index : index + ext_len]
                if len(body) >= 5 and body[0] == 0x00:
                    name_len = int.from_bytes(body[3:5], "big")
                    return body[5 : 5 + name_len].decode("ascii", "ignore")[:255] or None
            index += ext_len
        return None
    except Exception:
        return None


class PacketCollector(Collector):
    """Capture IP/TCP/UDP/ICMP/ARP metadata from a live interface."""

    name = "packet"

    def __init__(self, sink, **options: Any) -> None:
        super().__init__(sink, **options)
        self.bpf_filter: str = options.get("bpf_filter") or "ip or arp"
        self.snaplen: int = int(options.get("snaplen") or 128)
        self.interface: str | None = options.get("interface") or None
        self.promiscuous: bool = bool(options.get("promiscuous", False))
        self._sniffer = None
        self._thread: threading.Thread | None = None
        self._bytes = 0
        self._packets = 0
        self._active_interface: str | None = None

    # ---------------------------------------------------------- lifecycle
    def source_label(self) -> str | None:
        """The NIC capture is really running on, not the configured value."""
        return self._active_interface or super().source_label()

    def _start(self) -> bool:
        available, reason = is_pcap_available()
        if not available:
            self._last_error = reason
            return False
        from scapy.all import AsyncSniffer, conf  # type: ignore

        interface = self.interface or default_capture_interface() or getattr(conf, "iface", None)
        self._active_interface = str(interface) if interface else None
        self.set_detail(
            interface=str(interface),
            interface_source="configured" if self.interface else "auto",
            bpf=self.bpf_filter,
            snaplen=self.snaplen,
        )
        try:
            self._sniffer = AsyncSniffer(
                iface=interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
                promisc=self.promiscuous,
            )
            self._sniffer.start()
            return True
        except Exception as exc:
            self._last_error = f"capture start failed: {exc}"
            self._sniffer = None
            return False

    def _stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:  # pragma: no cover - shutdown race
                pass
            self._sniffer = None

    # ------------------------------------------------------------- capture
    def _handle_packet(self, packet) -> None:  # pragma: no cover - needs a live interface
        try:
            metadata = self._extract(packet)
        except Exception as exc:
            self.record_error(exc)
            return
        if metadata:
            self._bytes += int(metadata.get("bytes") or 0)
            self._packets += 1
            self.emit(metadata, event_type=self._event_type_for(metadata))

    def _extract(self, packet) -> dict[str, Any] | None:
        from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
        from scapy.layers.inet6 import IPv6  # type: ignore
        from scapy.layers.l2 import ARP  # type: ignore

        payload_bytes = bytes(packet.payload) if packet.haslayer(TCP) else b""

        if packet.haslayer(ARP):
            arp = packet[ARP]
            return {
                "source_ip": arp.psrc,
                "destination_ip": arp.pdst,
                "protocol": "ARP",
                "bytes": len(bytes(packet)),
                "packet_count": 1,
                "arp_op": "REQUEST" if int(arp.op) == 1 else "REPLY",
                "timestamp": float(getattr(packet, "time", 0)) or None,
            }

        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return None

        base = packet[IP] if packet.haslayer(IP) else packet[IPv6]
        metadata: dict[str, Any] = {
            "source_ip": base.src,
            "destination_ip": base.dst,
            "bytes": len(bytes(packet)),
            "packet_count": 1,
            "timestamp": float(getattr(packet, "time", 0)) or None,
        }

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            metadata.update(
                {
                    "protocol": "TCP",
                    "source_port": int(tcp.sport),
                    "destination_port": int(tcp.dport),
                    "tcp_flags": str(tcp.flags),
                }
            )
            if int(tcp.dport) == 53 or int(tcp.sport) == 53:
                metadata.update(self._dns_metadata(packet))
            else:
                metadata.update(extract_http_metadata(payload_bytes[:1024]))
                if not metadata.get("http_method"):
                    sni = extract_tls_sni(payload_bytes[:1024])
                    if sni:
                        metadata["tls_sni"] = sni
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            metadata.update(
                {
                    "protocol": "UDP",
                    "source_port": int(udp.sport),
                    "destination_port": int(udp.dport),
                }
            )
            if int(udp.dport) == 53 or int(udp.sport) == 53:
                metadata.update(self._dns_metadata(packet))
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            metadata.update({"protocol": "ICMP", "icmp_type": str(icmp.type)})
        else:
            metadata["protocol"] = "OTHER"

        return metadata

    @staticmethod
    def _dns_metadata(packet) -> dict[str, Any]:
        try:
            from scapy.layers.dns import DNS  # type: ignore

            if not packet.haslayer(DNS):
                return {}
            dns = packet[DNS]
            question = None
            if dns.qd is not None and getattr(dns, "qdcount", 0):
                raw = dns.qd.qname
                question = (
                    raw.decode("utf-8", "ignore").rstrip(".")
                    if isinstance(raw, (bytes, bytearray))
                    else str(raw).rstrip(".")
                )
            qtype = None
            if dns.qd is not None:
                qtype = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR"}.get(
                    int(getattr(dns.qd, "qtype", 0) or 0), str(getattr(dns.qd, "qtype", "") or "")
                )
            return {
                "dns_query": (question or "")[:255] or None,
                "dns_qtype": qtype or None,
                "dns_rcode": "NOERROR" if int(getattr(dns, "rcode", 0) or 0) == 0 else str(dns.rcode),
            }
        except Exception:  # pragma: no cover - malformed DNS must never break capture
            return {}

    @staticmethod
    def _event_type_for(metadata: dict[str, Any]) -> str:
        if metadata.get("dns_query"):
            return EventType.DNS_QUERY.value
        protocol = str(metadata.get("protocol") or "").upper()
        if protocol == "ARP":
            return EventType.ARP_ACTIVITY.value
        if protocol in {"ICMP", "ICMPV6"}:
            return EventType.ICMP_ACTIVITY.value
        return EventType.NETWORK_CONNECTION.value

    # ------------------------------------------------------------ status
    def status(self) -> dict:
        status = super().status()
        status["detail"].update(
            {
                "interface": self._active_interface or self.options.get("interface") or "auto",
                "bpf": self.bpf_filter,
                "packets": self._packets,
                "captured_bytes": self._bytes,
            }
        )
        return status


__all__ = ["PacketCollector", "extract_http_metadata", "extract_tls_sni", "is_pcap_available"]
