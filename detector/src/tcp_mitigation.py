import logging
from datetime import datetime, timedelta
from types import SimpleNamespace

from models import DNSEvent

try:
    from scapy.all import DNS, DNSQR, IP, UDP, send

    SCAPY_AVAILABLE = True
except ModuleNotFoundError:
    DNS = DNSQR = IP = UDP = None
    send = None
    SCAPY_AVAILABLE = False


logger = logging.getLogger(__name__)

Alert = dict[str, object]


class _SimplePacket:
    def __init__(
        self,
        *,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        dns,
    ) -> None:
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self._dns = dns

    def __getitem__(self, key: str):
        if key != "DNS":
            raise KeyError(key)
        return self._dns

    def copy(self):
        dns_copy = SimpleNamespace(
            id=self._dns.id,
            qr=self._dns.qr,
            tc=self._dns.tc,
            qdcount=self._dns.qdcount,
            ancount=self._dns.ancount,
            nscount=self._dns.nscount,
            arcount=self._dns.arcount,
            qd=SimpleNamespace(
                qname=self._dns.qd.qname,
                qtype=self._dns.qd.qtype,
            ),
        )
        return _SimplePacket(
            src=self.src,
            dst=self.dst,
            sport=self.sport,
            dport=self.dport,
            dns=dns_copy,
        )


def _default_sender(packet) -> None:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for live TCP mitigation packet injection")
    send(packet, verbose=False)


def _normalize_name(name: str) -> str:
    return name.rstrip(".").lower().strip()


def _fqdn(name: str) -> str:
    normalized = _normalize_name(name)
    return f"{normalized}." if normalized else ""


def _is_subdomain(name: str, zone: str) -> bool:
    normalized_name = _normalize_name(name)
    normalized_zone = _normalize_name(zone)
    if not normalized_name or not normalized_zone:
        return False
    return normalized_name == normalized_zone or normalized_name.endswith(
        f".{normalized_zone}"
    )


def build_truncated_response(event: DNSEvent):
    if not SCAPY_AVAILABLE:
        dns = SimpleNamespace(
            id=event.transaction_id,
            qr=1,
            tc=1,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
            qd=SimpleNamespace(
                qname=_fqdn(event.query_name).encode(),
                qtype=event.query_type,
            ),
        )
        return _SimplePacket(
            src=event.source_ip,
            dst=event.dest_ip,
            sport=event.source_port,
            dport=event.dest_port,
            dns=dns,
        )

    dns = DNS(
        id=event.transaction_id,
        qr=1,
        tc=1,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
        qd=DNSQR(qname=_fqdn(event.query_name), qtype=event.query_type),
    )
    return IP(src=event.source_ip, dst=event.dest_ip) / UDP(
        sport=event.source_port,
        dport=event.dest_port,
    ) / dns


class TCPMitigator:
    def __init__(
        self,
        *,
        armed_domain_seconds: int = 30,
        repeat_count: int = 3,
        transaction_cooldown_seconds: int = 2,
        sender=_default_sender,
    ) -> None:
        self.armed_domain_ttl = timedelta(seconds=armed_domain_seconds)
        self.repeat_count = max(repeat_count, 1)
        self.transaction_cooldown = timedelta(seconds=transaction_cooldown_seconds)
        self.sender = sender
        self.armed_domains: dict[str, datetime] = {}
        self.recent_transactions: dict[tuple[str, str, int, str, int], datetime] = {}

    def process_event(self, event: DNSEvent, alerts: list[Alert]) -> None:
        self._expire_state(event.timestamp)
        self._arm_precursor_domains(event, alerts)

        matching_domain = self._matching_armed_domain(event)
        direct_trigger = bool(alerts) and self._is_resolver_response(event)
        if not direct_trigger and matching_domain is None:
            return

        result = self._force_tcp(
            event,
            reason="direct_alert" if direct_trigger else "armed_domain",
            matched_domain=matching_domain,
        )
        if result is None:
            return

        for alert in alerts:
            alert["tcp_mitigation"] = result

    def _arm_precursor_domains(self, event: DNSEvent, alerts: list[Alert]) -> None:
        for alert in alerts:
            if alert.get("alert_type") != "kaminsky_precursor":
                continue
            target_domain = alert.get("target_domain")
            if not isinstance(target_domain, str):
                continue
            normalized = _normalize_name(target_domain)
            if not normalized:
                continue

            expires_at = event.timestamp + self.armed_domain_ttl
            self.armed_domains[normalized] = expires_at
            alert["tcp_mitigation"] = {
                "action": "armed_domain",
                "domain": normalized,
                "expires_at": expires_at.isoformat(),
            }

    def _matching_armed_domain(self, event: DNSEvent) -> str | None:
        if not self._is_resolver_response(event):
            return None

        matches = [
            domain
            for domain, expires_at in self.armed_domains.items()
            if expires_at >= event.timestamp and _is_subdomain(event.query_name, domain)
        ]
        if not matches:
            return None
        return max(matches, key=len)

    def _force_tcp(
        self,
        event: DNSEvent,
        *,
        reason: str,
        matched_domain: str | None,
    ) -> dict[str, object] | None:
        if not self._is_resolver_response(event):
            return None
        if not event.query_name or not event.query_type:
            return None

        key = self._transaction_key(event)
        last_sent = self.recent_transactions.get(key)
        if last_sent is not None and event.timestamp - last_sent < self.transaction_cooldown:
            return {
                "action": "force_tcp",
                "status": "skipped_recent_duplicate",
                "reason": reason,
                "matched_domain": matched_domain,
                "query_name": _normalize_name(event.query_name),
                "txid": event.transaction_id,
                "packets_sent": 0,
            }

        packet = build_truncated_response(event)
        packets_sent = 0
        try:
            for _ in range(self.repeat_count):
                self.sender(packet.copy())
                packets_sent += 1
        except Exception as exc:
            logger.exception("tcp mitigation send failed for %s", event.query_name)
            return {
                "action": "force_tcp",
                "status": "send_failed",
                "reason": reason,
                "matched_domain": matched_domain,
                "query_name": _normalize_name(event.query_name),
                "txid": event.transaction_id,
                "packets_sent": packets_sent,
                "error": str(exc),
            }

        self.recent_transactions[key] = event.timestamp
        logger.info(
            "tcp mitigation injected truncated response qname=%s txid=%s reason=%s packets=%s",
            event.query_name,
            event.transaction_id,
            reason,
            packets_sent,
        )
        return {
            "action": "force_tcp",
            "status": "sent",
            "reason": reason,
            "matched_domain": matched_domain,
            "query_name": _normalize_name(event.query_name),
            "txid": event.transaction_id,
            "packets_sent": packets_sent,
        }

    def _expire_state(self, now: datetime) -> None:
        expired_domains = [
            domain for domain, expires_at in self.armed_domains.items() if expires_at < now
        ]
        for domain in expired_domains:
            self.armed_domains.pop(domain, None)

        expired_transactions = [
            key
            for key, sent_at in self.recent_transactions.items()
            if now - sent_at > self.transaction_cooldown
        ]
        for key in expired_transactions:
            self.recent_transactions.pop(key, None)

    @staticmethod
    def _is_resolver_response(event: DNSEvent) -> bool:
        return (
            event.event_type == "response"
            and event.message_type == "resolver_response"
        )

    @staticmethod
    def _transaction_key(
        event: DNSEvent,
    ) -> tuple[str, str, int, str, int]:
        return (
            _normalize_name(event.query_name),
            event.query_type.upper(),
            event.transaction_id,
            event.source_ip,
            event.dest_port,
        )
