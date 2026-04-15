from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

from models import DNSEvent


class ResolverConfirmationTracker:
    def __init__(self, retention_seconds: int = 30) -> None:
        self.retention = timedelta(seconds=retention_seconds)
        self.events_by_domain: dict[str, deque[dict[str, object]]] = defaultdict(deque)

    def process_event(self, event: DNSEvent) -> None:
        if event.sensor != "dnstap":
            return
        if event.event_type != "response":
            return
        if not event.query_name:
            return

        now = event.timestamp
        normalized = event.query_name.rstrip(".").lower()
        bucket = self.events_by_domain[normalized]
        bucket.append(
            {
                "timestamp": now,
                "message_type": event.message_type,
                "query_type": event.query_type,
                "response_code": event.response_code,
                "answers": event.answers,
            }
        )
        self._expire(now)

    def confirm_for_alert(
        self,
        alert: dict[str, object],
        now: datetime,
    ) -> dict[str, object] | None:
        self._expire(now)
        domains = self._domains_for_alert(alert)
        if not domains:
            return None

        matched: list[tuple[str, dict[str, object]]] = []
        for domain in domains:
            for entry in self.events_by_domain.get(domain, ()): 
                matched.append((domain, entry))

        if not matched:
            return None

        matched.sort(key=lambda item: item[1]["timestamp"])
        counts = Counter(entry["message_type"] for _, entry in matched)
        latest_domain, latest_entry = matched[-1]

        return {
            "sensor": "dnstap",
            "matched_domains": sorted({domain for domain, _ in matched}),
            "message_types": dict(sorted(counts.items())),
            "resolver_response_seen": counts.get("resolver_response", 0) > 0,
            "client_response_seen": counts.get("client_response", 0) > 0,
            "latest_domain": latest_domain,
            "latest_timestamp": latest_entry["timestamp"].isoformat(),
            "latest_response_code": latest_entry["response_code"],
            "latest_answers": latest_entry["answers"],
        }

    def _expire(self, now: datetime) -> None:
        empty_domains = []
        for domain, bucket in self.events_by_domain.items():
            while bucket and now - bucket[0]["timestamp"] > self.retention:
                bucket.popleft()
            if not bucket:
                empty_domains.append(domain)
        for domain in empty_domains:
            self.events_by_domain.pop(domain, None)

    @staticmethod
    def _domains_for_alert(alert: dict[str, object]) -> list[str]:
        domains: list[str] = []
        for key in ("domain", "query_domain", "target_domain"):
            value = alert.get(key)
            if isinstance(value, str) and value.strip():
                normalized = value.rstrip(".").lower()
                if normalized not in domains:
                    domains.append(normalized)
        return domains
