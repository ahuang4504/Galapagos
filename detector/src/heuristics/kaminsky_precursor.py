from datetime import datetime, timedelta

from models import DNSEvent


Alert = dict[str, object]


def extract_parent_domain(query_name: str) -> str:
    normalized = query_name.rstrip(".").lower()
    labels = [label for label in normalized.split(".") if label]

    if len(labels) <= 2:
        return normalized

    return ".".join(labels[-2:])


def _looks_random_label(label: str) -> bool:
    normalized = label.strip().lower()
    if len(normalized) < 8 or not normalized.isalnum():
        return False

    unique_ratio = len(set(normalized)) / len(normalized)
    return any(ch.isdigit() for ch in normalized) or unique_ratio >= 0.75


def is_attack_like_query(query_name: str) -> bool:
    normalized = query_name.rstrip(".").lower()
    labels = [label for label in normalized.split(".") if label]
    if len(labels) != 3:
        return False

    return _looks_random_label(labels[0])


class KaminskyPrecursorDetector:
    def __init__(
        self,
        threshold: int = 20,
        window_seconds: int = 30,
        cooldown_seconds: int = 60,
    ) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.subdomain_tracker: dict[str, set[str]] = {}
        self.window_start: dict[str, datetime] = {}
        self.last_alert_time: dict[str, datetime] = {}

    def process_event(self, event: DNSEvent) -> list[Alert]:
        if event.message_type != "resolver_query" or event.event_type != "query":
            return []
        if event.query_type.upper() not in {"A", "AAAA"}:
            return []
        if not is_attack_like_query(event.query_name):
            return []

        parent_domain = extract_parent_domain(event.query_name)
        if not parent_domain:
            return []

        self._reset_window_if_needed(parent_domain, event.timestamp)

        if parent_domain not in self.subdomain_tracker:
            self.subdomain_tracker[parent_domain] = set()
            self.window_start[parent_domain] = event.timestamp

        self.subdomain_tracker[parent_domain].add(event.query_name.lower().rstrip("."))
        unique_count = len(self.subdomain_tracker[parent_domain])

        if unique_count <= self.threshold:
            return []

        last_alert = self.last_alert_time.get(parent_domain)
        if last_alert is not None and event.timestamp - last_alert <= self.cooldown:
            return []

        self.last_alert_time[parent_domain] = event.timestamp
        return [self._build_alert(parent_domain, event.timestamp)]

    def _reset_window_if_needed(self, parent_domain: str, now: datetime) -> None:
        started_at = self.window_start.get(parent_domain)
        if started_at is None:
            return

        if now - started_at > self.window:
            self.subdomain_tracker[parent_domain] = set()
            self.window_start[parent_domain] = now

    def _build_alert(self, parent_domain: str, timestamp: datetime) -> Alert:
        subdomains = sorted(self.subdomain_tracker[parent_domain])
        return {
            "alert_type": "kaminsky_precursor",
            "severity": "CRITICAL",
            "target_domain": parent_domain,
            "unique_subdomains_count": len(subdomains),
            "window_seconds": int(self.window.total_seconds()),
            "sample_subdomains": subdomains[:5],
            "timestamp": timestamp.isoformat(),
        }