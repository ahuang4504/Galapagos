from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from models import DNSEvent


Alert = dict[str, object]


@dataclass
class PendingQuery:
    query_event: DNSEvent
    first_response: Optional[DNSEvent] = None
    first_response_at: Optional[datetime] = None
    duplicate_alerted: bool = False


class QueryResponseMatcher:
    def __init__(
        self,
        query_timeout_seconds: int = 10,
        duplicate_grace_seconds: int = 2,
        startup_grace_seconds: int = 2,
    ) -> None:
        self.query_timeout = timedelta(seconds=query_timeout_seconds)
        self.duplicate_grace = timedelta(seconds=duplicate_grace_seconds)
        self.startup_grace = timedelta(seconds=startup_grace_seconds)
        self.pending_queries: dict[tuple[str, str, int, str, int], PendingQuery] = {}
        self.start_time: datetime | None = None

    def process_event(self, event: DNSEvent) -> list[Alert]:
        if self.start_time is None:
            self.start_time = event.timestamp

        self._sweep_expired(event.timestamp)

        if not event.message_type.startswith("resolver_"):
            return []

        # Some resolver-side responses observed during startup/root priming do
        # not carry a usable DNS question. Without qname/qtype we cannot build
        # a trustworthy correlation key, so treating them as unsolicited would
        # create false positives.
        if not event.query_name or not event.query_type:
            return []

        if event.event_type == "query":
            self.pending_queries[self._event_key(event)] = PendingQuery(query_event=event)
            return []

        if event.event_type != "response":
            return []

        key = self._event_key(event)
        pending = self.pending_queries.get(key)
        if pending is None:
            if self.start_time is not None and event.timestamp - self.start_time < self.startup_grace:
                return []
            return [self._unsolicited_alert(event)]

        if pending.first_response is None:
            pending.first_response = event
            pending.first_response_at = event.timestamp
            return []

        if pending.duplicate_alerted:
            return []

        pending.duplicate_alerted = True
        return [self._duplicate_alert(pending.first_response, event)]

    def _sweep_expired(self, now: datetime) -> None:
        expired_keys = []
        for key, pending in self.pending_queries.items():
            if pending.first_response_at is not None:
                if now - pending.first_response_at > self.duplicate_grace:
                    expired_keys.append(key)
            elif now - pending.query_event.timestamp > self.query_timeout:
                expired_keys.append(key)

        for key in expired_keys:
            self.pending_queries.pop(key, None)

    @staticmethod
    def _event_key(event: DNSEvent) -> tuple[str, str, int, str, int]:
        if event.message_type == "resolver_query":
            peer_ip = event.dest_ip
            local_port = event.source_port
        elif event.message_type == "resolver_response":
            peer_ip = event.source_ip
            local_port = event.dest_port
        else:
            peer_ip = event.dest_ip
            local_port = event.source_port

        return (
            event.query_name.lower(),
            event.query_type.upper(),
            event.transaction_id,
            peer_ip,
            local_port,
        )

    @staticmethod
    def _unsolicited_alert(event: DNSEvent) -> Alert:
        return {
            "alert_type": "unsolicited_response",
            "severity": "HIGH",
            "domain": event.query_name,
            "query_type": event.query_type,
            "txid": event.transaction_id,
            "source_ip": event.source_ip,
            "source_port": event.source_port,
            "timestamp": event.timestamp.isoformat(),
        }

    @staticmethod
    def _duplicate_alert(first_response: DNSEvent, second_response: DNSEvent) -> Alert:
        return {
            "alert_type": "duplicate_response",
            "severity": "HIGH",
            "domain": second_response.query_name,
            "query_type": second_response.query_type,
            "txid": second_response.transaction_id,
            "first_answer": first_response.answers,
            "second_answer": second_response.answers,
            "timestamp": second_response.timestamp.isoformat(),
        }
