from models import DNSEvent


Alert = dict[str, object]

_RDATA_DOMAIN_TYPES = {"NS", "CNAME", "DNAME", "PTR"}
_RDATA_TRAILING_DOMAIN_TYPES = {"MX", "SRV"}


def extract_bailiwick_zone(query_name: str) -> str:
    normalized = _normalize_name(query_name)
    labels = [label for label in normalized.split(".") if label]

    if len(labels) <= 2:
        return normalized

    return ".".join(labels[-2:])


def is_in_bailiwick(name: str, zone: str) -> bool:
    normalized_name = _normalize_name(name)
    normalized_zone = _normalize_name(zone)

    if not normalized_name or not normalized_zone:
        return False

    return (
        normalized_name == normalized_zone
        or normalized_name.endswith(f".{normalized_zone}")
    )


class BailiwickEnforcer:
    def process_event(self, event: DNSEvent) -> list[Alert]:
        if event.message_type != "resolver_response" or event.event_type != "response":
            return []

        zone = extract_bailiwick_zone(event.query_name)
        if not zone:
            return []

        referenced_names = self._collect_referenced_names(event)
        alerts = []
        for name, record_type, ttl, rdata in event.additional:
            violation = self._find_additional_violation(name, zone, referenced_names)
            if violation is None:
                continue
            alerts.append(
                self._build_alert(
                    event=event,
                    zone=zone,
                    section_name="additional",
                    record_name=name,
                    record_type=record_type,
                    ttl=ttl,
                    rdata=rdata,
                    violation=violation,
                )
            )

        return alerts

    @staticmethod
    def _find_additional_violation(
        record_name: str,
        zone: str,
        referenced_names: set[str],
    ) -> dict[str, str] | None:
        normalized_name = _normalize_name(record_name)
        if is_in_bailiwick(normalized_name, zone):
            return None
        if normalized_name in referenced_names:
            return None
        return {"field": "name", "value": normalized_name}

    def _collect_referenced_names(self, event: DNSEvent) -> set[str]:
        names: set[str] = set()
        for section in (event.answers, event.authority):
            for _, record_type, _, rdata in section:
                target_name = self._extract_rdata_name(record_type, rdata)
                if target_name:
                    names.add(target_name)
        return names

    @staticmethod
    def _extract_rdata_name(record_type: str, rdata: str) -> str | None:
        normalized_type = record_type.upper()
        stripped = rdata.strip()

        if normalized_type in _RDATA_DOMAIN_TYPES:
            return _normalize_name(stripped)

        if normalized_type in _RDATA_TRAILING_DOMAIN_TYPES:
            parts = stripped.split()
            if parts:
                return _normalize_name(parts[-1])

        return None

    @staticmethod
    def _build_alert(
        *,
        event: DNSEvent,
        zone: str,
        section_name: str,
        record_name: str,
        record_type: str,
        ttl: int,
        rdata: str,
        violation: dict[str, str],
    ) -> Alert:
        return {
            "alert_type": "bailiwick_violation",
            "severity": "CRITICAL",
            "query_domain": event.query_name,
            "bailiwick_zone": zone,
            "section": section_name,
            "violating_field": violation["field"],
            "violating_value": violation["value"],
            "violating_record": {
                "name": _normalize_name(record_name),
                "type": record_type,
                "ttl": ttl,
                "rdata": rdata,
            },
            "timestamp": event.timestamp.isoformat(),
        }


def _normalize_name(name: str) -> str:
    return name.rstrip(".").lower().strip()
