from models import DNSEvent


Alert = dict[str, object]

_ALLOWED_ADDITIONAL_REF_TYPES = {"NS", "CNAME", "DNAME", "PTR"}
_ALLOWED_ADDITIONAL_TRAILING_TYPES = {"MX", "SRV"}
_ALLOWED_GLUE_TYPES = {"A", "AAAA"}


def extract_bailiwick_zone(query_name: str) -> str:
    normalized = _normalize_name(query_name)
    if not normalized or normalized == ".":
        return "."
    return parent_zone(normalized)


def parent_zone(name: str) -> str:
    normalized = _normalize_name(name)
    if not normalized or normalized == ".":
        return "."

    labels = [label for label in normalized.split(".") if label]
    if len(labels) <= 1:
        return "."
    return ".".join(labels[1:])


def is_in_bailiwick(name: str, zone: str) -> bool:
    normalized_name = _normalize_name(name)
    normalized_zone = _normalize_name(zone)

    if not normalized_name or not normalized_zone:
        return False
    if normalized_zone == ".":
        return normalized_name != ""

    return normalized_name == normalized_zone or normalized_name.endswith(f".{normalized_zone}")


def is_ancestor_or_equal(ancestor: str, name: str) -> bool:
    normalized_ancestor = _normalize_name(ancestor)
    normalized_name = _normalize_name(name)

    if not normalized_ancestor or not normalized_name:
        return False
    if normalized_ancestor == ".":
        return normalized_name != ""

    return normalized_name == normalized_ancestor or normalized_name.endswith(
        f".{normalized_ancestor}"
    )


class BailiwickEnforcer:
    def __init__(self) -> None:
        self.pending_queries: dict[tuple[str, str, int, str, int], str] = {}
        self.known_zones: set[str] = {"."}
        self.peer_zones: dict[str, str] = {}

    def process_event(self, event: DNSEvent) -> list[Alert]:
        if not event.message_type.startswith("resolver_"):
            return []
        if not event.query_name or not event.query_type:
            return []

        if event.event_type == "query" and event.message_type == "resolver_query":
            self.pending_queries[self._event_key(event)] = self._infer_query_zone(event)
            return []

        if event.message_type != "resolver_response" or event.event_type != "response":
            return []

        qzone = self.pending_queries.pop(self._event_key(event), None)
        if qzone is None:
            qzone = self.peer_zones.get(event.source_ip) or self._fallback_qzone(event)

        alerts: list[Alert] = []
        _, answer_alerts, additional_reference_names = self._validate_answers(event, qzone)
        alerts.extend(answer_alerts)

        authority_reference_names: set[str] = set()
        delegation_targets: dict[str, set[str]] = {}
        for name, record_type, ttl, rdata in event.authority:
            violation = self._validate_authority_record(
                query_name=event.query_name,
                qzone=qzone,
                record_name=name,
                record_type=record_type,
            )
            if violation is not None:
                alerts.append(
                    self._build_alert(
                        event=event,
                        qzone=qzone,
                        section_name="authority",
                        record_name=name,
                        record_type=record_type,
                        ttl=ttl,
                        rdata=rdata,
                        violation=violation,
                    )
                )
                continue

            target_name = self._extract_rdata_name(record_type, rdata)
            if target_name:
                authority_reference_names.add(target_name)
                if record_type.upper() == "NS":
                    delegation_targets.setdefault(_normalize_name(name), set()).add(target_name)

        allowed_additional_names = additional_reference_names | authority_reference_names
        valid_additional_records: list[tuple[str, str, int, str]] = []
        for name, record_type, ttl, rdata in event.additional:
            violation = self._validate_additional_record(
                record_name=name,
                record_type=record_type,
                allowed_names=allowed_additional_names,
            )
            if violation is None:
                valid_additional_records.append((name, record_type, ttl, rdata))
                continue
            alerts.append(
                self._build_alert(
                    event=event,
                    qzone=qzone,
                    section_name="additional",
                    record_name=name,
                    record_type=record_type,
                    ttl=ttl,
                    rdata=rdata,
                    violation=violation,
                )
            )

        self._learn_zones(event, qzone, delegation_targets, valid_additional_records)
        return alerts

    def _infer_query_zone(self, event: DNSEvent) -> str:
        peer_zone = self.peer_zones.get(event.dest_ip)
        if peer_zone:
            return peer_zone
        return self._current_qzone(event.query_name)

    def _validate_answers(
        self,
        event: DNSEvent,
        qzone: str,
    ) -> tuple[set[str], list[Alert], set[str]]:
        allowed_names = {_normalize_name(event.query_name)}
        alerts: list[Alert] = []
        referenced_names: set[str] = set()

        for name, record_type, ttl, rdata in event.answers:
            normalized_name = _normalize_name(name)
            if normalized_name not in allowed_names:
                alerts.append(
                    self._build_alert(
                        event=event,
                        qzone=qzone,
                        section_name="answer",
                        record_name=name,
                        record_type=record_type,
                        ttl=ttl,
                        rdata=rdata,
                        violation={"field": "name", "value": normalized_name},
                    )
                )
                continue

            target_name = self._extract_rdata_name(record_type, rdata)
            if record_type.upper() in {"CNAME", "DNAME"} and target_name:
                allowed_names.add(target_name)
            if target_name:
                referenced_names.add(target_name)

        return allowed_names, alerts, referenced_names

    def _validate_authority_record(
        self,
        *,
        query_name: str,
        qzone: str,
        record_name: str,
        record_type: str,
    ) -> dict[str, str] | None:
        normalized_name = _normalize_name(record_name)
        normalized_type = record_type.upper()
        normalized_query = _normalize_name(query_name)

        if normalized_type == "NS":
            if not is_in_bailiwick(normalized_name, qzone):
                return {"field": "name", "value": normalized_name}
            if not is_ancestor_or_equal(normalized_name, normalized_query):
                return {"field": "name", "value": normalized_name}
            return None

        if normalized_type == "SOA":
            if not is_in_bailiwick(normalized_name, qzone):
                return {"field": "name", "value": normalized_name}
            if not is_ancestor_or_equal(normalized_name, normalized_query):
                return {"field": "name", "value": normalized_name}
            return None

        return None

    @staticmethod
    def _validate_additional_record(
        *,
        record_name: str,
        record_type: str,
        allowed_names: set[str],
    ) -> dict[str, str] | None:
        normalized_type = record_type.upper()
        if normalized_type not in _ALLOWED_GLUE_TYPES:
            return None

        normalized_name = _normalize_name(record_name)
        if normalized_name in allowed_names:
            return None
        return {"field": "name", "value": normalized_name}

    def _learn_zones(
        self,
        event: DNSEvent,
        qzone: str,
        delegation_targets: dict[str, set[str]],
        valid_additional_records: list[tuple[str, str, int, str]],
    ) -> None:
        self.known_zones.add(_normalize_name(qzone) or ".")

        query_name = _normalize_name(event.query_name)
        for name, record_type, _, _ in event.authority:
            normalized_name = _normalize_name(name)
            normalized_type = record_type.upper()
            if normalized_type not in {"NS", "SOA"}:
                continue
            if not is_in_bailiwick(normalized_name, qzone):
                continue
            if not is_ancestor_or_equal(normalized_name, query_name):
                continue
            self.known_zones.add(normalized_name)
            if normalized_type == "SOA":
                self.peer_zones[event.source_ip] = normalized_name

        for zone_name, targets in delegation_targets.items():
            self.known_zones.add(zone_name)
            for name, record_type, _, rdata in valid_additional_records:
                normalized_name = _normalize_name(name)
                if normalized_name not in targets:
                    continue
                if record_type.upper() not in _ALLOWED_GLUE_TYPES:
                    continue
                self.peer_zones[rdata] = zone_name

    def _current_qzone(self, query_name: str) -> str:
        normalized_query = _normalize_name(query_name)
        matches = [zone for zone in self.known_zones if is_in_bailiwick(normalized_query, zone)]
        if not matches:
            return "."
        return max(matches, key=_zone_specificity)

    def _fallback_qzone(self, event: DNSEvent) -> str:
        for name, record_type, _, _ in event.authority:
            normalized_type = record_type.upper()
            normalized_name = _normalize_name(name)
            if normalized_type == "SOA":
                return normalized_name
            if normalized_type == "NS" and is_ancestor_or_equal(normalized_name, event.query_name):
                return parent_zone(normalized_name)
        return self._current_qzone(event.query_name)

    @staticmethod
    def _extract_rdata_name(record_type: str, rdata: str) -> str | None:
        normalized_type = record_type.upper()
        stripped = rdata.strip()

        if normalized_type in _ALLOWED_ADDITIONAL_REF_TYPES:
            return _normalize_name(stripped)

        if normalized_type in _ALLOWED_ADDITIONAL_TRAILING_TYPES:
            parts = stripped.split()
            if parts:
                return _normalize_name(parts[-1])

        return None

    @staticmethod
    def _event_key(event: DNSEvent) -> tuple[str, str, int, str, int]:
        if event.message_type == "resolver_query":
            peer_ip = event.dest_ip
            local_port = event.source_port
        else:
            peer_ip = event.source_ip
            local_port = event.dest_port

        return (
            _normalize_name(event.query_name),
            event.query_type.upper(),
            event.transaction_id,
            peer_ip,
            local_port,
        )

    @staticmethod
    def _build_alert(
        *,
        event: DNSEvent,
        qzone: str,
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
            "bailiwick_zone": qzone,
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
    normalized = name.rstrip(".").lower().strip()
    return normalized or "."


def _zone_specificity(zone: str) -> tuple[int, int]:
    normalized = _normalize_name(zone)
    if normalized == ".":
        return (0, 0)
    return (len(normalized.split(".")), len(normalized))