from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from models import DNSEvent


Alert = dict[str, object]


@dataclass
class CUSUMConfig:
    warmup_n: int
    k_sigma: float
    h_sigma: float
    cooldown_seconds: float


@dataclass
class CUSUMState:
    mean: float = 0.0
    std: float = 1.0
    s_plus: float = 0.0
    s_minus: float = 0.0
    n_observations: int = 0
    warmup_samples: list[float] = field(default_factory=list)
    in_warmup: bool = True
    last_alert_time: datetime | None = None


DEFAULT_CUSUM_CONFIGS: dict[str, CUSUMConfig] = {
    "rtt_ms": CUSUMConfig(warmup_n=10, k_sigma=0.5, h_sigma=5.0, cooldown_seconds=60.0),
    "ttl": CUSUMConfig(warmup_n=8, k_sigma=0.3, h_sigma=4.0, cooldown_seconds=120.0),
    "ip_change": CUSUMConfig(warmup_n=6, k_sigma=0.2, h_sigma=3.5, cooldown_seconds=300.0),
    "record_count": CUSUMConfig(warmup_n=10, k_sigma=0.5, h_sigma=5.0, cooldown_seconds=60.0),
}


class CUSUMHeuristic:
    def __init__(
        self,
        feature_configs: dict[str, CUSUMConfig] | None = None,
        query_timeout_seconds: int = 10,
        ip_prefix_octets: int = 2,
    ) -> None:
        self.feature_configs = feature_configs or DEFAULT_CUSUM_CONFIGS
        self.query_timeout = timedelta(seconds=query_timeout_seconds)
        self.ip_prefix_octets = ip_prefix_octets
        self.states: dict[str, dict[str, CUSUMState]] = defaultdict(dict)
        self.pending_queries: dict[tuple[str, str, int, str, int], datetime] = {}
        self.historical_ip_prefixes: dict[str, set[str]] = defaultdict(set)

    def process_event(self, event: DNSEvent) -> list[Alert]:
        self._expire_queries(event.timestamp)

        if not event.message_type.startswith("resolver_"):
            return []
        if not event.query_name or not event.query_type:
            return []

        if event.event_type == "query":
            self.pending_queries[self._event_key(event)] = event.timestamp
            return []

        if event.event_type != "response" or event.message_type != "resolver_response":
            return []

        query_timestamp = self.pending_queries.pop(self._event_key(event), None)
        features = self._extract_features(event, query_timestamp)
        alerts: list[Alert] = []
        for feature_name, observation in features.items():
            config = self.feature_configs.get(feature_name)
            if config is None:
                continue

            state = self.states[event.query_name].setdefault(feature_name, CUSUMState())
            alert = self._update_state(
                state=state,
                config=config,
                observation=observation,
                timestamp=event.timestamp,
            )
            if alert is None:
                continue

            alert.update(
                {
                    "alert_type": "cusum_change_point",
                    "severity": "HIGH",
                    "domain": event.query_name,
                    "query_type": event.query_type,
                    "feature": feature_name,
                    "timestamp": event.timestamp.isoformat(),
                }
            )
            alerts.append(alert)

        return alerts

    def _update_state(
        self,
        *,
        state: CUSUMState,
        config: CUSUMConfig,
        observation: float,
        timestamp: datetime,
    ) -> Alert | None:
        state.n_observations += 1

        if state.in_warmup:
            state.warmup_samples.append(observation)
            if state.n_observations >= config.warmup_n:
                state.mean = sum(state.warmup_samples) / len(state.warmup_samples)
                variance = sum((value - state.mean) ** 2 for value in state.warmup_samples)
                variance /= len(state.warmup_samples)
                state.std = max(variance ** 0.5, 1e-6)
                state.in_warmup = False
                state.warmup_samples = []
            return None

        if state.last_alert_time is not None:
            if timestamp - state.last_alert_time < timedelta(seconds=config.cooldown_seconds):
                return None

        k = config.k_sigma * state.std
        h = config.h_sigma * state.std
        deviation = observation - state.mean
        state.s_plus = max(0.0, state.s_plus + deviation - k)
        state.s_minus = max(0.0, state.s_minus - deviation - k)

        if state.s_plus > h:
            alert = self._build_alert(
                direction="upward_shift",
                observation=observation,
                state=state,
                threshold=h,
            )
        elif state.s_minus > h:
            alert = self._build_alert(
                direction="downward_shift",
                observation=observation,
                state=state,
                threshold=h,
            )
        else:
            return None

        state.last_alert_time = timestamp
        state.s_plus = 0.0
        state.s_minus = 0.0
        return alert

    def _extract_features(
        self,
        event: DNSEvent,
        query_timestamp: datetime | None,
    ) -> dict[str, float]:
        features: dict[str, float] = {}

        if query_timestamp is not None:
            rtt_ms = (event.timestamp - query_timestamp).total_seconds() * 1000.0
            if rtt_ms >= 0:
                features["rtt_ms"] = rtt_ms

        if event.answers:
            features["ttl"] = float(event.answers[0][2])

        features["record_count"] = float(
            len(event.answers) + len(event.authority) + len(event.additional)
        )

        prefix = self._extract_ip_prefix(event)
        if prefix is not None:
            history = self.historical_ip_prefixes[event.query_name]
            features["ip_change"] = 0.0 if prefix in history else 1.0
            history.add(prefix)

        return features

    def _extract_ip_prefix(self, event: DNSEvent) -> str | None:
        for _, record_type, _, rdata in event.answers:
            if record_type != "A":
                continue
            octets = rdata.split(".")
            if len(octets) < self.ip_prefix_octets:
                return None
            return ".".join(octets[: self.ip_prefix_octets])
        return None

    def _build_alert(
        self,
        *,
        direction: str,
        observation: float,
        state: CUSUMState,
        threshold: float,
    ) -> Alert:
        cusum_value = state.s_plus if direction == "upward_shift" else state.s_minus
        return {
            "direction": direction,
            "observation": observation,
            "baseline_mean": state.mean,
            "baseline_std": state.std,
            "cusum_value": cusum_value,
            "threshold": threshold,
            "samples_seen": state.n_observations,
        }

    def _expire_queries(self, now: datetime) -> None:
        expired = [
            key
            for key, timestamp in self.pending_queries.items()
            if now - timestamp > self.query_timeout
        ]
        for key in expired:
            self.pending_queries.pop(key, None)

    def _event_key(self, event: DNSEvent) -> tuple[str, str, int, str, int]:
        if event.message_type == "resolver_query":
            peer_ip = event.dest_ip
            local_port = event.source_port
        else:
            peer_ip = event.source_ip
            local_port = event.dest_port

        return (
            event.query_name.lower(),
            event.query_type.upper(),
            event.transaction_id,
            peer_ip,
            local_port,
        )
