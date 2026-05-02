"""Isolation Forest scorer for live DNS resolver_response events.

Buffers resolver_query events for RTT matching, then scores every
resolver_response. If the anomaly score exceeds the threshold, emits
an alert dict that flows through the existing alert pipeline in main.py.
"""
import logging
import math
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np

# Add training/ to path so we can import extract_features and FEATURE_NAMES
# without duplicating them here.
_TRAINING_DIR = Path(__file__).resolve().parent.parent.parent / "training"
if str(_TRAINING_DIR) not in sys.path:
    sys.path.insert(0, str(_TRAINING_DIR))

from features import FEATURE_NAMES, extract_features  # noqa: E402
from models import DNSEvent  # noqa: E402

logger = logging.getLogger(__name__)

Alert = dict[str, object]

_QUERY_SWEEP_INTERVAL = timedelta(seconds=30)
_QUERY_MAX_AGE = timedelta(seconds=10)
_ALERT_COOLDOWN = timedelta(seconds=60)


def _query_key(event: DNSEvent) -> tuple:
    return (event.query_name, event.query_type, event.transaction_id)


class IForestScorer:
    def __init__(self, model_path: Path, threshold: float) -> None:
        self.model = joblib.load(model_path)
        self.threshold = threshold
        self.pending_queries: dict[tuple, DNSEvent] = {}
        self.last_alert: dict[str, datetime] = {}
        self._last_sweep: datetime = datetime.now(timezone.utc)
        logger.info("iforest: loaded model from %s (threshold=%.2f)", model_path, threshold)

    def process_event(self, event: DNSEvent) -> Alert | None:
        self._maybe_sweep(event.timestamp)

        if event.message_type == "resolver_query":
            self.pending_queries[_query_key(event)] = event
            return None

        if event.message_type != "resolver_response":
            return None

        matched = self.pending_queries.pop(_query_key(event), None)
        response_dict = {
            "query_name": event.query_name,
            "answers": event.answers,
            "authority": event.authority,
            "additional": event.additional,
            "timestamp": event.timestamp,
        }
        query_dict = {"timestamp": matched.timestamp} if matched else None

        # CRITICAL: vec is in FEATURE_NAMES positional order — matches training.
        # Do NOT reorder. model.score_samples() reads features by position.
        vec = extract_features(response_dict, query_dict)
        raw_score = float(self.model.score_samples(vec.reshape(1, -1))[0])
        anomaly_score = 1.0 / (1.0 + math.exp(raw_score))

        if anomaly_score < self.threshold:
            return None

        last = self.last_alert.get(event.query_name)
        if last is not None and event.timestamp - last <= _ALERT_COOLDOWN:
            return None
        self.last_alert[event.query_name] = event.timestamp

        logger.warning(
            "iforest: anomaly detected domain=%s score=%.4f raw=%.4f",
            event.query_name,
            anomaly_score,
            raw_score,
        )
        return {
            "alert_type": "iforest_anomaly",
            "severity": "HIGH",
            "domain": event.query_name,
            "anomaly_score": round(anomaly_score, 4),
            "raw_score": round(raw_score, 4),
            "threshold": self.threshold,
            "feature_vector": vec.tolist(),
            "feature_names": FEATURE_NAMES,
            "timestamp": event.timestamp.isoformat(),
        }

    def _maybe_sweep(self, now: datetime) -> None:
        if now - self._last_sweep < _QUERY_SWEEP_INTERVAL:
            return
        cutoff = now - _QUERY_MAX_AGE
        stale = [k for k, v in self.pending_queries.items() if v.timestamp < cutoff]
        for k in stale:
            del self.pending_queries[k]
        self._last_sweep = now
