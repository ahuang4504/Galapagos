"""Feature extraction for Isolation Forest training.

extract_features() accepts a plain dict representing a DNS response event,
plus an optional dict for the matched query (for RTT). Returns a 7-element
float32 numpy array in the canonical FEATURE_NAMES order.

Dict schema (mirrors DNSEvent fields):
  query_name   str
  answers      list of (name, rdtype, ttl, rdata) tuples
  authority    list of (name, rdtype, ttl, rdata) tuples
  additional   list of (name, rdtype, ttl, rdata) tuples
  timestamp    datetime (optional, for RTT)
"""
import math
from collections import Counter

import numpy as np

FEATURE_NAMES = [
    "ttl_seconds",          # raw TTL of first answer record (0 if no answers)
    "n_answer_records",     # count of answer RRs
    "n_authority_records",  # count of authority RRs — Kaminsky injects NS delegations here
    "n_additional_records", # count of additional RRs — Kaminsky injects glue records here
    "label_entropy",        # Shannon entropy of leftmost domain label
    "domain_length",        # total char count of queried name (without trailing dot)
    "resolution_time_ms",   # query→response elapsed ms; -1 if query not available
]


def extract_features(response: dict, query: dict | None = None) -> np.ndarray:
    answers = response.get("answers") or []
    authority = response.get("authority") or []
    additional = response.get("additional") or []
    qname = response.get("query_name") or ""

    ttl = int(answers[0][2]) if answers else 0

    labels = qname.rstrip(".").split(".")
    leftmost = labels[0] if labels else ""

    if query is not None:
        try:
            rtt = (response["timestamp"] - query["timestamp"]).total_seconds() * 1000
        except (KeyError, TypeError, AttributeError):
            rtt = -1.0
    else:
        rtt = -1.0

    vec = np.array([
        float(ttl),
        float(len(answers)),
        float(len(authority)),
        float(len(additional)),
        _shannon_entropy(leftmost),
        float(len(qname.rstrip("."))),
        float(rtt),
    ], dtype=np.float32)

    return vec


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))
