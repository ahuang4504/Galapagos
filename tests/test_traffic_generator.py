import tempfile
from pathlib import Path
import sys

sys.path.insert(0, "client")

from traffic_generator import choose_domain, compute_sleep_interval, load_domains


def test_load_domains_ignores_comments_and_normalizes() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "domains.txt"
        path.write_text(
            "# comment\n"
            "Example.COM.\n"
            "\n"
            "OpenAI.com\n"
        )

        domains = load_domains(path)

    assert domains == ["example.com", "openai.com"]


def test_choose_domain_can_reuse_recent_items() -> None:
    domains = ["example.com", "openai.com", "python.org"]
    recent = ["cached.example"]

    chosen = choose_domain(domains, cache_hit_ratio=1.0, recent=recent)
    assert chosen == "cached.example"


def test_compute_sleep_interval_stays_non_negative() -> None:
    interval = compute_sleep_interval(qps=5.0, jitter_ratio=0.9)
    assert interval >= 0.0


def test_compute_sleep_interval_requires_positive_qps() -> None:
    try:
        compute_sleep_interval(qps=0.0, jitter_ratio=0.1)
    except ValueError as exc:
        assert "qps must be positive" in str(exc)
    else:
        raise AssertionError("expected ValueError for non-positive qps")
