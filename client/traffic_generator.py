import argparse
import random
import subprocess
import time
from pathlib import Path


DEFAULT_DOMAINS_FILE = Path("/app/domains.txt")


def load_domains(domains_file: str | Path) -> list[str]:
    path = Path(domains_file)
    domains = [
        line.strip().lower().rstrip(".")
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not domains:
        raise ValueError(f"no domains loaded from {path}")
    return domains


def choose_domain(domains: list[str], cache_hit_ratio: float, recent: list[str]) -> str:
    if recent and random.random() < cache_hit_ratio:
        return random.choice(recent)
    return random.choice(domains)


def compute_sleep_interval(qps: float, jitter_ratio: float) -> float:
    if qps <= 0:
        raise ValueError("qps must be positive")

    base = 1.0 / qps
    jitter = base * jitter_ratio
    return max(0.0, random.uniform(base - jitter, base + jitter))


def run_query(domain: str, resolver: str, timeout_seconds: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "dig",
            "+time=1",
            "+tries=1",
            f"+timeout={max(1, int(timeout_seconds))}",
            f"@{resolver}",
            domain,
            "A",
            "+short",
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def run_traffic(args: argparse.Namespace) -> None:
    domains = load_domains(args.domains_file)
    rng_recent: list[str] = []
    query_limit = args.query_count
    deadline = time.monotonic() + args.duration if args.duration else None

    print(
        "traffic generator starting:",
        f"resolver={args.resolver}",
        f"domains={len(domains)}",
        f"qps={args.qps}",
        f"cache_hit_ratio={args.cache_hit_ratio}",
        flush=True,
    )

    sent = 0
    while True:
        if query_limit is not None and sent >= query_limit:
            break
        if deadline is not None and time.monotonic() >= deadline:
            break

        domain = choose_domain(domains, args.cache_hit_ratio, rng_recent)
        result = run_query(domain, args.resolver, args.timeout_seconds)
        answer = result.stdout.strip().splitlines()
        status = "ok" if result.returncode == 0 else f"rc={result.returncode}"
        print(
            f"[{sent + 1}] domain={domain} status={status} answers={answer[:2]}",
            flush=True,
        )

        rng_recent.append(domain)
        if len(rng_recent) > args.recent_window:
            rng_recent.pop(0)

        sent += 1
        time.sleep(compute_sleep_interval(args.qps, args.jitter_ratio))

    print(f"traffic generator finished: queries_sent={sent}", flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Baseline DNS traffic generator")
    parser.add_argument("--resolver", default="172.28.0.10")
    parser.add_argument("--domains-file", default=str(DEFAULT_DOMAINS_FILE))
    parser.add_argument("--qps", type=float, default=5.0)
    parser.add_argument("--jitter-ratio", type=float, default=0.25)
    parser.add_argument("--cache-hit-ratio", type=float, default=0.35)
    parser.add_argument("--recent-window", type=int, default=20)
    parser.add_argument("--query-count", type=int, default=None)
    parser.add_argument("--duration", type=float, default=None)
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    return parser


if __name__ == "__main__":
    run_traffic(build_parser().parse_args())
