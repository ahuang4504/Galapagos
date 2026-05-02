"""Generate Isolation Forest training data from real DNS traffic.

Queries each domain through a resolver, measures RTT, extracts features,
and saves a parquet file ready for train_model.py.

Usage:
  python generate_training_data.py \
    --resolver 172.18.0.2 \
    --domains data/tranco_top5k.txt \
    --output data/normal_features.parquet \
    --passes 2

Get the Tranco list first:
  curl -L https://tranco-list.eu/top-1m.csv.zip -o /tmp/tranco.zip
  unzip -p /tmp/tranco.zip top-1m.csv | head -5000 | cut -d, -f2 \
    > detector/training/data/tranco_top5k.txt
"""
import argparse
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.rdatatype
import dns.resolver
import pandas as pd

from features import FEATURE_NAMES, extract_features


def _rrset_to_tuples(rrset) -> list[tuple]:
    return [
        (str(rrset.name), dns.rdatatype.to_text(rrset.rdtype), rrset.ttl, rr.to_text())
        for rr in rrset
    ]


def _response_to_dicts(answer, qname: str, rtt_ms: float) -> tuple[dict, dict]:
    answers = [t for rs in answer.response.answer for t in _rrset_to_tuples(rs)]
    authority = [t for rs in answer.response.authority for t in _rrset_to_tuples(rs)]
    additional = [t for rs in answer.response.additional for t in _rrset_to_tuples(rs)]

    from datetime import timedelta
    t_response = datetime.now(timezone.utc)
    t_query = t_response - timedelta(milliseconds=rtt_ms)

    response = {
        "query_name": qname.rstrip(".").lower(),
        "answers": answers,
        "authority": authority,
        "additional": additional,
        "timestamp": t_response,
    }
    query = {"timestamp": t_query}
    return response, query


def main():
    parser = argparse.ArgumentParser(description="Generate DNS features for IForest training")
    parser.add_argument("--resolver", required=True, help="Resolver IP address")
    parser.add_argument("--domains", required=True, help="Path to domain list (one per line)")
    parser.add_argument("--output", required=True, help="Output parquet path")
    parser.add_argument("--passes", type=int, default=2, help="Times to iterate the domain list")
    parser.add_argument("--rate", type=float, default=10.0, help="Target queries per second")
    args = parser.parse_args()

    domains = [line.strip() for line in Path(args.domains).read_text(encoding="utf-8").splitlines() if line.strip()]
    print(f"Loaded {len(domains)} domains. Running {args.passes} pass(es) at {args.rate} qps.")

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [args.resolver]
    resolver.timeout = 3
    resolver.lifetime = 3

    interval = 1.0 / args.rate
    rows = []
    total = errors = 0

    for pass_num in range(args.passes):
        random.shuffle(domains)
        for domain in domains:
            qtype = random.choices(["A", "A", "A", "AAAA"], k=1)[0]
            t0 = time.perf_counter()
            try:
                answer = resolver.resolve(domain, qtype)
                rtt_ms = (time.perf_counter() - t0) * 1000
                response_dict, query_dict = _response_to_dicts(answer, domain, rtt_ms)
                vec = extract_features(response_dict, query_dict)
                rows.append(vec)
            except Exception:
                errors += 1
            total += 1
            if total % 500 == 0:
                print(f"  pass {pass_num + 1}/{args.passes}: {total} queries, "
                      f"{errors} errors, {len(rows)} features collected")
            time.sleep(interval * random.uniform(0.5, 1.5))

    print(f"\nDone. {total} queries, {errors} errors, {len(rows)} feature vectors.")

    if not rows:
        print("No features collected — check resolver connectivity.")
        return

    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"Saved {len(df)} rows to {out}")
    print(df.describe().to_string())


if __name__ == "__main__":
    main()
