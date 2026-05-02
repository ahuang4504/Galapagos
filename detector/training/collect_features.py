"""Collect Isolation Forest training features from live resolver traffic.

Taps the wire capture inside the detector container and records features
from resolver_response events — the raw answers coming back from upstream
authoritative servers. These include authority and additional sections that
client_response events do not carry.

Must be run inside the detector container (needs packet capture on eth0).

Usage:
  PYTHONPATH=/app/src python3 training/collect_features.py \
    --interface eth0 \
    --output training/data/normal_features.parquet
"""
import argparse
import asyncio
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from features import FEATURE_NAMES, extract_features
from ingest_wire import ingest_events


def _query_key(event):
    return (event.query_name, event.query_type, event.transaction_id)


def _event_to_dict(event) -> dict:
    return {
        "query_name": event.query_name,
        "answers": event.answers,
        "authority": event.authority,
        "additional": event.additional,
        "timestamp": event.timestamp,
    }


def _save(rows: list[np.ndarray], output: Path) -> None:
    if not rows:
        print("No features collected.")
        return
    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output, index=False)
    print(f"\nSaved {len(df)} feature vectors to {output}")
    print(df.describe().to_string())


async def run(interface: str, resolver_ip: str, output: Path) -> None:
    pending_queries: dict = {}
    rows: list[np.ndarray] = []
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(__import__("signal").SIGINT, stop.set)
    loop.add_signal_handler(__import__("signal").SIGTERM, stop.set)

    print(f"Listening on {interface} (resolver {resolver_ip}). Ctrl+C to stop and save.")

    async def collect():
        async for event in ingest_events(interface=interface, resolver_ip=resolver_ip):
            if stop.is_set():
                break
            if event.message_type == "resolver_query":
                pending_queries[_query_key(event)] = event
            elif event.message_type == "resolver_response":
                matched = pending_queries.pop(_query_key(event), None)
                try:
                    vec = extract_features(
                        _event_to_dict(event),
                        {"timestamp": matched.timestamp} if matched else None,
                    )
                    rows.append(vec)
                except Exception as exc:
                    print(f"skipped event: {exc}", file=sys.stderr)
                if len(rows) % 200 == 0 and rows:
                    print(f"  collected {len(rows)} feature vectors")

    collector = asyncio.create_task(collect())
    await stop.wait()
    collector.cancel()
    try:
        await collector
    except asyncio.CancelledError:
        pass

    _save(rows, output)


def main():
    parser = argparse.ArgumentParser(description="Collect DNS features from live wire capture")
    parser.add_argument("--interface", default="eth0", help="Network interface to capture on")
    parser.add_argument("--resolver-ip", default="172.28.0.10", help="Resolver IP address")
    parser.add_argument("--output", required=True, help="Output parquet path")
    args = parser.parse_args()

    asyncio.run(run(args.interface, args.resolver_ip, Path(args.output)))


if __name__ == "__main__":
    main()
