import asyncio
import logging
import os
import sys

from ingest_wire import ingest_events as ingest_wire_events
from heuristics.bailiwick import BailiwickEnforcer
from heuristics.kaminsky_precursor import KaminskyPrecursorDetector
from heuristics.query_response import QueryResponseMatcher
from logger import SummaryStats, log_alert, log_summary
from verification import ActiveVerifier, extract_alert_domain

# Logs go to stderr so stdout stays clean for structured event output.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

ENABLE_VERIFICATION = os.getenv("ENABLE_VERIFICATION", "1") != "0"
WIRE_CAPTURE_INTERFACE = os.getenv("WIRE_CAPTURE_INTERFACE", "eth0")
SUMMARY_INTERVAL_SECONDS = int(os.getenv("SUMMARY_INTERVAL_SECONDS", "60"))
KAMINSKY_THRESHOLD = int(os.getenv("KAMINSKY_THRESHOLD", "20"))
KAMINSKY_WINDOW_SECONDS = int(os.getenv("KAMINSKY_WINDOW_SECONDS", "30"))
KAMINSKY_COOLDOWN_SECONDS = int(os.getenv("KAMINSKY_COOLDOWN_SECONDS", "60"))


async def emit_periodic_summaries(
    stats: SummaryStats,
    matcher: QueryResponseMatcher,
) -> None:
    while True:
        await asyncio.sleep(SUMMARY_INTERVAL_SECONDS)
        log_summary(
            stats.snapshot(
                interval_seconds=SUMMARY_INTERVAL_SECONDS,
                queries_tracked=len(matcher.pending_queries),
            )
        )


async def pump_events(source, queue: asyncio.Queue, source_name: str) -> None:
    try:
        async for event in source:
            await queue.put(event)
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("event pump failed for %s", source_name)


async def run() -> None:
    logger.info(
        "DNShield detector starting, wire interface=%s",
        WIRE_CAPTURE_INTERFACE,
    )
    matcher = QueryResponseMatcher()
    precursor = KaminskyPrecursorDetector(
        threshold=KAMINSKY_THRESHOLD,
        window_seconds=KAMINSKY_WINDOW_SECONDS,
        cooldown_seconds=KAMINSKY_COOLDOWN_SECONDS,
    )
    bailiwick = BailiwickEnforcer()
    verifier = ActiveVerifier() if ENABLE_VERIFICATION else None
    stats = SummaryStats()
    summary_task = asyncio.create_task(emit_periodic_summaries(stats, matcher))
    event_queue: asyncio.Queue = asyncio.Queue(maxsize=20_000)
    pump_tasks = [
        asyncio.create_task(
            pump_events(
                ingest_wire_events(interface=WIRE_CAPTURE_INTERFACE),
                event_queue,
                "wire",
            )
        )
    ]

    try:
        while True:
            event = await event_queue.get()
            stats.record_event(event.sensor, event.message_type)

            alerts = matcher.process_event(event)
            alerts.extend(precursor.process_event(event))
            alerts.extend(bailiwick.process_event(event))
            for alert in alerts:
                domain = extract_alert_domain(alert)
                if domain and "domain" not in alert:
                    alert["domain"] = domain

                if verifier is not None and domain:
                    result = await verifier.verify(domain)
                    alert["verification"] = result.to_dict()
                    stats.record_verification(result.status)

                stats.record_alert()
                log_alert(alert)
    finally:
        for task in pump_tasks:
            task.cancel()
        for task in pump_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass
        summary_task.cancel()
        try:
            await summary_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(run())
