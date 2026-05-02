import asyncio
import logging
import os
import sys
from pathlib import Path

from ingest_wire import ingest_events as ingest_wire_events
from heuristics.kaminsky_precursor import KaminskyPrecursorDetector
from logger import SummaryStats, log_alert, log_summary
from tcp_mitigation import TCPMitigator
from verification import ActiveVerifier, extract_alert_domain
from anomaly.scorer import IForestScorer
from anomaly.cache_flusher import CacheFlusher

# Logs go to stderr so stdout stays clean for structured event output.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

ENABLE_DEFENSE = os.getenv("ENABLE_DEFENSE", "1") != "0"
WIRE_CAPTURE_INTERFACE = os.getenv("WIRE_CAPTURE_INTERFACE", "eth0")
IFOREST_MODEL_PATH = Path(os.getenv("IFOREST_MODEL_PATH", "training/data/iforest.joblib"))
IFOREST_THRESHOLD = float(os.getenv("IFOREST_THRESHOLD", "0.6"))
ENABLE_IFOREST = os.getenv("ENABLE_IFOREST", "1") != "0"
ENABLE_CACHE_FLUSH = os.getenv("ENABLE_CACHE_FLUSH", "0") != "0"
UNBOUND_CONTROL_HOST = os.getenv("UNBOUND_CONTROL_HOST", "127.0.0.1")
UNBOUND_CONTROL_PORT = int(os.getenv("UNBOUND_CONTROL_PORT", "8953"))
CACHE_FLUSH_COOLDOWN_SECONDS = int(os.getenv("CACHE_FLUSH_COOLDOWN_SECONDS", "60"))
SUMMARY_INTERVAL_SECONDS = int(os.getenv("SUMMARY_INTERVAL_SECONDS", "60"))
KAMINSKY_THRESHOLD = int(os.getenv("KAMINSKY_THRESHOLD", "20"))
KAMINSKY_WINDOW_SECONDS = int(os.getenv("KAMINSKY_WINDOW_SECONDS", "30"))
KAMINSKY_COOLDOWN_SECONDS = int(os.getenv("KAMINSKY_COOLDOWN_SECONDS", "60"))
TCP_MITIGATION_ARM_SECONDS = int(os.getenv("TCP_MITIGATION_ARM_SECONDS", "30"))
TCP_MITIGATION_REPEAT_COUNT = int(os.getenv("TCP_MITIGATION_REPEAT_COUNT", "3"))
TCP_MITIGATION_TRANSACTION_COOLDOWN_SECONDS = int(
    os.getenv("TCP_MITIGATION_TRANSACTION_COOLDOWN_SECONDS", "2")
)


async def emit_periodic_summaries(stats: SummaryStats) -> None:
    while True:
        await asyncio.sleep(SUMMARY_INTERVAL_SECONDS)
        log_summary(
            stats.snapshot(
                interval_seconds=SUMMARY_INTERVAL_SECONDS,
                queries_tracked=0,
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
        "DNShield detector starting, wire interface=%s, defense_enabled=%s",
        WIRE_CAPTURE_INTERFACE,
        ENABLE_DEFENSE,
    )
    precursor = (
        KaminskyPrecursorDetector(
            threshold=KAMINSKY_THRESHOLD,
            window_seconds=KAMINSKY_WINDOW_SECONDS,
            cooldown_seconds=KAMINSKY_COOLDOWN_SECONDS,
        )
        if ENABLE_DEFENSE
        else None
    )
    verifier = ActiveVerifier() if ENABLE_DEFENSE else None
    tcp_mitigator = (
        TCPMitigator(
            armed_domain_seconds=TCP_MITIGATION_ARM_SECONDS,
            repeat_count=TCP_MITIGATION_REPEAT_COUNT,
            transaction_cooldown_seconds=TCP_MITIGATION_TRANSACTION_COOLDOWN_SECONDS,
        )
        if ENABLE_DEFENSE
        else None
    )
    if ENABLE_DEFENSE and ENABLE_IFOREST and IFOREST_MODEL_PATH.exists():
        iforest_scorer = IForestScorer(IFOREST_MODEL_PATH, IFOREST_THRESHOLD)
    else:
        if ENABLE_DEFENSE and ENABLE_IFOREST:
            logger.warning("iforest: model not found at %s, scoring disabled", IFOREST_MODEL_PATH)
        iforest_scorer = None
    cache_flusher = (
        CacheFlusher(
            enabled=ENABLE_CACHE_FLUSH,
            control_host=UNBOUND_CONTROL_HOST,
            control_port=UNBOUND_CONTROL_PORT,
            cooldown_seconds=CACHE_FLUSH_COOLDOWN_SECONDS,
        )
        if ENABLE_DEFENSE
        else None
    )
    stats = SummaryStats()
    summary_task = asyncio.create_task(emit_periodic_summaries(stats))
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

            alerts: list[dict[str, object]] = []
            if precursor is not None:
                alerts.extend(precursor.process_event(event))
            if iforest_scorer is not None:
                iforest_alert = iforest_scorer.process_event(event)
                if iforest_alert:
                    alerts.append(iforest_alert)
            if tcp_mitigator is not None:
                tcp_mitigator.process_event(event, alerts)
            for alert in alerts:
                domain = extract_alert_domain(alert)
                if domain and "domain" not in alert:
                    alert["domain"] = domain

                if verifier is not None and domain:
                    result = await verifier.verify(domain)
                    alert["verification"] = result.to_dict()
                    stats.record_verification(result.status)

                    if (
                        cache_flusher is not None
                        and alert.get("alert_type") == "iforest_anomaly"
                        and result.status == "CONFIRMED"
                    ):
                        alert["cache_flush"] = cache_flusher.flush(domain)

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
