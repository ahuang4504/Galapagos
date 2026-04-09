import asyncio
import json
import logging
import sys

from ingest_dnstap import ingest_events

# Logs go to stderr so stdout stays clean for structured event output.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

SOCKET_PATH = "/var/run/unbound/dnstap.sock"


async def run() -> None:
    logger.info("DNShield detector starting, socket=%s", SOCKET_PATH)

    async for event in ingest_events(SOCKET_PATH):
        record = {
            "event_type": event.event_type,
            "message_type": event.message_type,
            "query_name": event.query_name,
            "query_type": event.query_type,
            "txid": event.transaction_id,
            "source": f"{event.source_ip}:{event.source_port}",
            "dest": f"{event.dest_ip}:{event.dest_port}",
            "rcode": event.response_code,
            "answers": len(event.answers),
            "authority": len(event.authority),
            "additional": len(event.additional),
            "timestamp": event.timestamp.isoformat(),
        }
        print(json.dumps(record), flush=True)


if __name__ == "__main__":
    asyncio.run(run())
