"""
Fallback ingestion for when dnstap isn't available. Parses Unbound's text log
output (log-queries/log-replies) into DNSEvent objects.

Limitation: text logs don't include authority or additional sections, so the
bailiwick heuristic (Phase 5) won't work on this path.
"""

import asyncio
import logging
import re
import sys
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional, TextIO

from models import DNSEvent

logger = logging.getLogger(__name__)

# Unbound query format:  [timestamp] unbound[pid:tid] info: <client_ip> <qname>. <qtype> IN
# Unbound reply format:  [timestamp] unbound[pid:tid] info: reply: <client_ip> <qname>. <qtype> IN <rcode> ...
_QUERY_RE = re.compile(r"\[(\d+)\].*?info:\s+(?!reply:)(\S+)\s+(\S+?\.?)\s+(\S+)\s+IN\s*$")
_REPLY_RE = re.compile(r"\[(\d+)\].*?info:\s+reply:\s+(\S+)\s+(\S+?\.?)\s+(\S+)\s+IN\s+(\S+)")


def _parse_log_line(line: str) -> Optional[DNSEvent]:
    m = _REPLY_RE.search(line)
    if m:
        ts_sec, client_ip, qname, qtype, rcode = m.groups()
        return DNSEvent(
            timestamp=datetime.fromtimestamp(int(ts_sec), tz=timezone.utc),
            event_type="response",
            message_type="client_response",
            query_name=qname.rstrip("."),
            query_type=qtype,
            transaction_id=0,
            source_ip="",
            source_port=0,
            dest_ip=client_ip,
            dest_port=0,
            response_code=rcode,
        )

    m = _QUERY_RE.search(line)
    if m:
        ts_sec, client_ip, qname, qtype = m.groups()
        return DNSEvent(
            timestamp=datetime.fromtimestamp(int(ts_sec), tz=timezone.utc),
            event_type="query",
            message_type="client_query",
            query_name=qname.rstrip("."),
            query_type=qtype,
            transaction_id=0,
            source_ip=client_ip,
            source_port=0,
            dest_ip="",
            dest_port=0,
        )

    return None


async def ingest_events(log_source: Optional[TextIO] = None) -> AsyncGenerator[DNSEvent, None]:
    source = log_source or sys.stdin
    loop = asyncio.get_event_loop()

    # readline() blocks, so run it in a thread to avoid freezing the event loop.
    while True:
        line = await loop.run_in_executor(None, source.readline)
        if not line:
            break
        event = _parse_log_line(line.rstrip("\n"))
        if event is not None:
            yield event
