import asyncio
import ipaddress
import logging
import os
import time
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

import dns.exception
import dns.message
import dns.rdatatype
import dns.rcode
from dnstap_pb import dnstap_pb2
from fstrm import (
    FSTRM_CONTROL_ACCEPT,
    FSTRM_CONTROL_FINISH,
    FSTRM_CONTROL_READY,
    FSTRM_CONTROL_START,
    FSTRM_CONTROL_STOP,
    FSTRM_DATA_FRAME,
    FstrmCodec,
)

from models import DNSEvent

logger = logging.getLogger(__name__)

DNSTAP_CONTENT_TYPE = b"protobuf:dnstap.Dnstap"

_MESSAGE_TYPE_MAP = {
    dnstap_pb2.Message.RESOLVER_QUERY:    ("query",    "resolver_query"),
    dnstap_pb2.Message.RESOLVER_RESPONSE: ("response", "resolver_response"),
    dnstap_pb2.Message.CLIENT_QUERY:      ("query",    "client_query"),
    dnstap_pb2.Message.CLIENT_RESPONSE:   ("response", "client_response"),
    dnstap_pb2.Message.AUTH_QUERY:        ("query",    "auth_query"),
    dnstap_pb2.Message.AUTH_RESPONSE:     ("response", "auth_response"),
}


def _extract_rrsets(section) -> list:
    records = []
    for rrset in section:
        name = str(rrset.name).rstrip(".")
        rdtype = dns.rdatatype.to_text(rrset.rdtype)
        ttl = rrset.ttl
        for rdata in rrset:
            records.append((name, rdtype, ttl, str(rdata)))
    return records


def _parse_wire(wire: bytes, is_response: bool) -> Optional[dict]:
    try:
        msg = dns.message.from_wire(wire)
    except Exception as exc:
        logger.debug("DNS wire parse error: %s", exc)
        return None

    q = msg.question[0] if msg.question else None
    result = {
        "query_name": str(q.name).rstrip(".") if q else "",
        "query_type": dns.rdatatype.to_text(q.rdtype) if q else "",
        "transaction_id": msg.id,
        "response_code": None,
        "answers": [],
        "authority": [],
        "additional": [],
    }

    if is_response:
        result["response_code"] = dns.rcode.to_text(msg.rcode())
        result["answers"] = _extract_rrsets(msg.answer)
        result["authority"] = _extract_rrsets(msg.authority)
        result["additional"] = _extract_rrsets(msg.additional)

    return result


def _parse_dnstap_payload(payload: bytes) -> Optional[DNSEvent]:
    dnstap_msg = dnstap_pb2.Dnstap()
    try:
        dnstap_msg.ParseFromString(payload)
    except Exception as exc:
        logger.debug("Protobuf parse error: %s", exc)
        return None

    if dnstap_msg.type != dnstap_pb2.Dnstap.MESSAGE:
        return None

    msg = dnstap_msg.message
    type_info = _MESSAGE_TYPE_MAP.get(msg.type)
    if type_info is None:
        return None

    event_type, message_type = type_info
    is_response = event_type == "response"

    # query_address / response_address are packed bytes (4 for IPv4, 16 for IPv6)
    try:
        source_ip = str(ipaddress.ip_address(msg.query_address)) if msg.query_address else ""
        dest_ip = str(ipaddress.ip_address(msg.response_address)) if msg.response_address else ""
    except ValueError:
        source_ip, dest_ip = "", ""

    if is_response and msg.response_time_sec:
        ts_sec, ts_nsec = msg.response_time_sec, msg.response_time_nsec
    elif msg.query_time_sec:
        ts_sec, ts_nsec = msg.query_time_sec, msg.query_time_nsec
    else:
        logger.warning("dnstap message has no timestamp, using current time")
        ts_sec, ts_nsec = int(time.time()), 0

    timestamp = datetime.fromtimestamp(ts_sec + ts_nsec / 1e9, tz=timezone.utc)

    # Some Unbound builds omit response_message on response events; fall back to query_message.
    wire = msg.response_message if is_response else msg.query_message
    if not wire and is_response:
        wire = msg.query_message
    if not wire:
        logger.warning("dnstap %s has no wire bytes, skipping", message_type)
        return None

    parsed = _parse_wire(wire, is_response)
    if parsed is None:
        return None

    return DNSEvent(
        timestamp=timestamp,
        event_type=event_type,
        message_type=message_type,
        query_name=parsed["query_name"],
        query_type=parsed["query_type"],
        transaction_id=parsed["transaction_id"],
        source_ip=source_ip,
        source_port=msg.query_port,
        dest_ip=dest_ip,
        dest_port=msg.response_port,
        response_code=parsed["response_code"],
        answers=parsed["answers"],
        authority=parsed["authority"],
        additional=parsed["additional"],
    )


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    queue: asyncio.Queue,
) -> None:
    logger.info("fstrm: Unbound connected")
    codec = FstrmCodec()

    async def read_frame() -> tuple:
        # Check the buffer before blocking on read — multiple frames can arrive
        # in one TCP segment, especially during the 3-frame handshake.
        while True:
            if codec.process():
                return codec.decode()
            data = await reader.read(65536)
            if not data:
                raise ConnectionResetError("connection closed")
            codec.append(data)

    try:
        # fstrm handshake: READY → ACCEPT → START → data frames → STOP → FINISH
        ctrl, content_types, _ = await read_frame()
        if ctrl != FSTRM_CONTROL_READY or DNSTAP_CONTENT_TYPE not in content_types:
            logger.warning("fstrm: unexpected handshake frame %d / %s", ctrl, content_types)
            return

        writer.write(codec.encode(FSTRM_CONTROL_ACCEPT, ct=[DNSTAP_CONTENT_TYPE]))
        await writer.drain()

        ctrl, _, _ = await read_frame()
        if ctrl != FSTRM_CONTROL_START:
            logger.warning("fstrm: expected START, got %d", ctrl)
            return

        logger.info("fstrm: handshake done, receiving events")

        while True:
            data = await reader.read(65536)
            if not data:
                break
            codec.append(data)
            while codec.process():
                ctrl, _, payload = codec.decode()
                if ctrl == FSTRM_DATA_FRAME:
                    event = _parse_dnstap_payload(payload)
                    if event is not None:
                        try:
                            queue.put_nowait(event)
                        except asyncio.QueueFull:
                            logger.warning("queue full, dropping %s/%s",
                                           event.event_type, event.query_name)
                elif ctrl == FSTRM_CONTROL_STOP:
                    writer.write(codec.encode(FSTRM_CONTROL_FINISH))
                    await writer.drain()
                    return

    except (ConnectionResetError, asyncio.IncompleteReadError) as exc:
        logger.info("fstrm: connection closed: %s", exc)
    except Exception as exc:
        logger.exception("fstrm: unexpected error: %s", exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def ingest_events(socket_path: str) -> AsyncGenerator[DNSEvent, None]:
    """Listen on a Unix socket for dnstap frames from Unbound, yield DNSEvents."""
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    # Bounded queue — drops events rather than OOM-ing under a Kaminsky flood.
    queue: asyncio.Queue[DNSEvent] = asyncio.Queue(maxsize=10_000)

    server = await asyncio.start_unix_server(
        lambda r, w: _handle_connection(r, w, queue),
        path=socket_path,
    )

    # Unbound runs as the 'unbound' user; world-writable lets it connect.
    os.chmod(socket_path, 0o777)
    logger.info("fstrm: listening on %s", socket_path)

    try:
        async with server:
            server_task = asyncio.create_task(server.serve_forever())
            try:
                while True:
                    yield await queue.get()
            finally:
                server_task.cancel()
                try:
                    await server_task
                except asyncio.CancelledError:
                    pass
    finally:
        if os.path.exists(socket_path):
            os.unlink(socket_path)
