import asyncio
import ipaddress
import logging
import os
import struct
from datetime import datetime, timezone
from typing import AsyncGenerator

import dns.message
import dns.rcode
import dns.rdatatype

from models import DNSEvent


logger = logging.getLogger(__name__)

DNSTAP_SOCKET_PATH = os.getenv("DNSTAP_SOCKET_PATH", "/var/run/unbound/dnstap.sock")
DNSTAP_CONTENT_TYPE = b"protobuf:dnstap.Dnstap"

FSTRM_CONTROL_FRAME_ACCEPT = 0x01
FSTRM_CONTROL_FRAME_START = 0x02
FSTRM_CONTROL_FRAME_STOP = 0x03
FSTRM_CONTROL_FRAME_READY = 0x04
FSTRM_CONTROL_FRAME_FINISH = 0x05
FSTRM_CONTROL_FIELD_CONTENT_TYPE = 0x01

DNSTAP_TYPE_MESSAGE = 1
MESSAGE_TYPE_MAP = {
    3: "resolver_query",
    4: "resolver_response",
    5: "client_query",
    6: "client_response",
}


def _decode_varint(payload: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(payload):
            raise ValueError("truncated varint")
        byte = payload[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("varint too large")


def _parse_proto_fields(payload: bytes) -> dict[int, list[object]]:
    fields: dict[int, list[object]] = {}
    offset = 0
    while offset < len(payload):
        key, offset = _decode_varint(payload, offset)
        field_number = key >> 3
        wire_type = key & 0x07

        if wire_type == 0:
            value, offset = _decode_varint(payload, offset)
        elif wire_type == 1:
            if offset + 8 > len(payload):
                raise ValueError("truncated fixed64")
            value = struct.unpack("<Q", payload[offset : offset + 8])[0]
            offset += 8
        elif wire_type == 2:
            length, offset = _decode_varint(payload, offset)
            if offset + length > len(payload):
                raise ValueError("truncated length-delimited field")
            value = payload[offset : offset + length]
            offset += length
        elif wire_type == 5:
            if offset + 4 > len(payload):
                raise ValueError("truncated fixed32")
            value = struct.unpack("<I", payload[offset : offset + 4])[0]
            offset += 4
        else:
            raise ValueError(f"unsupported wire type: {wire_type}")

        fields.setdefault(field_number, []).append(value)
    return fields


def _first(fields: dict[int, list[object]], number: int) -> object | None:
    values = fields.get(number)
    if not values:
        return None
    return values[0]


def _bytes_to_ip(value: object | None) -> str:
    if not isinstance(value, (bytes, bytearray)):
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _message_timestamp(fields: dict[int, list[object]], *, response: bool) -> datetime:
    sec_field = 12 if response else 8
    nsec_field = 13 if response else 9
    seconds = _first(fields, sec_field)
    nanoseconds = _first(fields, nsec_field)
    if not isinstance(seconds, int):
        return datetime.now(timezone.utc)
    if not isinstance(nanoseconds, int):
        nanoseconds = 0
    return datetime.fromtimestamp(
        seconds + (nanoseconds / 1_000_000_000),
        tz=timezone.utc,
    )


def _extract_rrs(section) -> list[tuple[str, str, int, str]]:
    records: list[tuple[str, str, int, str]] = []
    for rrset in section:
        for rdata in rrset:
            records.append(
                (
                    rrset.name.to_text().rstrip(".").lower(),
                    dns.rdatatype.to_text(rrset.rdtype),
                    int(rrset.ttl),
                    rdata.to_text().rstrip("."),
                )
            )
    return records


def _dnstap_payload_to_event(payload: bytes) -> DNSEvent | None:
    top_fields = _parse_proto_fields(payload)
    if _first(top_fields, 15) != DNSTAP_TYPE_MESSAGE:
        return None

    message_payload = _first(top_fields, 14)
    if not isinstance(message_payload, (bytes, bytearray)):
        return None

    message_fields = _parse_proto_fields(message_payload)
    message_type_value = _first(message_fields, 1)
    if not isinstance(message_type_value, int):
        return None

    message_type = MESSAGE_TYPE_MAP.get(message_type_value)
    if message_type is None:
        return None

    response = message_type.endswith("response")
    raw_dns = _first(message_fields, 14 if response else 10)
    if not isinstance(raw_dns, (bytes, bytearray)):
        return None

    try:
        dns_message = dns.message.from_wire(raw_dns)
    except Exception:
        logger.exception("dnstap: failed to parse embedded DNS message")
        return None

    question = dns_message.question[0] if dns_message.question else None
    query_name = (
        question.name.to_text().rstrip(".").lower()
        if question is not None
        else ""
    )
    query_type = (
        dns.rdatatype.to_text(question.rdtype)
        if question is not None
        else ""
    )

    initiator_ip = _bytes_to_ip(_first(message_fields, 4))
    responder_ip = _bytes_to_ip(_first(message_fields, 5))
    initiator_port = int(_first(message_fields, 6) or 0)
    responder_port = int(_first(message_fields, 7) or 0)

    if response:
        source_ip = responder_ip
        source_port = responder_port
        dest_ip = initiator_ip
        dest_port = initiator_port
        event_type = "response"
    else:
        source_ip = initiator_ip
        source_port = initiator_port
        dest_ip = responder_ip
        dest_port = responder_port
        event_type = "query"

    return DNSEvent(
        timestamp=_message_timestamp(message_fields, response=response),
        event_type=event_type,
        message_type=message_type,
        query_name=query_name,
        query_type=query_type,
        transaction_id=int(dns_message.id),
        source_ip=source_ip,
        source_port=source_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        response_code=dns.rcode.to_text(dns_message.rcode()) if response else None,
        answers=_extract_rrs(dns_message.answer) if response else [],
        authority=_extract_rrs(dns_message.authority) if response else [],
        additional=_extract_rrs(dns_message.additional) if response else [],
        sensor="dnstap",
    )


def _parse_control_frame(payload: bytes) -> tuple[int, dict[int, list[bytes]]]:
    if len(payload) < 4:
        raise ValueError("control frame too short")
    control_type = struct.unpack("!I", payload[:4])[0]
    fields: dict[int, list[bytes]] = {}
    offset = 4
    while offset + 8 <= len(payload):
        field_type, field_len = struct.unpack("!II", payload[offset : offset + 8])
        offset += 8
        if offset + field_len > len(payload):
            raise ValueError("truncated control field")
        field_value = payload[offset : offset + field_len]
        offset += field_len
        fields.setdefault(field_type, []).append(field_value)
    return control_type, fields


def _pack_control_frame(control_type: int, content_type: bytes | None = None) -> bytes:
    payload = bytearray(struct.pack("!I", control_type))
    if content_type is not None:
        payload.extend(struct.pack("!II", FSTRM_CONTROL_FIELD_CONTENT_TYPE, len(content_type)))
        payload.extend(content_type)
    return b"".join(
        [
            struct.pack("!I", 0),
            struct.pack("!I", len(payload)),
            bytes(payload),
        ]
    )


async def _handle_connection(reader, writer, queue: asyncio.Queue[DNSEvent]) -> None:
    peer = writer.get_extra_info("peername")
    logger.info("dnstap: sender connected from %s", peer)
    started = False

    try:
        while True:
            frame_length_bytes = await reader.readexactly(4)
            frame_length = struct.unpack("!I", frame_length_bytes)[0]

            if frame_length == 0:
                control_length = struct.unpack("!I", await reader.readexactly(4))[0]
                control_payload = await reader.readexactly(control_length)
                control_type, fields = _parse_control_frame(control_payload)
                if control_type == FSTRM_CONTROL_FRAME_READY:
                    writer.write(_pack_control_frame(FSTRM_CONTROL_FRAME_ACCEPT, DNSTAP_CONTENT_TYPE))
                    await writer.drain()
                elif control_type == FSTRM_CONTROL_FRAME_START:
                    content_types = fields.get(FSTRM_CONTROL_FIELD_CONTENT_TYPE, [])
                    if content_types and DNSTAP_CONTENT_TYPE not in content_types:
                        logger.warning("dnstap: unexpected content type %r", content_types)
                    started = True
                elif control_type == FSTRM_CONTROL_FRAME_STOP:
                    writer.write(_pack_control_frame(FSTRM_CONTROL_FRAME_FINISH))
                    await writer.drain()
                    break
                elif control_type == FSTRM_CONTROL_FRAME_FINISH:
                    break
                continue

            frame_payload = await reader.readexactly(frame_length)
            if not started:
                continue

            event = _dnstap_payload_to_event(frame_payload)
            if event is None:
                continue

            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("dnstap queue full, dropping %s/%s", event.event_type, event.query_name)
    except asyncio.IncompleteReadError:
        pass
    finally:
        writer.close()
        await writer.wait_closed()
        logger.info("dnstap: sender disconnected from %s", peer)


async def ingest_events(socket_path: str = DNSTAP_SOCKET_PATH) -> AsyncGenerator[DNSEvent, None]:
    socket_dir = os.path.dirname(socket_path)
    os.makedirs(socket_dir, exist_ok=True)
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    queue: asyncio.Queue[DNSEvent] = asyncio.Queue(maxsize=10_000)
    server = await asyncio.start_unix_server(
        lambda reader, writer: _handle_connection(reader, writer, queue),
        path=socket_path,
    )
    os.chmod(socket_path, 0o666)
    logger.info("dnstap: listening on unix socket %s", socket_path)

    serve_task = asyncio.create_task(server.serve_forever())
    try:
        while True:
            yield await queue.get()
    finally:
        serve_task.cancel()
        server.close()
        await server.wait_closed()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        try:
            await serve_task
        except asyncio.CancelledError:
            pass
        logger.info("dnstap: stopped listening on unix socket %s", socket_path)
