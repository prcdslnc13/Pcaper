#!/usr/bin/env python3
"""
TCP stream reassembly and HTTP object extraction for pcaper.

Two complementary capabilities:

1. Generic TCP stream reassembly (``TcpReassembler``): orders per-connection
   segments by sequence number, drops retransmissions/overlaps, records gaps,
   and produces the full client->server and server->client byte streams. This
   works for any TCP-over-USB traffic, including protocols pcaper does not
   otherwise understand (e.g. ZeroMQ).

2. HTTP object extraction (``extract_http_objects``): tshark already reassembles
   and de-chunks HTTP bodies into the ``http.file_data`` field, so recovering
   complete files (camera photos, previews, uploads) is a matter of reading that
   field and naming it from the request URI / content type.

The pure pieces (``TcpReassembler``, ``parse_http_messages``) have no third-party
dependencies; pyshark is imported lazily only by the capture-reading helpers.
"""

from dataclasses import dataclass, field
from typing import Dict, Generator, List, Tuple

__all__ = [
    "TcpSegment",
    "ReassembledStream",
    "TcpReassembler",
    "HttpMessage",
    "parse_http_messages",
    "HttpObject",
    "iter_tcp_segments",
    "reassemble_streams",
    "extract_http_objects",
]


# ---------------------------------------------------------------------------
# Interval helpers (used to place out-of-order/overlapping segments and to
# report gaps in the reassembled stream).
# ---------------------------------------------------------------------------

Interval = Tuple[int, int]


def _merge(intervals: List[Interval]) -> List[Interval]:
    """Merge overlapping/adjacent [start, end) intervals; returns sorted list."""
    if not intervals:
        return []
    ordered = sorted(intervals)
    out = [list(ordered[0])]
    for start, end in ordered[1:]:
        if start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [(s, e) for s, e in out]


def _subtract(start: int, end: int, covered: List[Interval]) -> List[Interval]:
    """Return the parts of [start, end) not present in ``covered``.

    ``covered`` must be a sorted, merged list of intervals.
    """
    result: List[Interval] = []
    cur = start
    for cov_start, cov_end in covered:
        if cov_end <= cur:
            continue
        if cov_start >= end:
            break
        if cov_start > cur:
            result.append((cur, min(cov_start, end)))
        cur = max(cur, cov_end)
        if cur >= end:
            break
    if cur < end:
        result.append((cur, end))
    return result


# ---------------------------------------------------------------------------
# TCP reassembly
# ---------------------------------------------------------------------------

@dataclass
class TcpSegment:
    """A single TCP segment carrying payload, with a relative sequence number.

    ``seq`` is the relative sequence number (first byte of the stream = 1, as
    reported by tshark), so the byte offset into the stream is ``seq - 1``.
    ``direction`` is ``"c2s"`` (client->server) or ``"s2c"`` (server->client).
    """
    stream: int
    direction: str
    seq: int
    data: bytes
    timestamp: float = 0.0
    client: str = ""
    server: str = ""


@dataclass
class ReassembledStream:
    """A fully reassembled TCP connection (both directions)."""
    stream: int
    client: str
    server: str
    c2s: bytes
    s2c: bytes
    gaps: Dict[str, List[Interval]] = field(default_factory=dict)
    start_ts: float = 0.0
    end_ts: float = 0.0

    def data(self, direction: str) -> bytes:
        """Return the reassembled bytes for ``"c2s"`` or ``"s2c"``."""
        return self.c2s if direction == "c2s" else self.s2c


class TcpReassembler:
    """Accumulates TCP segments and reassembles them into ordered streams.

    Segments may arrive out of order, be retransmitted, or overlap; the first
    bytes seen for a given offset win (keep-first), later duplicates are ignored.
    Missing ranges are zero-filled in the output but reported in ``gaps`` so they
    are never silently hidden.
    """

    def __init__(self) -> None:
        self._streams: Dict[int, dict] = {}

    def add(self, seg: TcpSegment) -> None:
        st = self._streams.setdefault(
            seg.stream,
            {
                "client": "",
                "server": "",
                "frags": {"c2s": [], "s2c": []},
                "start_ts": 0.0,
                "end_ts": 0.0,
            },
        )
        if not st["client"] and seg.client:
            st["client"] = seg.client
        if not st["server"] and seg.server:
            st["server"] = seg.server
        if seg.timestamp:
            if st["start_ts"] == 0.0 or seg.timestamp < st["start_ts"]:
                st["start_ts"] = seg.timestamp
            if seg.timestamp > st["end_ts"]:
                st["end_ts"] = seg.timestamp
        if seg.data and seg.direction in st["frags"]:
            offset = max(seg.seq - 1, 0)
            st["frags"][seg.direction].append((offset, seg.data))

    @staticmethod
    def _assemble(frags: List[Tuple[int, bytes]]) -> Tuple[bytes, List[Interval]]:
        if not frags:
            return b"", []
        total = max(off + len(data) for off, data in frags)
        buf = bytearray(total)
        covered: List[Interval] = []
        # Preserve insertion order so the earliest-seen bytes win on overlap.
        for off, data in frags:
            end = off + len(data)
            for seg_start, seg_end in _subtract(off, end, covered):
                buf[seg_start:seg_end] = data[seg_start - off:seg_end - off]
            covered = _merge(covered + [(off, end)])
        gaps = _subtract(0, total, covered)
        return bytes(buf), gaps

    def streams(self) -> List[ReassembledStream]:
        result: List[ReassembledStream] = []
        for stream_id in sorted(self._streams):
            st = self._streams[stream_id]
            c2s, c2s_gaps = self._assemble(st["frags"]["c2s"])
            s2c, s2c_gaps = self._assemble(st["frags"]["s2c"])
            result.append(
                ReassembledStream(
                    stream=stream_id,
                    client=st["client"],
                    server=st["server"],
                    c2s=c2s,
                    s2c=s2c,
                    gaps={"c2s": c2s_gaps, "s2c": s2c_gaps},
                    start_ts=st["start_ts"],
                    end_ts=st["end_ts"],
                )
            )
        return result


# ---------------------------------------------------------------------------
# Minimal HTTP/1.x message parsing over a reassembled byte stream
# ---------------------------------------------------------------------------

@dataclass
class HttpMessage:
    kind: str            # "request" or "response"
    start_line: str
    headers: Dict[str, str]
    body: bytes


def _read_chunked(data: bytes, pos: int) -> Tuple[bytes, int]:
    """Decode a chunked body starting at ``pos``; return (body, next_pos)."""
    out = bytearray()
    while pos < len(data):
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            break
        size_token = data[pos:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            break
        pos = line_end + 2
        if size == 0:
            # Skip optional trailer headers up to the terminating blank line.
            trailer_end = data.find(b"\r\n", pos)
            pos = trailer_end + 2 if trailer_end != -1 else len(data)
            break
        out += data[pos:pos + size]
        pos += size + 2  # payload + trailing CRLF
    return bytes(out), pos


def parse_http_messages(data: bytes) -> List[HttpMessage]:
    """Parse consecutive HTTP/1.x messages from a reassembled stream buffer.

    Handles ``Content-Length`` and ``Transfer-Encoding: chunked`` bodies and
    keep-alive pipelining (multiple messages back-to-back in one direction).
    """
    messages: List[HttpMessage] = []
    pos = 0
    while pos < len(data):
        header_end = data.find(b"\r\n\r\n", pos)
        if header_end == -1:
            break
        head = data[pos:header_end].decode("latin-1")
        lines = head.split("\r\n")
        start_line = lines[0].strip()
        if not start_line:
            break
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        body_start = header_end + 4
        kind = "response" if start_line.upper().startswith("HTTP/") else "request"

        if "chunked" in headers.get("transfer-encoding", "").lower():
            body, next_pos = _read_chunked(data, body_start)
        elif "content-length" in headers:
            try:
                length = int(headers["content-length"])
            except ValueError:
                length = 0
            body = data[body_start:body_start + length]
            next_pos = body_start + length
        elif kind == "request":
            body, next_pos = b"", body_start
        else:
            body, next_pos = data[body_start:], len(data)

        messages.append(HttpMessage(kind, start_line, headers, body))
        if next_pos <= pos:
            break
        pos = next_pos
    return messages


# ---------------------------------------------------------------------------
# HTTP object extraction
# ---------------------------------------------------------------------------

@dataclass
class HttpObject:
    index: int
    filename: str
    uri: str
    kind: str            # "response" (download) or "request" (upload)
    content_type: str
    size: int
    stream: int
    md5: str
    data: bytes


_EXT_BY_TYPE = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/bmp": ".bmp",
    "application/json": ".json",
    "text/html": ".html",
    "text/plain": ".txt",
    "application/octet-stream": ".bin",
}


def _object_filename(uri: str, ctype: str, kind: str, idx: int,
                     used: set) -> str:
    import posixpath

    base = posixpath.basename(uri.split("?", 1)[0]) if uri else ""
    if not base:
        base = f"object_{idx}"

    root, ext = posixpath.splitext(base)
    if not ext:
        ext = _EXT_BY_TYPE.get(ctype.split(";", 1)[0].strip().lower(), ".bin")
        root, base = base, base + ext

    if kind == "request":
        root, ext = posixpath.splitext(base)
        base = f"{root}.request{ext}"

    candidate = base
    n = 2
    while candidate in used:
        root, ext = posixpath.splitext(base)
        candidate = f"{root}_{n}{ext}"
        n += 1
    return candidate


# ---------------------------------------------------------------------------
# Capture readers (pyshark imported lazily so the pure logic above stays
# dependency-free and unit-testable).
# ---------------------------------------------------------------------------

def _truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def iter_tcp_segments(pcap_path: str) -> Generator[TcpSegment, None, None]:
    """Yield payload-bearing TCP segments from a capture, direction-tagged.

    The connection initiator (SYN sender) is treated as the client; if no SYN is
    observed, the first side seen sending data is assumed to be the client.
    """
    import pyshark
    from pcaper import ensure_event_loop, hex_to_bytes

    ensure_event_loop()
    cap = pyshark.FileCapture(pcap_path, display_filter="tcp")
    client_of: Dict[int, str] = {}
    try:
        for packet in cap:
            timestamp = float(getattr(packet, "sniff_timestamp", 0) or 0)

            # A single USB/MBIM transfer can aggregate several Ethernet frames,
            # so one packet may contain multiple ip/tcp layers. Walk them in
            # order, pairing each tcp layer with the most recent ip layer.
            cur_src_ip = "?"
            cur_dst_ip = "?"
            for layer in packet.layers:
                name = layer.layer_name
                if name in ("ip", "ipv6"):
                    cur_src_ip = getattr(layer, "src", "?")
                    cur_dst_ip = getattr(layer, "dst", "?")
                    continue
                if name != "tcp":
                    continue

                tcp = layer
                try:
                    stream = int(tcp.stream)
                except (AttributeError, ValueError):
                    continue

                src = f"{cur_src_ip}:{getattr(tcp, 'srcport', '?')}"
                dst = f"{cur_dst_ip}:{getattr(tcp, 'dstport', '?')}"

                if _truthy(getattr(tcp, "flags_syn", "")) and \
                        not _truthy(getattr(tcp, "flags_ack", "")):
                    client_of[stream] = src

                payload = getattr(tcp, "payload", None)
                if not payload:
                    continue

                client_of.setdefault(stream, src)
                client = client_of[stream]
                direction = "c2s" if src == client else "s2c"
                server = dst if src == client else src

                try:
                    seq = int(getattr(tcp, "seq"))
                    data = hex_to_bytes(str(payload))
                except (AttributeError, ValueError):
                    continue

                yield TcpSegment(stream, direction, seq, data, timestamp,
                                 client, server)
    finally:
        cap.close()


def reassemble_streams(pcap_path: str) -> List[ReassembledStream]:
    """Read a capture and return all reassembled TCP streams."""
    reassembler = TcpReassembler()
    for segment in iter_tcp_segments(pcap_path):
        reassembler.add(segment)
    return reassembler.streams()


def extract_http_objects(pcap_path: str) -> List[HttpObject]:
    """Extract complete HTTP bodies (files) carried in the capture.

    Relies on tshark's reassembled, de-chunked ``http.file_data`` field, so each
    returned object is a whole file regardless of how many TCP segments it spanned.
    """
    import hashlib
    import pyshark
    from pcaper import ensure_event_loop, hex_to_bytes

    ensure_event_loop()
    cap = pyshark.FileCapture(pcap_path, display_filter="http.file_data")
    objects: List[HttpObject] = []
    used: set = set()
    idx = 0
    try:
        for packet in cap:
            http = getattr(packet, "http", None)
            if http is None:
                continue
            file_data = getattr(http, "file_data", None)
            if not file_data:
                continue
            try:
                data = hex_to_bytes(str(file_data))
            except ValueError:
                continue
            if not data:
                continue

            uri = str(getattr(http, "request_uri", "") or "")
            method = getattr(http, "request_method", None)
            kind = "request" if method else "response"
            ctype = str(getattr(http, "content_type", "") or "")
            try:
                stream = int(packet.tcp.stream)
            except (AttributeError, ValueError):
                stream = -1

            idx += 1
            filename = _object_filename(uri, ctype, kind, idx, used)
            used.add(filename)
            objects.append(
                HttpObject(
                    index=idx,
                    filename=filename,
                    uri=uri,
                    kind=kind,
                    content_type=ctype.split(";", 1)[0].strip(),
                    size=len(data),
                    stream=stream,
                    md5=hashlib.md5(data).hexdigest(),
                    data=data,
                )
            )
    finally:
        cap.close()
    return objects
