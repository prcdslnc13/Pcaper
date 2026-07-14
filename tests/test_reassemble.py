#!/usr/bin/env python3
"""
Unit tests for the pure reassembly logic in reassemble.py.

These tests exercise TcpReassembler and parse_http_messages with synthetic
inputs only -- no pyshark/tshark required. Runs under pytest, or standalone:

    python tests/test_reassemble.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reassemble import (  # noqa: E402
    HttpMessage,
    TcpReassembler,
    TcpSegment,
    parse_http_messages,
)


def _reassemble(segments):
    """Feed segments to a fresh reassembler and return the single stream."""
    r = TcpReassembler()
    for seg in segments:
        r.add(seg)
    streams = r.streams()
    assert len(streams) == 1, f"expected 1 stream, got {len(streams)}"
    return streams[0]


def seg(seq, data, direction="c2s", **kw):
    return TcpSegment(stream=1, direction=direction, seq=seq,
                      data=data.encode() if isinstance(data, str) else data,
                      client="10.0.0.1:1000", server="10.0.0.2:80", **kw)


def test_in_order():
    s = _reassemble([seg(1, "hello "), seg(7, "world")])
    assert s.c2s == b"hello world"
    assert s.gaps["c2s"] == []


def test_out_of_order():
    # Deliver the second segment first.
    s = _reassemble([seg(7, "world"), seg(1, "hello ")])
    assert s.c2s == b"hello world"
    assert s.gaps["c2s"] == []


def test_retransmission_is_deduped():
    # Same bytes delivered twice must not be duplicated.
    s = _reassemble([seg(1, "hello "), seg(1, "hello "), seg(7, "world")])
    assert s.c2s == b"hello world"


def test_overlap_keeps_first():
    # Overlapping segment; the first-seen bytes at each offset win.
    s = _reassemble([seg(1, "ABCDE"), seg(3, "xxxYZ")])
    # offsets 0-4 = ABCDE (kept), offset 5-7 = YZ appended
    assert s.c2s == b"ABCDEYZ"


def test_gap_is_reported_and_zero_filled():
    # Bytes 1-5 present, 6-10 missing, 11-15 present.
    s = _reassemble([seg(1, "AAAAA"), seg(11, "BBBBB")])
    assert len(s.c2s) == 15
    assert s.c2s[:5] == b"AAAAA"
    assert s.c2s[5:10] == b"\x00" * 5  # zero-filled gap
    assert s.c2s[10:] == b"BBBBB"
    assert s.gaps["c2s"] == [(5, 10)]


def test_directions_are_separated():
    s = _reassemble([
        seg(1, "GET / HTTP/1.0\r\n\r\n", direction="c2s"),
        seg(1, "HTTP/1.0 200 OK\r\n\r\n", direction="s2c"),
    ])
    assert s.c2s.startswith(b"GET /")
    assert s.s2c.startswith(b"HTTP/1.0 200")


def test_multiple_streams():
    r = TcpReassembler()
    r.add(TcpSegment(1, "c2s", 1, b"one"))
    r.add(TcpSegment(2, "c2s", 1, b"two"))
    streams = r.streams()
    assert [st.stream for st in streams] == [1, 2]
    assert streams[0].c2s == b"one"
    assert streams[1].c2s == b"two"


def test_http_content_length_body():
    raw = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
    msgs = parse_http_messages(raw)
    assert len(msgs) == 1
    assert msgs[0].kind == "request"
    assert msgs[0].start_line == "POST /x HTTP/1.1"
    assert msgs[0].body == b"hello"


def test_http_chunked_body_is_decoded():
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    msgs = parse_http_messages(raw)
    assert len(msgs) == 1
    assert msgs[0].kind == "response"
    assert msgs[0].body == b"hello world"


def test_http_pipelined_messages():
    raw = (b"GET /a HTTP/1.1\r\n\r\n"
           b"GET /b HTTP/1.1\r\n\r\n")
    msgs = parse_http_messages(raw)
    assert len(msgs) == 2
    assert msgs[0].start_line == "GET /a HTTP/1.1"
    assert msgs[1].start_line == "GET /b HTTP/1.1"


def _run_standalone():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
