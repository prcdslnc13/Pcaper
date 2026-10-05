#!/usr/bin/env python3
"""
aliencell.py - decode Aliencell X1 (Aliencell Studio) ZeroMQ traffic from a USB capture.

The X1 exposes a network link over USB (MBIM/Ethernet). On it the host talks
ZeroMQ: TCP 6688 is the REQ/ROUTER command channel, TCP 6699 the PUB/SUB
telemetry channel. Message bodies use a private length-prefixed encoding
(not msgpack):

    u16 name_len, name                      # empty on replies, then one extra u16 0
    struct := u16 count, count * ( u16 key_len, key, u16 val_len, val )
    val    := bool (1 byte) | int32 LE (4) | double LE (8)
            | u16-prefixed utf-8 string | nested struct
    keys are prefixed "d." (stripped in the output)

Usage:
    python aliencell.py capture.pcapng            # command/reply/event timeline
    python aliencell.py capture.pcapng --focus    # only what relates to the focus plane / Z
    python aliencell.py capture.pcapng --all      # include every RealtimeData telemetry message
    python aliencell.py capture.pcapng --json     # one JSON object per line

Requires tshark (Wireshark CLI).
"""
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys

CMD_PORT = 6688
PUB_PORT = 6699
FIELDS = ["frame.number", "frame.time_relative", "ip.src", "tcp.srcport",
          "tcp.dstport", "tcp.stream", "tcp.seq", "tcp.payload"]
# fields whose 4-byte value is a float32, not an int32
FLOAT32_KEYS = {"focus_distance"}
# fields whose 8-byte value is an int64, not a double
INT64_KEYS = {"task_exec_seconds", "estimatedTime", "dev_usage_time_s"}


# --------------------------------------------------------------------------- tshark
def find_tshark():
    exe = shutil.which("tshark")
    if exe:
        return exe
    for p in (r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe",
              "/Applications/Wireshark.app/Contents/MacOS/tshark",
              "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"):
        if os.path.exists(p):
            return p
    sys.exit("tshark not found (install Wireshark or add it to PATH)")


def tcp_segments(pcap):
    """Yield one dict per TCP segment with payload on the ZeroMQ ports."""
    cmd = [find_tshark(), "-r", pcap, "-Y",
           f"(tcp.port=={CMD_PORT} || tcp.port=={PUB_PORT}) && tcp.len>0",
           "-T", "fields", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(out.stderr.strip() or "tshark failed")
    for line in out.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < len(FIELDS):
            continue
        fn, t = int(cols[0]), float(cols[1])
        # one USB frame can carry several TCP segments; tshark comma-joins them
        parts = [c.split(",") for c in cols[2:]]
        n = max(len(p) for p in parts)
        for i in range(n):
            src, sp, dp, st, seq, pl = (p[i] if i < len(p) else p[-1] for p in parts)
            if not pl:
                continue
            yield dict(frame=fn, t=t, src=src, sport=int(sp), dport=int(dp),
                       stream=int(st), seq=int(seq), data=bytes.fromhex(pl))


# --------------------------------------------------------------------------- TCP
def reassemble(segs):
    """-> {(stream, direction): (bytes, [(offset, time, frame)])}"""
    by_key = {}
    for r in segs:
        direction = "c2s" if r["dport"] in (CMD_PORT, PUB_PORT) else "s2c"
        by_key.setdefault((r["stream"], direction), []).append(r)
    res = {}
    for key, lst in by_key.items():
        lst.sort(key=lambda r: (r["seq"], r["frame"]))
        buf = bytearray()
        marks = []
        expect = None
        for r in lst:
            if expect is None:
                expect = r["seq"]
            d = r["data"]
            if r["seq"] < expect:                      # retransmission / overlap
                skip = expect - r["seq"]
                if skip >= len(d):
                    continue
                d = d[skip:]
            elif r["seq"] > expect:                    # loss: pad, keep going
                buf += b"\0" * (r["seq"] - expect)
            marks.append((len(buf), r["t"], r["frame"]))
            buf += d
            expect = r["seq"] + len(r["data"])
        res[key] = (bytes(buf), marks)
    return res


def time_at(marks, off):
    t = f = None
    for o, tt, ff in marks:
        if o <= off:
            t, f = tt, ff
        else:
            break
    return t, f


# --------------------------------------------------------------------------- ZMTP
def zmtp_messages(buf):
    """Yield (offset, last_frame_body) per ZMTP/3 message. Skips greeting + command frames."""
    i = 0
    k = buf.find(b"\x05READY", 0, 400)
    if k >= 2:
        i = k - 2                      # the greeting bytes precede the READY command frame
    frames = []
    start = None
    while i + 2 <= len(buf):
        flags = buf[i]
        if flags & 2:                  # long frame
            if i + 9 > len(buf):
                break
            size = struct.unpack(">Q", buf[i + 1:i + 9])[0]
            body, nxt = buf[i + 9:i + 9 + size], i + 9 + size
        else:
            size = buf[i + 1]
            body, nxt = buf[i + 2:i + 2 + size], i + 2 + size
        if nxt > len(buf):
            break
        if flags & 4:                  # command frame
            i = nxt
            continue
        if start is None:
            start = i
        frames.append(body)
        if not flags & 1:              # last frame of the message
            yield start, frames[-1]
            frames, start = [], None
        i = nxt


# --------------------------------------------------------------------------- body
def _string(b):
    if len(b) >= 2 and struct.unpack("<H", b[:2])[0] == len(b) - 2:
        try:
            s = b[2:].decode("utf-8")
            if all(c.isprintable() or c in "\r\n\t" for c in s):
                return s
        except UnicodeDecodeError:
            pass
    return None


def _string_list(b):
    """u16 count, then count * (u16 len, utf-8 bytes) - e.g. support_ftype=["al"]."""
    if len(b) < 2:
        return None
    cnt = struct.unpack("<H", b[:2])[0]
    i, out = 2, []
    for _ in range(cnt):
        if i + 2 > len(b):
            return None
        n = struct.unpack("<H", b[i:i + 2])[0]
        s = _string(b[i:i + 2 + n])
        if s is None:
            return None
        out.append(s)
        i += 2 + n
    return out if i == len(b) else None


def parse_value(b, key=""):
    n = len(b)
    if n == 1:
        return bool(b[0]) if b[0] in (0, 1) else b[0]
    s = _string(b)
    if s is not None and (n not in (4, 8) or not s.isdigit()):
        return s
    if n == 4:
        if key in FLOAT32_KEYS:
            return struct.unpack("<f", b)[0]
        return struct.unpack("<i", b)[0]
    if n == 8:
        if key in INT64_KEYS:
            return struct.unpack("<q", b)[0]
        return struct.unpack("<d", b)[0]
    st = parse_struct(b)
    if st is not None:
        return st
    lst = _string_list(b)
    if lst is not None:
        return lst
    return b.hex()


def parse_struct(b):
    if len(b) < 2:
        return None
    cnt = struct.unpack("<H", b[:2])[0]
    i, out = 2, {}
    for _ in range(cnt):
        if i + 2 > len(b):
            return None
        kl = struct.unpack("<H", b[i:i + 2])[0]
        i += 2
        key = b[i:i + kl]
        i += kl
        if i + 2 > len(b):
            return None
        vl = struct.unpack("<H", b[i:i + 2])[0]
        i += 2
        val = b[i:i + vl]
        i += vl
        if i > len(b):
            return None
        try:
            k = key.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not k.isprintable():
            return None
        if k.startswith("d."):
            k = k[2:]
        out[k] = parse_value(val, k)
    return out if i == len(b) else None


def parse_body(b):
    if len(b) < 2:
        return None, None
    nl = struct.unpack("<H", b[:2])[0]
    name = b[2:2 + nl].decode("ascii", "replace")
    st = parse_struct(b[2 + nl:])
    if st is None and b[2 + nl:4 + nl] == b"\x00\x00":
        st = parse_struct(b[4 + nl:])            # reply: empty name, extra u16 0
    return (name or "(reply)"), st


# --------------------------------------------------------------------------- decode
def decode(pcap):
    """-> sorted list of dicts: t, frame, stream, port, direction, name, body."""
    rows = []
    for (stream, direction), (buf, marks) in reassemble(tcp_segments(pcap)).items():
        port = None
        for off, body in zmtp_messages(buf):
            if not body:
                continue
            name, st = parse_body(body)
            if name is None:
                continue
            t, f = time_at(marks, off)
            rows.append(dict(t=t, frame=f, stream=stream, direction=direction,
                             name=name, body=st if st is not None else body[:64].hex()))
    rows.sort(key=lambda r: (r["t"], r["frame"]))
    # tag each row with the port it belongs to: streams carrying RealtimeData are PUB
    pub_streams = {r["stream"] for r in rows if r["name"] in ("RealtimeData", "Status", "Events")}
    for r in rows:
        r["port"] = PUB_PORT if r["stream"] in pub_streams else CMD_PORT
    return rows


def pair_replies(rows):
    """Attach each (reply) to the request with the same req_id."""
    pending = {}
    for r in rows:
        base = r["body"].get("base", {}) if isinstance(r["body"], dict) else {}
        rid = base.get("req_id")
        if r["name"] == "(reply)" and rid in pending:
            req = pending.pop(rid)
            req["reply"] = r
            req["reply_ms"] = (r["t"] - req["t"]) * 1000
            r["skip"] = True
        elif r["port"] == CMD_PORT and r["direction"] == "c2s" and rid:
            pending[rid] = r


def diff(old, new, path=""):
    out = {}
    for k in sorted(set(old) | set(new)):
        a, b = old.get(k), new.get(k)
        if isinstance(a, dict) and isinstance(b, dict):
            out.update(diff(a, b, f"{path}{k}."))
        elif a != b:
            out[f"{path}{k}"] = b
    return out


# --------------------------------------------------------------------------- output
def fmt(v):
    if isinstance(v, float):
        return f"{v:.4g}" if abs(v) < 1e6 else f"{v:.3e}"
    return json.dumps(v, ensure_ascii=False)


def brief(d, limit=400):
    if not isinstance(d, dict):
        return str(d)
    s = ", ".join(f"{k}={fmt(v)}" for k, v in d.items() if k != "base")
    return s if len(s) <= limit else s[:limit] + " ..."


def print_timeline(rows, show_all=False, focus_only=False):
    last_status = None
    for r in rows:
        if r.get("skip"):
            continue
        name, body = r["name"], r["body"]
        if name == "RealtimeData" and not show_all:
            continue
        if focus_only and name not in ("AutoFocus", "ExecFile", "Status", "RealtimeData",
                                       "TaskDetailInfo", "CancelReadyTask", "StartTask"):
            continue
        line = f"[{r['t']:9.3f}s f{r['frame']:<6} {'HOST>DEV' if r['direction']=='c2s' else 'DEV>HOST'} :{r['port']}] {name}"
        if name == "Status" and isinstance(body, dict):
            if last_status is not None:
                d = diff(last_status, body)
                if not d:
                    continue
                if focus_only:
                    d = {k: v for k, v in d.items() if any(w in k for w in ("state", "focus", "probe", "button"))}
                    if not d:
                        continue
                print(f"{line}  changed: {brief(d)}")
            else:
                print(f"{line}  {brief(body)}")
            last_status = body
            continue
        if name == "RealtimeData" and isinstance(body, dict):
            pos = body.get("pos", {})
            print(f"{line}  x={fmt(pos.get('x'))} y={fmt(pos.get('y'))} z={fmt(pos.get('z'))} "
                  f"exec_s={body.get('task_exec_seconds')}")
            continue
        print(f"{line}  {brief(body)}")
        rep = r.get("reply")
        if rep is not None:
            rb = rep["body"] if isinstance(rep["body"], dict) else {}
            base = rb.get("base", {})
            extra = brief({k: v for k, v in rb.items() if k != "base"}, 300)
            print(f"{'':>34}-> reply {r['reply_ms']:.0f} ms err_code={base.get('err_code')} "
                  f"err_msg={fmt(base.get('err_msg'))}{'  ' + extra if extra else ''}")


def print_focus_summary(rows):
    print("\n=== Focus-plane summary ===")
    focus = [r for r in rows if r["name"] == "AutoFocus"]
    execs = [r for r in rows if r["name"] == "ExecFile"]
    dists, last = [], None
    zs, lastz = [], None
    for r in rows:
        b = r["body"] if isinstance(r["body"], dict) else {}
        if r["name"] == "Status":
            d = b.get("focus_module", {}).get("focus_distance")
            if d is not None and d != last:
                dists.append((r["t"], d))
                last = d
        elif r["name"] == "RealtimeData":
            z = b.get("pos", {}).get("z")
            if z is not None and z != lastz:
                zs.append((r["t"], z))
                lastz = z
    for r in focus:
        b = r["body"]
        print(f"AutoFocus at {r['t']:.3f}s: type={b.get('type')} mode={b.get('mode')} "
              f"focus_x={b.get('focus_x')} focus_y={b.get('focus_y')} need_update_photo={b.get('need_update_photo')}")
    for t, d in dists:
        print(f"Status.focus_module.focus_distance -> {d:.4f} at {t:.3f}s" + ("  (not measured)" if d == -1000 else ""))
    for r in execs:
        b = r["body"]
        print(f"ExecFile at {r['t']:.3f}s: path={b.get('path')} start_z_type={b.get('start_z_type')} "
              f"start_z={b.get('start_z')} start_xy_type={b.get('start_xy_type')} "
              f"start_x={b.get('start_x')} start_y={b.get('start_y')}")
        measured = [d for _, d in dists if d != -1000]
        if measured:
            delta = b.get("start_z", 0) - measured[-1]
            print(f"   start_z - last measured focus_distance = {delta:+.4f} mm")
    if zs:
        print(f"telemetry pos.z took {len(zs)} distinct value(s): " +
              ", ".join(f"{z:.3f}@{t:.1f}s" for t, z in zs[:12]))
    if not (focus or execs):
        print("no AutoFocus / ExecFile request in this capture")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--all", action="store_true", help="include every RealtimeData telemetry message")
    ap.add_argument("--focus", action="store_true", help="only focus/Z related messages plus a summary")
    ap.add_argument("--json", action="store_true", help="emit one JSON object per message instead")
    a = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    rows = decode(a.pcap)
    if not rows:
        sys.exit("no ZeroMQ traffic on ports 6688/6699 found (is this an Aliencell capture with network-over-USB?)")
    if a.json:
        for r in rows:
            print(json.dumps(r, ensure_ascii=False, default=str))
        return
    pair_replies(rows)
    print_timeline(rows, show_all=a.all, focus_only=a.focus)
    print_focus_summary(rows)


if __name__ == "__main__":
    main()
