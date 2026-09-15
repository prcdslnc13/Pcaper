#!/usr/bin/env python3
"""
urbtrace - URB-level timeline for USB serial (CDC and FTDI) captures.

Where ``pcaper.py`` answers "what bytes crossed the link", this answers
"what did the USB stack actually do, and when". It pairs every URB submit with
its completion so you can tell a write that never completed from a read that was
never issued -- the distinction that payload extraction cannot make.

Built for diagnosing host-side serial stalls: an application that stops talking
to a device looks identical at the payload layer whether it blocked in write(),
blocked in read(), or simply stopped being scheduled. At the URB layer the three
look completely different:

  * blocked in write   -> OUT URB submitted, never completed (an "orphan")
  * blocked in read    -> OUT URB completed normally, IN URBs stop being submitted
  * data never arrived -> IN URBs submitted and pending, no completion with data

Usage:
    python urbtrace.py capture.pcapng
    python urbtrace.py capture.pcapng --vidpid 0483:5740     # STM32 VCP (CDC)
    python urbtrace.py capture.pcapng --vidpid 0403:6001     # FTDI FT232
    python urbtrace.py capture.pcapng --verdict '$J='
    python urbtrace.py capture.pcapng -f tsv -o urbs.tsv
"""

import argparse
import bisect
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

__version__ = "0.2.0"

# usb.irp_info.direction
SUBMIT = 0x00
COMPLETE = 0x01

# usb.transfer_type
XFER = {0x00: "ISO", 0x01: "INTR", 0x02: "CTRL", 0x03: "BULK"}

# A short bulk OUT on a CDC device completes in single-digit milliseconds; past
# this, the host was waiting on something rather than transferring.
SLOW_WRITE_MS = 50.0

# An orphaned submit is called stuck once it has been outstanding for this many
# times the endpoint's median completion latency. The floor keeps very fast
# endpoints (sub-millisecond turnaround) from flagging ordinary scheduling jitter.
PENDING_TOLERANCE = 10.0
PENDING_FLOOR_S = 1.0

# usb.usbd_status values worth naming; anything else is shown as raw hex.
USBD_STATUS = {
    0x00000000: "SUCCESS",
    0xC0000004: "CANCELED",
    0xC0000011: "DEV_NOT_RESPONDING",
    0xC0000030: "STALL_PID",
    0xC0007000: "TIMEOUT",
    0x80000300: "ERROR_SHORT_TRANSFER",
}

BASE_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "usb.irp_id",
    "usb.irp_info.direction",
    "usb.function",
    "usb.transfer_type",
    "usb.endpoint_address",
    "usb.endpoint_address.direction",
    "usb.device_address",
    "usb.usbd_status",
    "usb.data_len",
    "usb.time",
]

# Where the serial bytes live, most specific first. The protocol dissectors
# strip framing that the raw leftover data keeps: an FTDI IN transfer leads with
# two modem/line-status bytes, and the driver polls constantly, so on usb.capdata
# alone every read would look like data. The dissectors only engage when the
# device descriptors are in the capture (USBPcap's "inject descriptors").
PAYLOAD_FIELDS = [
    "usbcom.data.in_payload",
    "usbcom.data.out_payload",
    "ftdi-ft.if_a_rx_payload",
    "ftdi-ft.if_a_tx_payload",
    "ftdi-ft.if_b_rx_payload",
    "ftdi-ft.if_b_tx_payload",
    "ftdi-ft.if_c_rx_payload",
    "ftdi-ft.if_c_tx_payload",
    "ftdi-ft.if_d_rx_payload",
    "ftdi-ft.if_d_tx_payload",
    "usb.capdata",
]

FIELDS = BASE_FIELDS + PAYLOAD_FIELDS


@dataclass
class Urb:
    """One URB event (a submit or a completion) from the capture."""
    frame: int
    epoch: float
    irp: str
    info_dir: int
    function: int
    xfer: int
    endpoint: int
    ep_dir: int          # 1 = IN (device->host), 0 = OUT (host->device)
    address: str
    status: Optional[int]
    data_len: int
    latency: Optional[float]
    payload: bytes

    # Filled in during pairing.
    completed_by: Optional["Urb"] = field(default=None, repr=False)

    @property
    def is_submit(self) -> bool:
        return self.info_dir == SUBMIT

    @property
    def direction(self) -> str:
        return "IN" if self.ep_dir == 1 else "OUT"

    @property
    def kind(self) -> str:
        return XFER.get(self.xfer, f"0x{self.xfer:02x}")

    @property
    def status_name(self) -> str:
        if self.status is None:
            return ""
        return USBD_STATUS.get(self.status, f"0x{self.status:08x}")

    @property
    def clock(self) -> str:
        """Local wall clock, formatted to match a typical app debug log."""
        return datetime.fromtimestamp(self.epoch).strftime("%H:%M:%S.%f")[:-3]


def check_tshark() -> str:
    """Locate tshark, preferring PATH but falling back to the Windows default."""
    found = shutil.which("tshark")
    if found:
        return found
    fallback = r"C:\Program Files\Wireshark\tshark.exe"
    try:
        if subprocess.run([fallback, "--version"], capture_output=True).returncode == 0:
            return fallback
    except OSError:
        pass
    print(
        "Error: tshark not found. Install Wireshark, or add it to PATH:\n"
        r"  Windows default: C:\Program Files\Wireshark",
        file=sys.stderr,
    )
    sys.exit(1)


def _hexfield(value: str) -> bytes:
    """Decode a tshark hex field, which may be colon-separated or bare."""
    clean = value.replace(":", "").replace(" ", "")
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return b""


def _int(value: str) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def resolve_address(tshark: str, pcap: str, vidpid: str) -> Optional[str]:
    """
    Find the USB device address for a VID:PID.

    USBPcap captures an entire root hub, so a capture normally contains several
    unrelated devices. Device descriptors carry the VID/PID, and USBPcap's
    ``--inject-descriptors`` replays them for already-connected devices, so this
    works whether or not the capture began before the device was plugged in.
    """
    try:
        vid, pid = (int(part, 16) for part in vidpid.split(":", 1))
    except ValueError:
        print(f"Error: --vidpid expects VID:PID hex, got {vidpid!r}", file=sys.stderr)
        sys.exit(2)

    out = subprocess.run(
        [tshark, "-r", pcap,
         "-Y", f"usb.idVendor == {vid} && usb.idProduct == {pid}",
         "-T", "fields", "-e", "usb.device_address"],
        capture_output=True, text=True,
    ).stdout

    addresses = [line.strip() for line in out.splitlines() if line.strip()]
    if not addresses:
        return None
    # Later enumerations win: a replug reassigns the address.
    return addresses[-1]


def read_urbs(tshark: str, pcap: str, address: Optional[str]) -> list[Urb]:
    """Extract every URB event for one device (or all devices if address is None)."""
    cmd = [tshark, "-r", pcap, "-T", "fields"]
    if address:
        cmd += ["-Y", f"usb.device_address == {address}"]
    for name in FIELDS:
        cmd += ["-e", name]
    # Keep multi-value fields on one line so column counts stay stable.
    cmd += ["-E", "separator=\t", "-E", "occurrence=f"]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"Error: tshark failed:\n{proc.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    urbs: list[Urb] = []
    for line in proc.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < len(FIELDS):
            cols += [""] * (len(FIELDS) - len(cols))
        (frame, epoch, irp, info_dir, func, xfer, ep, ep_dir,
         addr, status, dlen, utime) = cols[:len(BASE_FIELDS)]
        payload_cols = cols[len(BASE_FIELDS):len(FIELDS)]

        if not irp:
            continue  # not a URB-bearing frame

        payload = b""
        for candidate in payload_cols:
            if candidate:
                payload = _hexfield(candidate)
                break

        urbs.append(Urb(
            frame=_int(frame) or 0,
            epoch=float(epoch) if epoch else 0.0,
            irp=irp,
            info_dir=_int(info_dir) or 0,
            function=_int(func) or 0,
            xfer=_int(xfer) if _int(xfer) is not None else -1,
            endpoint=_int(ep) or 0,
            ep_dir=_int(ep_dir) or 0,
            address=addr,
            status=_int(status),
            data_len=_int(dlen) or 0,
            latency=float(utime) if utime else None,
            payload=payload,
        ))
    return urbs


def pair(urbs: list[Urb]) -> tuple[list[Urb], list[Urb]]:
    """
    Match each submit to its completion.

    IRP ids are pointers and get recycled, so a naive dict keyed on the id alone
    would mis-pair a later URB with an earlier orphan. Matching each completion
    to the most recent unmatched submit of the same id keeps reuse honest.

    Returns (all events in order, orphaned submits).
    """
    pending: dict[str, list[Urb]] = {}
    for urb in urbs:
        if urb.is_submit:
            pending.setdefault(urb.irp, []).append(urb)
        else:
            queue = pending.get(urb.irp)
            if queue:
                submit = queue.pop()
                submit.completed_by = urb
    orphans = [u for queue in pending.values() for u in queue]
    orphans.sort(key=lambda u: u.epoch)
    return urbs, orphans


def classify_orphans(
    orphans: list[Urb], urbs: list[Urb]
) -> tuple[list[Urb], list[Urb]]:
    """
    Split orphaned submits into genuinely stuck transfers and expected ones.

    Not every submit without a completion is a stall, and treating them alike
    buries the signal:

      * A CDC-ACM interrupt IN endpoint (the serial-state notification) is
        submitted once and sits pending until the device has something to say,
        so it is orphaned for the whole capture by design.
      * Drivers keep a rotating pool of reads outstanding -- typically the same
        IRP structures resubmitted the instant they complete -- so at capture
        stop there is always a tail of pending submits whose completions simply
        happened after we stopped looking.

    Neither a fixed time window nor an "was it overtaken" test separates those
    reliably: the window has to guess the pool depth, and pooled IRPs complete
    out of order with respect to each other, so later completions on the same
    endpoint are normal.

    What does work is comparing against the endpoint's own behaviour. Measure how
    long completions on that endpoint normally take, then ask how long this URB
    had been outstanding when the capture ended. A read pending for less than the
    endpoint's usual turnaround is simply in flight; one pending for orders of
    magnitude longer is stuck.

    Returns (blocked, benign).
    """
    capture_end = max(u.epoch for u in urbs) if urbs else 0.0

    # Observed completion latency per endpoint, from successfully paired URBs.
    latencies: dict[int, list[float]] = {}
    for urb in urbs:
        if urb.is_submit and urb.completed_by is not None:
            latencies.setdefault(urb.endpoint, []).append(
                urb.completed_by.epoch - urb.epoch
            )

    def threshold(endpoint: int) -> float:
        """How long is too long to still be pending on this endpoint, in seconds."""
        samples = sorted(latencies.get(endpoint, []))
        if not samples:
            return PENDING_FLOOR_S
        median = samples[len(samples) // 2]
        return max(median * PENDING_TOLERANCE, PENDING_FLOOR_S)

    blocked, benign = [], []
    for urb in orphans:
        if urb.xfer == 0x01:                          # interrupt: pending by design
            benign.append(urb)
            continue
        outstanding = capture_end - urb.epoch
        if outstanding > threshold(urb.endpoint):
            blocked.append(urb)
        else:
            benign.append(urb)                        # still legitimately in flight
    return blocked, benign


def ascii_of(data: bytes, limit: int = 60) -> str:
    """Render payload bytes readably, keeping control codes visible."""
    out = []
    for byte in data[:limit]:
        if byte == 0x0A:
            out.append("\\n")
        elif byte == 0x0D:
            out.append("\\r")
        elif 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"<{byte:02X}>")
    text = "".join(out)
    if len(data) > limit:
        text += f" ...(+{len(data) - limit}B)"
    return text


def format_timeline(urbs: list[Urb], orphans: set[int], data_only: bool) -> str:
    """Human-readable URB timeline, one line per event."""
    lines = [
        f"{'clock':<13} {'frame':>6} {'ev':<4} {'dir':<3} {'type':<4} "
        f"{'ep':>4} {'len':>5} {'lat_ms':>8}  status / data",
        "-" * 118,
    ]
    for urb in urbs:
        if data_only and not urb.payload:
            continue
        event = "SUB" if urb.is_submit else "CPL"
        lat = f"{urb.latency * 1000:.3f}" if urb.latency is not None else ""
        tail = urb.status_name
        if urb.payload:
            tail = f"{tail:<10} {ascii_of(urb.payload)}" if tail else ascii_of(urb.payload)
        flag = "  <== NEVER COMPLETED" if urb.frame in orphans else ""
        lines.append(
            f"{urb.clock:<13} {urb.frame:>6} {event:<4} {urb.direction:<3} "
            f"{urb.kind:<4} 0x{urb.endpoint:02x} {urb.data_len:>5} {lat:>8}  {tail}{flag}"
        )
    return "\n".join(lines)


def format_tsv(urbs: list[Urb], orphans: set[int]) -> str:
    rows = ["clock\tepoch\tframe\tevent\tdirection\ttype\tendpoint\t"
            "bytes\tlatency_ms\tstatus\torphan\tdata"]
    for urb in urbs:
        rows.append("\t".join([
            urb.clock,
            f"{urb.epoch:.6f}",
            str(urb.frame),
            "submit" if urb.is_submit else "complete",
            urb.direction,
            urb.kind,
            f"0x{urb.endpoint:02x}",
            str(urb.data_len),
            f"{urb.latency * 1000:.3f}" if urb.latency is not None else "",
            urb.status_name,
            "yes" if urb.frame in orphans else "",
            ascii_of(urb.payload, limit=200),
        ]))
    return "\n".join(rows)


def report_gaps(urbs: list[Urb], gap_ms: float) -> list[str]:
    """Find stretches where the link went quiet, longest first."""
    events = [u for u in urbs if u.epoch]
    gaps = []
    for prev, nxt in zip(events, events[1:]):
        delta = (nxt.epoch - prev.epoch) * 1000
        if delta >= gap_ms:
            gaps.append((delta, prev, nxt))
    gaps.sort(key=lambda g: g[0], reverse=True)

    lines = []
    for delta, prev, nxt in gaps[:10]:
        lines.append(
            f"  {delta / 1000:8.3f} s  {prev.clock} -> {nxt.clock}   "
            f"after frame {prev.frame} ({prev.direction} {prev.kind}"
            f"{': ' + ascii_of(prev.payload, 40) if prev.payload else ''})"
        )
    return lines


def verdict(urbs: list[Urb], orphans: set[int], needle: str) -> str:
    """
    Answer the write-vs-read question for a specific outgoing command.

    Finds each OUT URB whose payload contains ``needle`` and reports whether that
    write completed, how long it took, and what came back afterwards.
    """
    probe = needle.encode("utf-8", "replace")
    hits = [u for u in urbs if u.payload and probe in u.payload and u.direction == "OUT"]
    if not hits:
        return f"No OUT URB carrying {needle!r} found in this capture."

    epochs = [u.epoch for u in urbs]
    out = [f"Found {len(hits)} OUT transfer(s) carrying {needle!r}", ""]

    for n, urb in enumerate(hits, 1):
        out.append(f"--- occurrence {n} -- frame {urb.frame} at {urb.clock} ---")
        out.append(f"  payload      : {ascii_of(urb.payload, 120)}")

        if urb.is_submit:
            done = urb.completed_by
            if done is None:
                out.append("  WRITE        : submitted, NEVER COMPLETED")
                out.append("  => the host blocked inside the write. The USB stack never")
                out.append("     acknowledged this transfer, so the app's write call could")
                out.append("     not have returned.")
            else:
                lat = (done.epoch - urb.epoch) * 1000
                out.append(f"  WRITE        : completed at {done.clock} "
                           f"after {lat:.3f} ms, status {done.status_name}")
                if done.status not in (0x00000000, None):
                    out.append("  => the write did NOT succeed. A non-success completion this")
                    out.append("     late usually means the transfer was still outstanding when")
                    out.append("     the port was closed and the stack cancelled it -- i.e. the")
                    out.append("     write was blocked for its whole lifetime.")
                elif lat > SLOW_WRITE_MS:
                    out.append(f"  => the write succeeded but took {lat / 1000:.2f} s. A bulk OUT of")
                    out.append("     this size should complete in single-digit milliseconds, so the")
                    out.append("     host was blocked inside the write for essentially all of it.")
                else:
                    out.append("  => the write completed normally. The app's write call returned,")
                    out.append("     so any stall after this point is in the read path, not the write.")
        else:
            out.append(f"  WRITE        : completion event, status {urb.status_name}")

        # What did the device send back, and when?
        start = bisect.bisect_right(epochs, urb.epoch)
        following = [u for u in urbs[start:]
                     if u.direction == "IN" and u.payload and not u.is_submit]
        if following:
            reply = following[0]
            out.append(f"  first IN data: {reply.clock} "
                       f"(+{(reply.epoch - urb.epoch) * 1000:.1f} ms) "
                       f"{ascii_of(reply.payload, 80)}")
        else:
            out.append("  first IN data: none for the rest of the capture")

        # Did the host keep asking for data at all?
        in_submits = [u for u in urbs[start:] if u.direction == "IN" and u.is_submit]
        if in_submits:
            last = in_submits[-1]
            out.append(f"  IN URBs after: {len(in_submits)}, last at {last.clock} "
                       f"(+{(last.epoch - urb.epoch):.3f} s)")
        else:
            out.append("  IN URBs after: NONE -- the host stopped requesting data entirely")
        out.append("")

    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="URB-level timeline for USB serial (CDC and FTDI) captures.",
        epilog="Pairs URB submits with completions so a blocked write is "
               "distinguishable from a blocked read.",
    )
    parser.add_argument("pcap", help="Capture file (.pcap / .pcapng)")
    parser.add_argument("--vidpid", metavar="VID:PID",
                        help="Restrict to one device, e.g. 0483:5740 (STM32 VCP) "
                             "or 0403:6001 (FTDI FT232)")
    parser.add_argument("--address", help="Restrict by USB device address instead")
    parser.add_argument("--verdict", metavar="TEXT",
                        help="Diagnose the write/read question for OUT transfers "
                             "containing TEXT, e.g. '$J='")
    parser.add_argument("--gap-ms", type=float, default=250.0,
                        help="Report quiet stretches at least this long (default: 250)")
    parser.add_argument("--data-only", action="store_true",
                        help="Timeline shows only URBs carrying payload")
    parser.add_argument("-f", "--format", choices=["timeline", "tsv"], default="timeline")
    parser.add_argument("-o", "--output", help="Write to file instead of stdout")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"urbtrace {__version__}")
    args = parser.parse_args()

    tshark = check_tshark()

    address = args.address
    if args.vidpid and not address:
        address = resolve_address(tshark, args.pcap, args.vidpid)
        if address is None:
            print(f"Warning: no device matching {args.vidpid} in this capture; "
                  "showing all devices. Check the capture covers the right root hub.",
                  file=sys.stderr)
        elif args.verbose:
            print(f"Resolved {args.vidpid} to device address {address}", file=sys.stderr)

    urbs = read_urbs(tshark, args.pcap, address)
    if not urbs:
        print("No URBs found. Is this a USB capture, and does the filter match?",
              file=sys.stderr)
        sys.exit(1)

    urbs, orphan_list = pair(urbs)
    blocked_list, benign_list = classify_orphans(orphan_list, urbs)
    orphans = {u.frame for u in blocked_list}

    if args.verdict:
        body = verdict(urbs, orphans, args.verdict)
    elif args.format == "tsv":
        body = format_tsv(urbs, orphans)
    else:
        body = format_timeline(urbs, orphans, args.data_only)

    # Summary always goes to stderr so it never pollutes redirected output.
    submits = sum(1 for u in urbs if u.is_submit)
    with_data = sum(1 for u in urbs if u.payload)
    summary = [
        "",
        f"URB events      : {len(urbs)} ({submits} submits, {len(urbs) - submits} completions)",
        f"Carrying payload: {with_data}",
        f"Stuck transfers : {len(blocked_list)}"
        + ("  <== submitted, never completed" if blocked_list
           else "  (none -- every transfer the host started also finished)"),
    ]
    for urb in blocked_list[:10]:
        summary.append(f"    frame {urb.frame} at {urb.clock} {urb.direction} "
                       f"{urb.kind} ep 0x{urb.endpoint:02x} "
                       f"{ascii_of(urb.payload, 50)}")
    if benign_list:
        summary.append(
            f"Expected orphans: {len(benign_list)} "
            "(interrupt-endpoint reads, and transfers still in flight at capture stop)"
        )

    gaps = report_gaps(urbs, args.gap_ms)
    if gaps:
        summary.append(f"Quiet stretches >= {args.gap_ms:.0f} ms (longest first):")
        summary.extend(gaps)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(body + "\n")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(body)
    print("\n".join(summary), file=sys.stderr)


if __name__ == "__main__":
    main()
