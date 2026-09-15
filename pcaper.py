#!/usr/bin/env python3
"""
Pcaper - Extract USB packet data from pcap captures.

Extracts serial payloads (USB CDC and FTDI) and "Leftover Capture Data" from
USB packets, useful for recovering G-code sent to CNC machines, laser cutters,
3D printers, etc.
"""

import argparse
import asyncio
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Optional

try:
    import pyshark
except ImportError:
    print("Error: pyshark not installed. Run: pip install pyshark",
          file=sys.stderr)
    sys.exit(1)

__version__ = "0.2.0"

# Where the Wireshark installer puts tshark when it is not on PATH.
TSHARK_WINDOWS_DEFAULT = r"C:\Program Files\Wireshark\tshark.exe"

# tshark's protocol name for FTDI FT232/FT2232/FT4232 traffic. pyshark exposes
# layers by attribute, and "ftdi-ft" cannot be spelled as one, so it is looked
# up by name instead.
FTDI_LAYER = "ftdi-ft"


@dataclass
class USBPacket:
    """Represents a USB packet with leftover capture data."""
    timestamp: float
    source: str
    destination: str
    direction: str  # "OUT" (host->device) or "IN" (device->host)
    raw_data: bytes
    protocol: str = "USB"  # "SERIAL", "USB", "TCP", or "HTTP"


def ensure_event_loop() -> None:
    """
    Ensure an asyncio event loop exists for the current thread.

    pyshark relies on an implicit event loop in the main thread. Python 3.14
    removed that implicit loop, so ``get_event_loop()`` raises RuntimeError and
    pyshark fails with "There is no current event loop in thread 'MainThread'".
    Creating one explicitly restores the expected behavior.
    """
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


def check_tshark() -> str:
    """Locate tshark, preferring PATH but falling back to the Windows default."""
    found = shutil.which('tshark')
    if found:
        return found
    if Path(TSHARK_WINDOWS_DEFAULT).is_file():
        return TSHARK_WINDOWS_DEFAULT
    print(
        "Error: tshark not found. Please install Wireshark:\n"
        "  macOS:   brew install wireshark\n"
        "  Ubuntu:  sudo apt install tshark\n"
        "  Windows: Install Wireshark from wireshark.org, or add\n"
        "           C:\\Program Files\\Wireshark to PATH",
        file=sys.stderr
    )
    sys.exit(1)


def find_layer(packet, name: str):
    """Return the packet layer with this tshark protocol name, or None."""
    for layer in getattr(packet, 'layers', []):
        if layer.layer_name == name:
            return layer
    return None


def ftdi_payload(layer) -> Optional[bytes]:
    """
    Serial bytes carried by one FTDI frame, or None if it carries none.

    FTDI chips prefix every IN transfer with two modem/line-status bytes, and
    the driver polls the chip continuously, so most IN frames are status only.
    tshark's ftdi-ft dissector strips the status bytes and exposes real serial
    data as ``if_<channel>_rx_payload`` / ``if_<channel>_tx_payload`` (one pair
    per channel; FT2232/FT4232 parts have several). Reading those fields rather
    than ``usb.capdata`` is what keeps the status bytes out of the extracted
    stream and drops the empty polls.
    """
    for name in layer.field_names:
        if name.endswith('_rx_payload') or name.endswith('_tx_payload'):
            value = getattr(layer, name, None)
            if value:
                return hex_to_bytes(str(value))
    return None


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string (with : or space separators) to bytes."""
    hex_clean = hex_string.replace(':', '').replace(' ', '')
    return bytes.fromhex(hex_clean)


def extract_usb_packets(
    pcap_path: str,
    include_net: bool = False,
    tshark_path: Optional[str] = None,
) -> Generator[USBPacket, None, None]:
    """
    Extract packets with payload data from a USB pcap file.

    Checks multiple possible data locations, most specific first:
    - usbcom.data.in_payload (USB CDC serial incoming data)
    - usbcom.data.out_payload (USB CDC serial outgoing data)
    - ftdi-ft.if_*_rx_payload / if_*_tx_payload (FTDI serial data, status
      bytes already stripped by the dissector)
    - usb.capdata (generic USB leftover capture data)

    The protocol-aware fields only exist when tshark could identify the
    device, which needs its descriptors in the capture. USBPcap injects them
    for already-connected devices when "inject descriptors" is on, which
    capture-serial.ps1 forces.

    When ``include_net`` is set, also extracts TCP payloads carried over the USB
    link (network-over-USB via RNDIS/MBIM/ECM, i.e. usb -> eth -> ip -> tcp).
    Many devices expose themselves as a USB network adapter and do the real work
    over TCP/HTTP, which is invisible to the serial/capdata extraction above.

    Args:
        pcap_path: Path to the pcap file
        include_net: If True, also yield TCP-over-USB payloads
        tshark_path: Explicit tshark executable, when it is not on PATH

    Yields:
        USBPacket objects for each packet containing payload data
    """
    ensure_event_loop()
    cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path)

    for packet in cap:
        try:
            timestamp = float(packet.sniff_timestamp)

            # USB-level endpoints. The PC is always addressed as "host", so this
            # determines direction regardless of what higher layer carries data.
            usb_src = 'unknown'
            usb_dst = 'unknown'
            if hasattr(packet, 'usb'):
                usb_src = getattr(packet.usb, 'src', 'unknown')
                usb_dst = getattr(packet.usb, 'dst', 'unknown')

            # "host" as source means OUT (command to device); otherwise IN.
            direction = "OUT" if str(usb_src).lower() == "host" else "IN"

            # Defaults describe the USB endpoints; net packets override below.
            source = usb_src
            destination = usb_dst
            protocol = "USB"

            # Try multiple possible data field locations
            raw_data = None

            # Check for USB CDC serial data (usbcom layer)
            if hasattr(packet, 'usbcom'):
                # Try IN payload (device -> host)
                in_payload = getattr(packet.usbcom, 'data_in_payload', None)
                if in_payload:
                    raw_data = hex_to_bytes(in_payload)

                # Try OUT payload (host -> device)
                if raw_data is None:
                    out_payload = getattr(packet.usbcom, 'data_out_payload', None)
                    if out_payload:
                        raw_data = hex_to_bytes(out_payload)

                if raw_data is not None:
                    protocol = "SERIAL"

            # Check for FTDI serial data (FT232 and friends)
            if raw_data is None:
                ftdi = find_layer(packet, FTDI_LAYER)
                if ftdi is not None:
                    raw_data = ftdi_payload(ftdi)
                    if raw_data is not None:
                        protocol = "SERIAL"

            # Check for generic USB leftover capture data
            if raw_data is None and hasattr(packet, 'usb'):
                capdata = getattr(packet.usb, 'capdata', None)
                if capdata:
                    raw_data = hex_to_bytes(capdata)

            # Check for TCP payload carried over the USB link (network-over-USB)
            if raw_data is None and include_net and hasattr(packet, 'tcp'):
                payload = getattr(packet.tcp, 'payload', None)
                if payload:
                    raw_data = hex_to_bytes(str(payload))

                    # Prefer IP/port endpoints for a meaningful description
                    ip_layer = getattr(packet, 'ip', None) or getattr(packet, 'ipv6', None)
                    src_ip = getattr(ip_layer, 'src', usb_src)
                    dst_ip = getattr(ip_layer, 'dst', usb_dst)
                    src_port = getattr(packet.tcp, 'srcport', '?')
                    dst_port = getattr(packet.tcp, 'dstport', '?')
                    source = f"{src_ip}:{src_port}"
                    destination = f"{dst_ip}:{dst_port}"
                    protocol = "HTTP" if hasattr(packet, 'http') else "TCP"

            # Skip packets without payload data
            if raw_data is None or len(raw_data) == 0:
                continue

            yield USBPacket(
                timestamp=timestamp,
                source=str(source),
                destination=str(destination),
                direction=direction,
                raw_data=raw_data,
                protocol=protocol,
            )
        except (AttributeError, ValueError):
            # Packet doesn't have expected fields or invalid hex, skip
            continue

    cap.close()


def bytes_to_ascii(data: bytes) -> str:
    """
    Convert bytes to ASCII string.

    Preserves printable characters and common whitespace.
    Non-printable characters are replaced with '.'.

    Args:
        data: Raw bytes to convert

    Returns:
        ASCII string representation
    """
    result = []
    for byte in data:
        if byte == 0x0a:  # newline
            result.append('\n')
        elif byte == 0x0d:  # carriage return
            continue  # Skip CR, keep only LF for cleaner output
        elif byte == 0x09:  # tab
            result.append('\t')
        elif 0x20 <= byte <= 0x7e:  # printable ASCII
            result.append(chr(byte))
        else:
            result.append('.')
    return ''.join(result)


def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to hex string for display.

    Args:
        data: Raw bytes to convert

    Returns:
        Space-separated hex string (e.g., "47 32 38")
    """
    return ' '.join(f'{b:02x}' for b in data)


def format_labeled(packet: USBPacket, packet_num: int, raw_bytes: bool = False) -> str:
    """
    Format packet as a human-readable labeled block.

    Args:
        packet: The USB packet to format
        packet_num: Packet sequence number
        raw_bytes: If True, show hex bytes instead of ASCII

    Returns:
        Formatted string block
    """
    separator = "=" * 80
    data_label = "Data (hex):" if raw_bytes else "Data:"
    data_content = bytes_to_hex(packet.raw_data) if raw_bytes else bytes_to_ascii(packet.raw_data)
    direction_arrow = "->" if packet.direction == "OUT" else "<-"

    return (
        f"{separator}\n"
        f"Packet #{packet_num} [{packet.direction}] {packet.protocol}\n"
        f"{separator}\n"
        f"Timestamp:   {packet.timestamp}\n"
        f"Endpoint:    {packet.source} {direction_arrow} {packet.destination}\n"
        f"{data_label}\n"
        f"{data_content}\n\n"
    )


def format_tsv(packet: USBPacket, raw_bytes: bool = False) -> str:
    """
    Format packet as tab-separated values.

    Args:
        packet: The USB packet to format
        raw_bytes: If True, show hex bytes instead of ASCII

    Returns:
        Tab-separated line
    """
    data = bytes_to_hex(packet.raw_data) if raw_bytes else bytes_to_ascii(packet.raw_data)
    # Replace newlines with literal \n for TSV compatibility
    data_escaped = data.replace('\n', '\\n').replace('\t', '\\t')
    return (
        f"{packet.timestamp}\t{packet.direction}\t{packet.protocol}\t"
        f"{packet.source}\t{packet.destination}\t{data_escaped}\n"
    )


def format_gcode(packet: USBPacket, raw_bytes: bool = False) -> str:
    """
    Format packet as data only (minimal output for G-code extraction).

    Args:
        packet: The USB packet to format
        raw_bytes: If True, show hex bytes instead of ASCII

    Returns:
        Data content with direction prefix
    """
    data = bytes_to_hex(packet.raw_data) if raw_bytes else bytes_to_ascii(packet.raw_data)
    # Strip trailing whitespace and add direction prefix
    data = data.rstrip()
    prefix = ">>> " if packet.direction == "OUT" else "<<< "
    # Handle multi-line data by prefixing each line
    lines = data.split('\n')
    prefixed_lines = [f"{prefix}{line}" for line in lines if line]
    return '\n'.join(prefixed_lines) + '\n'


def format_reassembled_stream(stream, raw_bytes: bool = False) -> str:
    """
    Format a reassembled TCP stream as a labeled block covering both directions.

    Args:
        stream: A reassemble.ReassembledStream instance
        raw_bytes: If True, show hex bytes instead of ASCII

    Returns:
        Formatted string block
    """
    separator = "=" * 80
    lines = [
        separator,
        f"Stream #{stream.stream}  {stream.client} <-> {stream.server}",
        separator,
    ]
    if stream.start_ts:
        lines.append(f"Time:        {stream.start_ts} - {stream.end_ts}")

    for direction, label in (("c2s", "client -> server"),
                             ("s2c", "server -> client")):
        data = stream.data(direction)
        if not data:
            continue
        gaps = stream.gaps.get(direction, [])
        gap_note = f"  [MISSING BYTES: {gaps}]" if gaps else ""
        content = bytes_to_hex(data) if raw_bytes else bytes_to_ascii(data)
        lines.append("")
        lines.append(f"--- {label} ({len(data)} bytes){gap_note} ---")
        lines.append(content.rstrip("\n"))

    lines.append("")
    lines.append("")
    return "\n".join(lines) + "\n"


def generate_output_path(input_path: str) -> str:
    """
    Generate output filename from input path.

    Replaces the extension with .txt.

    Args:
        input_path: Path to input file

    Returns:
        Output path with .txt extension
    """
    p = Path(input_path)
    return str(p.with_suffix('.txt'))


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract USB packet data from pcap captures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output formats:
  labeled  - Human-readable blocks with labels (default)
  tsv      - Tab-separated: timestamp\\tdirection\\tprotocol\\tsource\\tdest\\tdata
  gcode    - Data with direction prefix (>>> OUT, <<< IN)

Examples:
  %(prog)s capture.pcap                    # Basic extraction (serial/capdata)
  %(prog)s capture.pcap -f gcode           # G-code only output
  %(prog)s capture.pcap -f tsv --raw-bytes # TSV with hex bytes
  %(prog)s capture.pcap --net              # Also include network-over-USB TCP
  %(prog)s capture.pcap --reassemble       # Full reassembled TCP streams
  %(prog)s capture.pcap --extract-objects out/  # Carve HTTP files into out/
        """
    )
    parser.add_argument(
        "input_file",
        help="Input pcap file path"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <input_basename>.txt)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["labeled", "tsv", "gcode"],
        default="labeled",
        help="Output format (default: labeled)"
    )
    parser.add_argument(
        "--raw-bytes",
        action="store_true",
        help="Output raw bytes as hex instead of ASCII"
    )
    parser.add_argument(
        "-n", "--net",
        action="store_true",
        help="Also extract TCP payloads carried over the USB link "
             "(network-over-USB via RNDIS/MBIM/ECM). Can be large/binary."
    )
    parser.add_argument(
        "-r", "--reassemble",
        action="store_true",
        help="Reassemble full TCP-over-USB streams (ordered, de-duplicated) "
             "instead of per-packet payloads. Output is one block per stream."
    )
    parser.add_argument(
        "--extract-objects",
        metavar="DIR",
        help="Recover complete HTTP bodies (files: images, uploads, etc.) "
             "from the capture into DIR, plus a manifest.tsv. Ignores -f/-o."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show packet count, etc.)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    return parser.parse_args()


def run_extract_objects(args: argparse.Namespace) -> int:
    """Recover complete HTTP bodies from the capture into a directory."""
    import reassemble

    objects = reassemble.extract_http_objects(args.input_file)
    out_dir = Path(args.extract_objects)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for obj in objects:
            (out_dir / obj.filename).write_bytes(obj.data)
        with open(out_dir / "manifest.tsv", 'w', encoding='utf-8') as manifest:
            manifest.write(
                "index\tkind\tfilename\tsize\tcontent_type\turi\tmd5\n"
            )
            for obj in objects:
                manifest.write(
                    f"{obj.index}\t{obj.kind}\t{obj.filename}\t{obj.size}\t"
                    f"{obj.content_type or '-'}\t{obj.uri or '-'}\t{obj.md5}\n"
                )
    except PermissionError:
        print(f"Error: Cannot write to {out_dir}", file=sys.stderr)
        return 1

    if not objects:
        print("Warning: No HTTP objects found in capture.", file=sys.stderr)
        return 0

    print(f"Extracted {len(objects)} object(s) to {out_dir}")
    if args.verbose:
        for obj in objects:
            print(f"  #{obj.index} [{obj.kind}] {obj.filename} "
                  f"({obj.size} bytes, {obj.content_type or 'unknown'})")
    return 0


def run_reassemble(args: argparse.Namespace, output_path: str) -> int:
    """Reassemble TCP-over-USB streams and write them to the output file."""
    import reassemble

    streams = reassemble.reassemble_streams(args.input_file)
    stream_count = 0
    try:
        with open(output_path, 'w', encoding='utf-8') as out:
            for stream in streams:
                if not stream.c2s and not stream.s2c:
                    continue
                stream_count += 1
                out.write(format_reassembled_stream(stream, args.raw_bytes))
    except PermissionError:
        print(f"Error: Cannot write to {output_path}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"Reassembled {stream_count} TCP stream(s)")
        print(f"Output written to: {output_path}")
    if stream_count == 0:
        print("Warning: No TCP streams found in capture.", file=sys.stderr)
    return 0


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Check dependencies
    tshark_path = check_tshark()

    # Validate input file
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: File not found: {args.input_file}", file=sys.stderr)
        return 1

    if not input_path.is_file():
        print(f"Error: Not a file: {args.input_file}", file=sys.stderr)
        return 1

    # Determine output path
    output_path = args.output or generate_output_path(args.input_file)

    if args.verbose:
        print(f"Processing: {args.input_file}")
        if args.extract_objects:
            print(f"Mode: extract HTTP objects -> {args.extract_objects}")
        elif args.reassemble:
            print("Mode: reassemble TCP streams")
            print(f"Output file: {output_path}")
        else:
            print(f"Output format: {args.format}")
            print(f"Network-over-USB: {'included' if args.net else 'excluded'}")
            print(f"Output file: {output_path}")

    # Reassembly and object extraction take their own code paths
    if args.extract_objects:
        return run_extract_objects(args)
    if args.reassemble:
        return run_reassemble(args, output_path)

    # Process packets
    packet_count = 0
    last_direction = None
    try:
        with open(output_path, 'w') as out:
            # Write header for TSV format
            if args.format == 'tsv':
                out.write(
                    "timestamp\tdirection\tprotocol\tsource\tdestination\tdata\n"
                )

            for packet in extract_usb_packets(args.input_file, include_net=args.net,
                                              tshark_path=tshark_path):
                packet_count += 1

                # Add blank line when direction changes
                if last_direction is not None and packet.direction != last_direction:
                    out.write('\n')
                last_direction = packet.direction

                if args.format == 'labeled':
                    out.write(format_labeled(packet, packet_count, args.raw_bytes))
                elif args.format == 'tsv':
                    out.write(format_tsv(packet, args.raw_bytes))
                elif args.format == 'gcode':
                    out.write(format_gcode(packet, args.raw_bytes))

        if args.verbose:
            print(f"Processed {packet_count} packets with data")
            print(f"Output written to: {output_path}")

        if packet_count == 0:
            print("Warning: No serial or leftover capture data found.\n"
                  "  If the port was open during the capture, tshark may not have been\n"
                  "  able to identify the device: FTDI and CDC payloads are only decoded\n"
                  "  when the device descriptors are in the capture (capture-serial.ps1\n"
                  "  injects them). Try --raw-bytes to see if anything is there at all.",
                  file=sys.stderr)

        return 0

    except PermissionError:
        print(f"Error: Cannot write to {output_path}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error processing pcap: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
