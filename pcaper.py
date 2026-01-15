#!/usr/bin/env python3
"""
Pcaper - Extract USB packet data from pcap captures.

Extracts "Leftover Capture Data" from USB packets, useful for
recovering G-code sent to CNC machines, laser cutters, 3D printers, etc.
"""

import argparse
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Generator

try:
    import pyshark
except ImportError:
    print("Error: pyshark not installed. Run: pip install pyshark",
          file=sys.stderr)
    sys.exit(1)

__version__ = "0.1.0"


@dataclass
class USBPacket:
    """Represents a USB packet with leftover capture data."""
    timestamp: float
    source: str
    destination: str
    direction: str  # "OUT" (host->device) or "IN" (device->host)
    raw_data: bytes


def check_tshark() -> None:
    """Verify tshark is available on the system."""
    if not shutil.which('tshark'):
        print(
            "Error: tshark not found. Please install Wireshark:\n"
            "  macOS:   brew install wireshark\n"
            "  Ubuntu:  sudo apt install tshark\n"
            "  Windows: Install Wireshark from wireshark.org",
            file=sys.stderr
        )
        sys.exit(1)


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string (with : or space separators) to bytes."""
    hex_clean = hex_string.replace(':', '').replace(' ', '')
    return bytes.fromhex(hex_clean)


def extract_usb_packets(pcap_path: str) -> Generator[USBPacket, None, None]:
    """
    Extract USB packets with payload data from a pcap file.

    Checks multiple possible data locations:
    - usb.capdata (generic USB leftover capture data)
    - usbcom.data.in_payload (USB CDC serial incoming data)
    - usbcom.data.out_payload (USB CDC serial outgoing data)

    Args:
        pcap_path: Path to the pcap file

    Yields:
        USBPacket objects for each packet containing payload data
    """
    cap = pyshark.FileCapture(pcap_path)

    for packet in cap:
        try:
            timestamp = float(packet.sniff_timestamp)

            # Get source and destination
            source = 'unknown'
            destination = 'unknown'
            if hasattr(packet, 'usb'):
                source = getattr(packet.usb, 'src', 'unknown')
                destination = getattr(packet.usb, 'dst', 'unknown')

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

            # Check for generic USB leftover capture data
            if raw_data is None and hasattr(packet, 'usb'):
                capdata = getattr(packet.usb, 'capdata', None)
                if capdata:
                    raw_data = hex_to_bytes(capdata)

            # Skip packets without payload data
            if raw_data is None or len(raw_data) == 0:
                continue

            # Determine direction based on source
            # "host" as source means OUT (command to device)
            # anything else means IN (response from device)
            direction = "OUT" if str(source).lower() == "host" else "IN"

            yield USBPacket(
                timestamp=timestamp,
                source=str(source),
                destination=str(destination),
                direction=direction,
                raw_data=raw_data,
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
        f"Packet #{packet_num} [{packet.direction}]\n"
        f"{separator}\n"
        f"Timestamp:   {packet.timestamp}\n"
        f"Direction:   {packet.source} {direction_arrow} {packet.destination}\n"
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
    return f"{packet.timestamp}\t{packet.direction}\t{packet.source}\t{packet.destination}\t{data_escaped}\n"


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
  tsv      - Tab-separated: timestamp\\tdirection\\tsource\\tdest\\tdata
  gcode    - Data with direction prefix (>>> OUT, <<< IN)

Examples:
  %(prog)s capture.pcap                    # Basic extraction
  %(prog)s capture.pcap -f gcode           # G-code only output
  %(prog)s capture.pcap -f tsv --raw-bytes # TSV with hex bytes
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


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Check dependencies
    check_tshark()

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
        print(f"Output format: {args.format}")
        print(f"Output file: {output_path}")

    # Process packets
    packet_count = 0
    last_direction = None
    try:
        with open(output_path, 'w') as out:
            # Write header for TSV format
            if args.format == 'tsv':
                out.write("timestamp\tdirection\tsource\tdestination\tdata\n")

            for packet in extract_usb_packets(args.input_file):
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
            print("Warning: No packets with leftover capture data found.", file=sys.stderr)

        return 0

    except PermissionError:
        print(f"Error: Cannot write to {output_path}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error processing pcap: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
