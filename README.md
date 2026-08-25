# Pcaper

Extract G-Code and other data from USB packet captures.

## Requirements

- Python 3.8+
- Wireshark/tshark installed on the system

## Installation

### macOS

```bash
brew install wireshark
pip install -r requirements.txt
```

### Ubuntu/Debian

```bash
sudo apt install tshark
pip install -r requirements.txt
```

### Windows

1. **Install Python** (if not already installed):
   - Download from [python.org](https://www.python.org/downloads/)
   - During installation, check "Add Python to PATH"

2. **Install Wireshark with USBPcap**:
   - Download from [wireshark.org](https://www.wireshark.org/download.html)
   - During installation, check "Install USBPcap" to enable USB capture
   - Wireshark installer adds tshark to PATH automatically

3. **Install Python dependencies**:
   ```cmd
   pip install -r requirements.txt
   ```

4. **Verify tshark is accessible**:
   ```cmd
   tshark --version
   ```
   If not found, add Wireshark to PATH manually:
   - Default location: `C:\Program Files\Wireshark`
   - Add to System Environment Variables → Path

## Capturing USB Traffic

### Windows (USBPcap)

1. Open Wireshark
2. Select a USBPcap interface (e.g., "USBPcap1")
3. Start capture, perform the actions you want to record
4. Stop capture and save as `.pcap` or `.pcapng`

Alternatively, use the command line:
```cmd
"C:\Program Files\Wireshark\USBPcapCMD.exe" -d "\\.\USBPcap1" -o capture.pcap
```

### Linux

```bash
sudo modprobe usbmon
sudo tshark -i usbmon0 -w capture.pcap
```

### macOS

USB capture requires additional setup with a virtual machine or specialized tools.

## Usage

```bash
# Basic extraction (labeled format, ASCII output)
python pcaper.py capture.pcap

# G-code only output (minimal, just the data)
python pcaper.py capture.pcap -f gcode

# Tab-separated values
python pcaper.py capture.pcap -f tsv

# Raw hex bytes instead of ASCII
python pcaper.py capture.pcap --raw-bytes

# Also extract network-over-USB traffic (see below)
python pcaper.py capture.pcap --net

# Reassemble full TCP-over-USB streams (see below)
python pcaper.py capture.pcap --reassemble

# Recover complete HTTP files (images, uploads, ...) into a directory
python pcaper.py capture.pcap --extract-objects out/

# Custom output file
python pcaper.py capture.pcap -o output.txt

# Verbose mode
python pcaper.py capture.pcap -v
```

### Network-over-USB (`--net`)

Some devices (e.g. laser cutters, printers with a built-in web UI) present
themselves as a USB *network adapter* (RNDIS/MBIM/ECM) and do most of their work
over TCP/HTTP rather than a USB serial port. That traffic is invisible to the
default serial/`capdata` extraction.

Pass `--net` to also extract the TCP payloads carried over the USB link. Packets
are labeled with their protocol (`TCP`/`HTTP`) and IP:port endpoints. Note this
can produce large output and includes binary payloads (images, uploads), so
combine with `--raw-bytes` or `-f tsv` when inspecting binary data.

`--net` shows raw **per-segment** payloads. Because network-over-USB often
aggregates several Ethernet frames into one USB transfer, and multi-segment
messages (a large HTTP body) span many packets, use the reassembly options below
to see complete streams and files.

### TCP stream reassembly (`--reassemble`)

Reconstructs each TCP connection into its full, ordered byte stream (both
directions), transparently handling out-of-order segments, retransmissions,
overlaps, and USB/MBIM frame aggregation. Output is one labeled block per stream,
with a client-to-server and server-to-client section. Any bytes genuinely missing
from the capture are zero-filled and flagged as `[MISSING BYTES: ...]` — never
silently dropped. This works for any TCP protocol, including ones pcaper does not
otherwise decode (e.g. ZeroMQ control/telemetry channels).

### HTTP object extraction (`--extract-objects DIR`)

Recovers complete HTTP bodies as files into `DIR`, plus a `manifest.tsv`
(index, kind, filename, size, content-type, URI, MD5). Downloaded responses
(e.g. `combined.jpg`) and uploaded request bodies are both recovered; files are
named from the request URI and de-duplicated. This is the way to pull the actual
images/payloads out of a capture:

```bash
python pcaper.py capture.pcap --extract-objects recovered/
# -> recovered/combined.jpg, recovered/preview_333x222.png, recovered/manifest.tsv, ...
```

On Windows, you may need to use `py` instead of `python`:
```cmd
py pcaper.py capture.pcap -f gcode
```

## Output Formats

### Labeled (default)
Human-readable blocks with metadata for each packet, showing direction and timestamps.

### TSV
Tab-separated values with columns: `timestamp`, `direction`, `protocol`, `source`, `destination`, `data`

### G-code
Data with direction prefixes (`>>>` for commands sent, `<<<` for responses). Blank lines separate direction changes for readability.
