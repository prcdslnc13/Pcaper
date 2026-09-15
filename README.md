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

#### `capture-serial.ps1` (recommended)

USBPcap attaches per *root hub*, so the interface number depends on which
physical port the device is plugged into — capturing the wrong one silently
records nothing useful. This helper resolves the interface at run time from the
COM port (or the VID:PID), captures to a timestamped file, and then checks that
the file actually contains the device's traffic:

```powershell
# from an elevated shell -- USBPcap will not give a handle to a non-admin process
.\capture-serial.ps1 -Port COM10 -Tag jog-hang
.\capture-serial.ps1 -VidPid 0403:6001 -Seconds 120 -Tag baseline      # FTDI FT232
.\capture-serial.ps1 -Port COM10 -RingMinutes 5 -RingFiles 48 -Tag standing
```

Start the capture *before* the application opens the port; the open sequence
(baud rate, flow control, DTR/RTS) is usually the most informative part.
Ctrl-C stops the capture and still runs the checks. The verdict at the end
tells apart four situations that all look like "no data" in Wireshark:

| Verdict | Meaning |
|---|---|
| `EMPTY` | USBPcap recorded nothing at all — the capture never started (see below) |
| none from VID:PID | traffic was recorded, but the device is on another root hub |
| port never opened | device seen, but nothing opened the COM port during the capture |
| no serial bytes | the port was opened; only FTDI status polls / control transfers |

If it cannot match the device it prints every visible device tree rather than
guessing which one you meant; pass the right one as `-Interface USBPcapN`.

#### Empty captures: check Wireshark's preferences

tshark launches USBPcapCMD with the options saved in Wireshark's preferences
file (`%APPDATA%\Wireshark\preferences`). If *Capture from all devices* was
ever unticked in the Wireshark GUI for an interface, it is saved as

```
extcap.____usbpcap1.capturefromalldevices: false
extcap.____usbpcap1.injectdescriptors: false
```

and from then on **every** capture on that interface — GUI or tshark — records
zero packets, not even the device descriptors. `capture-serial.ps1` overrides
these for its own run and warns when it sees them. To fix the GUI, re-tick the
options in the interface's options dialog (the gear icon next to `USBPcapN`),
or delete those lines. The same override works for a plain tshark command:

```cmd
tshark -o extcap.____usbpcap1.capturefromalldevices:true -o extcap.____usbpcap1.injectdescriptors:true -i \\.\USBPcap1 -w capture.pcapng
```

The value must be lowercase `true`; tshark silently ignores `TRUE`.

*Inject descriptors* matters beyond this: it is what lets tshark identify an
already-connected device, and the CDC (`usbcom`) and FTDI (`ftdi-ft`)
dissectors — and therefore `pcaper.py` and `urbtrace.py --vidpid` — only work
when the descriptors are in the capture.

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

### USB serial adapters (CDC and FTDI)

Serial payloads are read from tshark's protocol dissectors rather than from raw
leftover data: `usbcom` for CDC-ACM ports (STM32 VCP, most boards that show up
as "USB Serial Device (COMn)") and `ftdi-ft` for FTDI FT232/FT2232/FT4232
adapters ("USB Serial Port (COMn)"). For FTDI this is essential — the chip
prefixes every read with two status bytes and the driver polls it constantly,
so raw capture data would be a stream of `01 60` noise with the real bytes
buried in it. Both dissectors need the device descriptors in the capture (see
*Inject descriptors* above); `pcaper.py` falls back to raw `usb.capdata` when
they are absent and says so when it finds nothing.

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

## URB-level analysis (`urbtrace.py`)

`pcaper.py` answers *what bytes crossed the link*. When an application stops
talking to a device, that is not enough: a write that never completed, a read
that was never issued, and a device that sent nothing all look identical at the
payload layer. `urbtrace.py` pairs every URB submit with its completion, which
tells them apart:

| Symptom | What the capture shows |
|---|---|
| Blocked in `write()` | OUT URB submitted, never completed (or completes late / `CANCELED`) |
| Blocked in `read()` | OUT URB completed normally, IN URBs stop being submitted |
| Device sent nothing | IN URBs submitted and pending, no completion carries data |

```bash
# full URB timeline, wall-clock stamped to line up with an application log
python urbtrace.py capture.pcapng --vidpid 0483:5740     # STM32 VCP (CDC)
python urbtrace.py capture.pcapng --vidpid 0403:6001     # FTDI FT232

# only transfers carrying payload
python urbtrace.py capture.pcapng --vidpid 0483:5740 --data-only

# diagnose one specific command
python urbtrace.py capture.pcapng --verdict '$J='

# machine-readable
python urbtrace.py capture.pcapng -f tsv -o urbs.tsv
```

`--verdict TEXT` finds each OUT transfer containing `TEXT` and reports whether
that write completed, how long it took, what came back afterwards, and whether
the host kept requesting data at all.

Timestamps are printed as local `HH:MM:SS.mmm` specifically so the timeline can
be read side by side with an application's own debug log.

### Reading the summary

The summary (on stderr, so it never pollutes redirected output) reports **stuck
transfers** and **quiet stretches**. Not every submit without a completion is a
stall — drivers keep a rotating pool of reads outstanding, and CDC interrupt
endpoints sit pending by design, so both are excluded. A transfer is only called
stuck when it stayed outstanding far longer than that endpoint's own median
completion latency. On a healthy capture the count is zero, so any non-zero
count is worth reading.

## Tests

The tests use synthetic inputs only, so they need neither tshark nor a capture:

```bash
python tests/test_reassemble.py
python tests/test_pcaper_serial.py
# or, with pytest installed: python -m pytest tests/
```

## Output Formats

### Labeled (default)
Human-readable blocks with metadata for each packet, showing direction and timestamps.

### TSV
Tab-separated values with columns: `timestamp`, `direction`, `protocol`, `source`, `destination`, `data`

### G-code
Data with direction prefixes (`>>>` for commands sent, `<<<` for responses). Blank lines separate direction changes for readability.
