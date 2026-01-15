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

# Custom output file
python pcaper.py capture.pcap -o output.txt

# Verbose mode
python pcaper.py capture.pcap -v
```

On Windows, you may need to use `py` instead of `python`:
```cmd
py pcaper.py capture.pcap -f gcode
```

## Output Formats

### Labeled (default)
Human-readable blocks with metadata for each packet, showing direction and timestamps.

### TSV
Tab-separated values with columns: `timestamp`, `direction`, `source`, `destination`, `data`

### G-code
Data with direction prefixes (`>>>` for commands sent, `<<<` for responses). Blank lines separate direction changes for readability.
