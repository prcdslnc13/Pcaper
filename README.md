# Pcaper

Extract G-Code and other data from USB packet captures.

## Requirements

- Python 3.8+
- Wireshark/tshark installed on the system

### Installing tshark

- **macOS**: `brew install wireshark`
- **Ubuntu/Debian**: `sudo apt install tshark`
- **Windows**: Install Wireshark from [wireshark.org](https://www.wireshark.org/)

## Installation

```bash
pip install -r requirements.txt
```

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

## Output Formats

### Labeled (default)
Human-readable blocks with metadata for each packet.

### TSV
Tab-separated values with header: `timestamp`, `source`, `destination`, `data`

### G-code
Data only, one entry per packet. Useful for extracting clean G-code files.
