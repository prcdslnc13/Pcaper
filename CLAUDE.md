# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

Pcaper extracts G-Code commands from USB packet captures (pcap files). This is useful for reverse-engineering or analyzing 3D printer/CNC machine communications captured via USB sniffing.

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the tool
python pcaper.py <input.pcap>

# Run with verbose output
python pcaper.py <input.pcap> -v

# URB-level timeline (write-vs-read stalls) for one device
python urbtrace.py <input.pcapng> --vidpid 0403:6001

# Tests (synthetic inputs, no tshark needed)
python tests/test_reassemble.py
python tests/test_pcaper_serial.py
```

## Capturing on Windows

Use `capture-serial.ps1 -Port COMn` from an elevated shell. It resolves the
USBPcap interface for the port, overrides Wireshark's saved extcap preferences
(a saved "capture from all devices: false" makes every tshark/GUI capture on
that interface empty), and prints a verdict on whether the device's traffic is
actually in the file. See README "Empty captures".

## System Requirement

Requires tshark (Wireshark CLI) to be installed: `brew install wireshark` on macOS.
