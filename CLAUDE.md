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
```

## System Requirement

Requires tshark (Wireshark CLI) to be installed: `brew install wireshark` on macOS.
