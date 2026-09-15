#!/usr/bin/env python3
"""
Unit tests for pcaper.py's serial payload extraction.

Feeds pyshark-shaped fake packets through extract_usb_packets, so no tshark,
pyshark parsing, or capture file is needed. Runs under pytest, or standalone:

    python tests/test_pcaper_serial.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pcaper  # noqa: E402


# --- pyshark stand-ins ---------------------------------------------------------
# Only the surface pcaper touches: packet.layers, packet.<layer>, packet.usb.src,
# layer.layer_name, layer.field_names and layer.<field>. pyshark names fields
# with the layer prefix stripped and dots/dashes turned to underscores, e.g.
# "ftdi-ft.if_a_rx_payload" -> if_a_rx_payload, "usbcom.data.in_payload" ->
# data_in_payload. Byte fields arrive colon-separated ("47:31:0a").

class FakeLayer:
    def __init__(self, layer_name, **fields):
        self.layer_name = layer_name
        self.field_names = list(fields)
        for name, value in fields.items():
            setattr(self, name, value)


class FakePacket:
    def __init__(self, *layers, ts="1.5"):
        self.layers = list(layers)
        self.sniff_timestamp = ts

    def __getattr__(self, item):
        # Like pyshark: packet.usb returns the layer, missing layers raise.
        for layer in self.__dict__.get("layers", []):
            if layer.layer_name == item:
                return layer
        raise AttributeError(item)


class FakeCapture:
    def __init__(self, packets):
        self._packets = packets
        self.closed = False

    def __iter__(self):
        return iter(self._packets)

    def close(self):
        self.closed = True


def extract(packets, **kwargs):
    """Run extract_usb_packets over fake packets and return the list."""
    original = pcaper.pyshark.FileCapture
    pcaper.pyshark.FileCapture = lambda path, **kw: FakeCapture(packets)
    try:
        return list(pcaper.extract_usb_packets("fake.pcapng", **kwargs))
    finally:
        pcaper.pyshark.FileCapture = original


def usb(src, dst, **extra):
    return FakeLayer("usb", src=src, dst=dst, **extra)


# --- CDC (usbcom) ----------------------------------------------------------------

def test_cdc_in_payload():
    pkt = FakePacket(usb("1.1.1", "host"), FakeLayer("usbcom", data_in_payload="6f:6b:0a"))
    [p] = extract([pkt])
    assert p.raw_data == b"ok\n"
    assert p.direction == "IN"
    assert p.protocol == "SERIAL"


def test_cdc_out_payload():
    pkt = FakePacket(usb("host", "1.1.1"), FakeLayer("usbcom", data_out_payload="47:31:0a"))
    [p] = extract([pkt])
    assert p.raw_data == b"G1\n"
    assert p.direction == "OUT"
    assert p.protocol == "SERIAL"


# --- FTDI (ftdi-ft) ---------------------------------------------------------------

def test_ftdi_tx_payload_is_serial_out():
    pkt = FakePacket(usb("host", "1.3.2"), FakeLayer("ftdi-ft", if_a_tx_payload="24:4a:3d:0a"))
    [p] = extract([pkt])
    assert p.raw_data == b"$J=\n"
    assert p.direction == "OUT"
    assert p.protocol == "SERIAL"


def test_ftdi_rx_payload_is_serial_in():
    pkt = FakePacket(
        usb("1.3.1", "host"),
        FakeLayer("ftdi-ft", modem_status="0x31", line_status="0x60", if_a_rx_payload="6f:6b:0d:0a"),
    )
    [p] = extract([pkt])
    assert p.raw_data == b"ok\r\n"
    assert p.direction == "IN"
    assert p.protocol == "SERIAL"


def test_ftdi_status_only_poll_is_skipped():
    # The FTDI driver polls constantly; each poll returns two status bytes and
    # no data. Those must not appear as serial traffic.
    pkt = FakePacket(usb("1.3.1", "host"), FakeLayer("ftdi-ft", modem_status="0x31", line_status="0x60"))
    assert extract([pkt]) == []


def test_ftdi_second_channel_is_found():
    pkt = FakePacket(usb("1.5.3", "host"), FakeLayer("ftdi-ft", if_b_rx_payload="42"))
    [p] = extract([pkt])
    assert p.raw_data == b"B"


def test_ftdi_layer_is_matched_by_name_not_attribute():
    # "ftdi-ft" is not a valid attribute name, so hasattr-style lookup would
    # never see it. find_layer must go through packet.layers.
    layer = FakeLayer("ftdi-ft", if_a_tx_payload="41")
    pkt = FakePacket(usb("host", "1.3.2"), layer)
    assert pcaper.find_layer(pkt, "ftdi-ft") is layer
    assert pcaper.find_layer(pkt, "usbcom") is None


# --- fallbacks ----------------------------------------------------------------------

def test_capdata_fallback_is_generic_usb():
    pkt = FakePacket(usb("host", "1.2.1", capdata="47:32:38"))
    [p] = extract([pkt])
    assert p.raw_data == b"G28"
    assert p.protocol == "USB"
    assert p.direction == "OUT"


def test_frames_without_payload_are_skipped():
    assert extract([FakePacket(usb("1.2.1", "host"))]) == []


def test_capture_is_closed():
    original = pcaper.pyshark.FileCapture
    cap = FakeCapture([])
    pcaper.pyshark.FileCapture = lambda path, **kw: cap
    try:
        list(pcaper.extract_usb_packets("fake.pcapng"))
    finally:
        pcaper.pyshark.FileCapture = original
    assert cap.closed


def test_check_tshark_falls_back_to_windows_default():
    original_which = pcaper.shutil.which
    original_default = pcaper.TSHARK_WINDOWS_DEFAULT
    with tempfile.NamedTemporaryFile(suffix="tshark.exe", delete=False) as tmp:
        fake = tmp.name
    try:
        pcaper.shutil.which = lambda name: None
        pcaper.TSHARK_WINDOWS_DEFAULT = fake
        assert pcaper.check_tshark() == fake
    finally:
        pcaper.shutil.which = original_which
        pcaper.TSHARK_WINDOWS_DEFAULT = original_default
        os.unlink(fake)


def _run_standalone():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL {name}: {exc!r}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return failures


if __name__ == "__main__":
    sys.exit(1 if _run_standalone() else 0)
