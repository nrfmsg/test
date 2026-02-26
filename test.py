#!/usr/bin/env python3
“””
ASC to BLF converter
Supports CAN and Ethernet (EthernetPacket) frames.

Requirements:
pip install python-can

Usage:
python asc_to_blf.py input.asc output.blf
“””

import re
import sys
import struct
import time
from datetime import datetime
from pathlib import Path

try:
import can
from can.formats.blf import BLFWriter
except ImportError:
print(“Error: python-can is required. Install with: pip install python-can”)
sys.exit(1)

# ───────────────────────────── BLF constants ──────────────────────────────

# Object signatures

BLF_OBJECT_SIGNATURE = b”LOBJ”
BLF_FILE_SIGNATURE   = b”BLF0200”

# Object types (partial list)

BLF_OBJ_CAN_MESSAGE        = 1
BLF_OBJ_CAN_ERROR          = 2
BLF_OBJ_CAN_MESSAGE2       = 86
BLF_OBJ_ETHERNET_FRAME     = 71   # EthernetFrame (raw Ethernet packet)

# Base timestamp (BLF uses 100-nanosecond units from 1980-01-01)

_BLF_BASE = datetime(1980, 1, 1)

def _sec_to_blf_ts(seconds: float) -> int:
“”“Convert seconds (float) to BLF 100-ns ticks.”””
return int(seconds * 1e7)

# ───────────────────── Low-level BLF object writer ────────────────────────

class RawBLFWriter:
“””
Minimal BLF file writer that handles both CAN messages and
Ethernet frames (object type 71).

```
The python-can BLFWriter only supports CAN/LIN messages, so we
implement a thin wrapper around the binary format directly.
"""

# BLF base statistics block size (from spec)
_FILE_HEADER_SIZE = 0x90  # 144 bytes

def __init__(self, path: str):
    self.path = path
    self._objects: list[bytes] = []
    self._start_ts: float | None = None
    self._last_ts: float  = 0.0
    self._msg_count = 0

# ── public API ────────────────────────────────────────────────────────

def add_can_message(self, timestamp: float, channel: int,
                    arbitration_id: int, data: bytes,
                    is_extended: bool = False,
                    is_remote: bool = False):
    if self._start_ts is None:
        self._start_ts = timestamp
    self._last_ts = timestamp
    self._msg_count += 1

    dlc  = len(data)
    flags = 0
    if is_extended:
        flags |= 0x04
    if is_remote:
        flags |= 0x10

    # CAN message base object payload (type 1)
    payload = struct.pack("<HBBBB",
                          channel & 0xFFFF,  # channel (1-based)
                          dlc,
                          flags,
                          arbitration_id & 0xFF,           # id low
                          (arbitration_id >> 8) & 0xFF,    # id high
                          )
    # For extended / >11-bit id we use object type 86 (CAN_MESSAGE2)
    obj_type = BLF_OBJ_CAN_MESSAGE
    if is_extended or arbitration_id > 0x7FF:
        obj_type = BLF_OBJ_CAN_MESSAGE2
        # Rebuild with 4-byte id
        payload = struct.pack("<HBBBI",
                              channel & 0xFFFF,
                              dlc,
                              flags,
                              0,              # reserved
                              arbitration_id | (0x80000000 if is_extended else 0),
                              )

    payload += data.ljust(8, b"\x00")[:8]  # pad/truncate to 8 bytes
    self._objects.append(
        self._make_object(obj_type, timestamp, payload))

def add_ethernet_frame(self, timestamp: float, channel: int,
                       src_mac: bytes, dst_mac: bytes,
                       eth_type: int, payload: bytes):
    """Add an Ethernet frame object (type 71)."""
    if self._start_ts is None:
        self._start_ts = timestamp
    self._last_ts = timestamp
    self._msg_count += 1

    # EthernetFrame object layout (BLF spec §4.4.x):
    # WORD  channel
    # BYTE[6] dst
    # BYTE[6] src
    # WORD  ethertype
    # WORD  payloadLength
    # BYTE* payload
    frame_data = (
        struct.pack("<H", channel) +
        dst_mac[:6].ljust(6, b"\x00") +
        src_mac[:6].ljust(6, b"\x00") +
        struct.pack("<HH", eth_type, len(payload)) +
        payload
    )
    self._objects.append(
        self._make_object(BLF_OBJ_ETHERNET_FRAME, timestamp, frame_data))

def close(self):
    """Write all collected objects to disk with proper BLF envelope."""
    start_ts = self._start_ts or 0.0
    end_ts   = self._last_ts

    body = b"".join(self._objects)

    header = self._make_file_header(
        start_ts=start_ts,
        end_ts=end_ts,
        obj_count=self._msg_count,
        body_size=len(body),
    )

    with open(self.path, "wb") as f:
        f.write(header)
        f.write(body)

# ── private helpers ───────────────────────────────────────────────────

@staticmethod
def _make_object(obj_type: int, timestamp: float, app_data: bytes) -> bytes:
    """
    Build a single BLF object (LOBJ block).

    Header layout (24 bytes):
      4  signature  "LOBJ"
      2  header_size (always 0x18 = 24)
      2  header_version (0x01)
      4  object_size (header + app_data, 4-byte aligned)
      4  object_type
      4  timestamp_ms (low 32 bits, milliseconds – some tools use this)
     [then immediately app_data]

    NOTE: Vector's actual BLF uses a more complex header (version 1 vs 2)
    with 64-bit timestamps.  We use the compact version 1 layout that
    python-can also uses.
    """
    HEADER_SIZE = 32  # 32-byte header used by python-can / CANalyzer

    ts_ns = _sec_to_blf_ts(timestamp)   # 100-ns units

    # Total size rounded up to 4-byte boundary
    total = HEADER_SIZE + len(app_data)
    pad   = (4 - total % 4) % 4
    total_padded = total + pad

    hdr = struct.pack("<4sHHIII8x",   # 32 bytes
                      BLF_OBJECT_SIGNATURE,
                      HEADER_SIZE,     # header size
                      0x0001,          # header version
                      total_padded,    # object size
                      obj_type,
                      0,               # timestamp (ms, kept 0 – we use 64-bit below)
                      )
    # Overwrite last 8 bytes of header with 64-bit timestamp (100 ns)
    hdr = hdr[:24] + struct.pack("<Q", ts_ns)

    return hdr + app_data + b"\x00" * pad

@staticmethod
def _datetime_to_systemtime(dt: datetime) -> bytes:
    """Pack a datetime as SYSTEMTIME (8× WORD)."""
    return struct.pack("<8H",
                       dt.year, dt.month, dt.weekday() + 1, dt.day,
                       dt.hour, dt.minute, dt.second,
                       dt.microsecond // 1000)

def _make_file_header(self, start_ts: float, end_ts: float,
                      obj_count: int, body_size: int) -> bytes:
    """Build the 144-byte BLF file header."""
    HDR_SIZE = 0x90  # 144

    meas_start = datetime.fromtimestamp(
        time.time() - (end_ts - start_ts))
    last_obj   = datetime.fromtimestamp(time.time())

    stat_size = HDR_SIZE + body_size

    hdr = struct.pack("<7sxI",        # signature + padding + header_size
                      BLF_FILE_SIGNATURE,
                      HDR_SIZE)

    # api_version, application name (128 bytes reserved → we use 0)
    hdr += struct.pack("<I", 0x0403)   # api version 4.3
    hdr += b"\x00" * 128              # application name (empty)
    hdr += struct.pack("<II",
                       0,             # api_version (repeat / padding)
                       obj_count)     # object_count
    hdr += struct.pack("<QQ",
                       _sec_to_blf_ts(start_ts),
                       _sec_to_blf_ts(end_ts))
    hdr += self._datetime_to_systemtime(meas_start)  # 16 bytes
    hdr += self._datetime_to_systemtime(last_obj)     # 16 bytes
    hdr += struct.pack("<QI",
                       stat_size,     # file_size
                       0)             # uncompressed_size (0 = not compressed)

    # Pad to HDR_SIZE
    hdr = hdr[:HDR_SIZE].ljust(HDR_SIZE, b"\x00")
    return hdr
```

# ───────────────────────────── ASC parser ─────────────────────────────────

# Patterns for ASC lines

RE_HEADER_DATE  = re.compile(r”^date\s+(.+)$”, re.IGNORECASE)
RE_TIMESTAMP    = re.compile(
r”^\s*([\d.]+)\s+”          # timestamp
r”(\w+)\s+”                  # channel (number or name)
r”([0-9A-Fa-fXx]+)\s+”      # CAN id
r”([RTr])?\s*”               # R = remote
r”(?:Rx|Tx|d)?\s*”
r”(\d+)\s*”                  # dlc (optional for remote)
r”((?:[0-9A-Fa-f]{2}\s*)*)”  # data bytes
)
RE_ETH = re.compile(
r”^\s*([\d.]+)\s+”           # timestamp
r”ETH\s+”                    # keyword
r”(\d+)\s+”                  # channel
r”([0-9A-Fa-f:]+)\s+”        # dst MAC
r”([0-9A-Fa-f:]+)\s+”        # src MAC
r”([0-9A-Fa-f]{4})\s+”       # ethertype
r”(\d+)\s+”                  # payload length
r”((?:[0-9A-Fa-f]{2}\s*)*)”  # payload bytes
, re.IGNORECASE)

# Alternative: EthernetPacket / EthernetRxOk line formats used by CANalyzer

RE_ETH2 = re.compile(
r”^\s*([\d.]+)\s+”
r”(?:EthernetPacket|EthernetRxOk|EthernetTxOk)\s+”
r”channel=(\d+)\s+”
r”dst=([0-9A-Fa-f:]+)\s+”
r”src=([0-9A-Fa-f:]+)\s+”
r”(?:type|ethertype)=([0-9A-Fa-fx]+)\s+”
r”(?:payloadLength|len)=(\d+)\s+”
r”payload=([0-9A-Fa-f ]*)”
, re.IGNORECASE)

def _parse_mac(mac_str: str) -> bytes:
mac_str = mac_str.replace(”-”, “:”).replace(” “, “”)
parts = mac_str.split(”:”)
return bytes(int(p, 16) for p in parts)

def parse_asc(filepath: str):
“””
Generator that yields dicts describing each parsed event.

```
Yielded dict keys:
  type        : "can" | "ethernet"
  timestamp   : float (seconds)
  channel     : int
  --- CAN ---
  arb_id      : int
  is_extended : bool
  is_remote   : bool
  data        : bytes
  --- Ethernet ---
  dst_mac     : bytes (6)
  src_mac     : bytes (6)
  eth_type    : int
  payload     : bytes
"""
with open(filepath, "r", errors="replace") as f:
    for raw_line in f:
        line = raw_line.rstrip()

        # ── Ethernet (format 1: plain ETH line) ──────────────────────
        m = RE_ETH.match(line)
        if m:
            ts, ch, dst, src, etype, plen, pdata = m.groups()
            payload_bytes = bytes(
                int(b, 16) for b in pdata.split() if b)
            yield {
                "type":      "ethernet",
                "timestamp": float(ts),
                "channel":   int(ch),
                "dst_mac":   _parse_mac(dst),
                "src_mac":   _parse_mac(src),
                "eth_type":  int(etype, 16),
                "payload":   payload_bytes,
            }
            continue

        # ── Ethernet (format 2: keyword + named fields) ───────────────
        m = RE_ETH2.match(line)
        if m:
            ts, ch, dst, src, etype, plen, pdata = m.groups()
            payload_bytes = bytes(
                int(b, 16) for b in pdata.split() if b)
            yield {
                "type":      "ethernet",
                "timestamp": float(ts),
                "channel":   int(ch),
                "dst_mac":   _parse_mac(dst),
                "src_mac":   _parse_mac(src),
                "eth_type":  int(etype, 16),
                "payload":   payload_bytes,
            }
            continue

        # ── CAN ──────────────────────────────────────────────────────
        m = RE_TIMESTAMP.match(line)
        if m:
            ts, ch_str, id_str, rtr, dlc_str, data_str = m.groups()

            # Skip non-numeric channels (header artefacts)
            if not ch_str.isdigit():
                continue

            try:
                arb_id = int(id_str, 16)
            except ValueError:
                continue

            is_extended = len(id_str.lstrip("0x0X")) > 3
            is_remote   = rtr is not None and rtr.upper() == "R"
            data_bytes  = bytes(
                int(b, 16) for b in data_str.split() if b)

            yield {
                "type":        "can",
                "timestamp":   float(ts),
                "channel":     int(ch_str),
                "arb_id":      arb_id,
                "is_extended": is_extended,
                "is_remote":   is_remote,
                "data":        data_bytes,
            }
```

# ─────────────────────────────── main ────────────────────────────────────

def convert(asc_path: str, blf_path: str, verbose: bool = True):
writer = RawBLFWriter(blf_path)

```
can_count = 0
eth_count = 0
skip_count = 0

for event in parse_asc(asc_path):
    if event["type"] == "can":
        writer.add_can_message(
            timestamp      = event["timestamp"],
            channel        = event["channel"],
            arbitration_id = event["arb_id"],
            data           = event["data"],
            is_extended    = event["is_extended"],
            is_remote      = event["is_remote"],
        )
        can_count += 1
    elif event["type"] == "ethernet":
        writer.add_ethernet_frame(
            timestamp = event["timestamp"],
            channel   = event["channel"],
            src_mac   = event["src_mac"],
            dst_mac   = event["dst_mac"],
            eth_type  = event["eth_type"],
            payload   = event["payload"],
        )
        eth_count += 1
    else:
        skip_count += 1

writer.close()

if verbose:
    total = can_count + eth_count
    print(f"Conversion complete: {asc_path} → {blf_path}")
    print(f"  CAN frames   : {can_count}")
    print(f"  Ethernet frames: {eth_count}")
    print(f"  Total written: {total}")
    if skip_count:
        print(f"  Skipped lines: {skip_count}")
```

def main():
if len(sys.argv) < 3:
print(“Usage: python asc_to_blf.py <input.asc> <output.blf>”)
sys.exit(1)

```
asc_path = sys.argv[1]
blf_path = sys.argv[2]

if not Path(asc_path).exists():
    print(f"Error: File not found: {asc_path}")
    sys.exit(1)

convert(asc_path, blf_path)
```

if **name** == “**main**”:
main()
