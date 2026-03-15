#!/usr/bin/env python3
from __future__ import annotations

"""Vector CANoe の ASC/BLF ログを単一CSVへ変換するツール。

CAN と Ethernet のレコードを抽出し、同一スキーマの行へ正規化して
後段処理を 1 つのテーブルで扱えるようにする。

設計上の方針:
- BLF は Ethernet フレームを扱える `vblf` を利用する。
- ASC の CAN は `python-can` (`ASCReader`) で安定して解析する。
- ASC の Ethernet は CANoe 設定で表記が変わるため、テキスト解析する。
"""

import argparse
import csv
import datetime as dt
import ipaddress
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

from can.io.asc import ASCReader
from vblf.can import CanFdMessage, CanFdMessage64, CanMessage, CanMessage2
from vblf.constants import ObjFlags
from vblf.ethernet import EthernetFrameEx
from vblf.reader import BlfReader


CSV_COLUMNS = [
    # 入力ファイル由来の情報
    "source_file",
    "record_type",
    # 共通列
    "timestamp",
    "channel",
    # CAN 列
    "can_id",
    "dlc",
    "can_data",
    # Ethernet / IP / トランスポート層列
    "src_mac",
    "dst_mac",
    "ethertype",
    "ip_version",
    "src_ip",
    "dst_ip",
    "transport_protocol",
    "src_port",
    "dst_port",
    "tcp_flags",
]

MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
TIMESTAMP_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)")
HEX_RE = re.compile(r"0x[0-9A-Fa-f]+")


@dataclass
class CsvRow:
    """内部で扱う正規化済みのCSV行モデル。

    該当しない列は空文字で埋める。例: CAN行では Ethernet 列を空にする。
    """

    source_file: str
    record_type: str
    timestamp: str = ""
    channel: str = ""
    can_id: str = ""
    dlc: str = ""
    can_data: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: str = ""
    ip_version: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    transport_protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    tcp_flags: str = ""


def parse_args() -> argparse.Namespace:
    """CLI引数を解析する。"""

    parser = argparse.ArgumentParser(
        description="Parse Vector CANoe ASC/BLF logs and export CAN/Ethernet records to CSV."
    )
    parser.add_argument("inputs", nargs="+", help="Input .asc/.blf file(s)")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file path")
    return parser.parse_args()


def main() -> int:
    """エントリーポイント。

    1) すべての入力ファイルを正規化行へ変換する。
    2) タイムスタンプ順に並べる（空のタイムスタンプは末尾）。
    3) 1つのCSVとして出力する。
    """

    args = parse_args()
    rows: list[CsvRow] = []

    for input_name in args.inputs:
        path = Path(input_name)
        suffix = path.suffix.lower()
        if suffix == ".blf":
            rows.extend(iter_blf_rows(path))
        elif suffix == ".asc":
            rows.extend(iter_asc_rows(path))
        else:
            raise ValueError(f"Unsupported file type: {path}")

    rows.sort(key=lambda row: sort_key(row.timestamp))
    write_csv(Path(args.output), rows)
    return 0


def sort_key(timestamp: str) -> tuple[int, str]:
    """タイムスタンプ文字列用の安定ソートキーを返す。

    1要素目で「タイムスタンプ有無」を優先し、2要素目でISO文字列順に並べる。
    """

    if not timestamp:
        return (1, "")
    return (0, timestamp)


def write_csv(path: Path, rows: Iterable[CsvRow]) -> None:
    """固定列順で正規化行をCSVへ書き出す。"""

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def iter_blf_rows(path: Path) -> Iterator[CsvRow]:
    """BLFオブジェクトから正規化行を順次生成する。

    本ツールで扱う型のみをCSV行へ変換する:
    - CAN: CanMessage/CanMessage2/CanFdMessage/CanFdMessage64
    - Ethernet: EthernetFrameEx
    """

    with BlfReader(path) as reader:
        # BLFのオブジェクト時刻は相対値のため、計測開始時刻を基準に絶対化する。
        base_time = system_time_to_datetime(reader.file_statistics.measurement_start_time)
        for obj in reader:
            if isinstance(obj, (CanMessage, CanMessage2, CanFdMessage, CanFdMessage64)):
                yield can_row_from_blf(path, obj, base_time)
            elif isinstance(obj, EthernetFrameEx):
                yield ethernet_row_from_blf(path, obj, base_time)


def can_row_from_blf(
    path: Path,
    obj: CanMessage | CanMessage2 | CanFdMessage | CanFdMessage64,
    base_time: dt.datetime,
) -> CsvRow:
    """BLFのCANオブジェクト1件をCsvRowへ変換する。"""

    timestamp = format_blf_timestamp(base_time, obj.header.object_flags, obj.header.object_time_stamp)
    frame_id = getattr(obj, "frame_id", 0)
    data = getattr(obj, "data", b"")
    dlc = getattr(obj, "dlc", len(data))

    return CsvRow(
        source_file=str(path),
        record_type="CAN",
        timestamp=timestamp,
        channel=str(getattr(obj, "channel", "")),
        can_id=format_can_id(frame_id),
        dlc=str(dlc),
        can_data=bytes_to_hex(data),
    )


def ethernet_row_from_blf(path: Path, obj: EthernetFrameEx, base_time: dt.datetime) -> CsvRow:
    """BLFのEthernetオブジェクト1件をCsvRowへ変換する。

    `frame_data` は可能な範囲でL4まで解析する（IPv4/IPv6 + TCP/UDP）。
    """

    parsed = decode_ethernet_frame(obj.frame_data)
    timestamp = format_blf_timestamp(base_time, obj.header.object_flags, obj.header.object_time_stamp)

    return CsvRow(
        source_file=str(path),
        record_type="ETHERNET",
        timestamp=timestamp,
        channel=str(obj.channel),
        src_mac=parsed.get("src_mac", ""),
        dst_mac=parsed.get("dst_mac", ""),
        ethertype=parsed.get("ethertype", ""),
        ip_version=parsed.get("ip_version", ""),
        src_ip=parsed.get("src_ip", ""),
        dst_ip=parsed.get("dst_ip", ""),
        transport_protocol=parsed.get("transport_protocol", ""),
        src_port=parsed.get("src_port", ""),
        dst_port=parsed.get("dst_port", ""),
        tcp_flags=parsed.get("tcp_flags", ""),
    )


def iter_asc_rows(path: Path) -> Iterator[CsvRow]:
    """ASCから取得したCAN/Ethernet行を時刻順で生成する。"""

    can_rows = list(iter_asc_can_rows(path))
    eth_rows = list(iter_asc_ethernet_rows(path))
    yield from sorted(can_rows + eth_rows, key=lambda row: sort_key(row.timestamp))


def iter_asc_can_rows(path: Path) -> Iterator[CsvRow]:
    """python-can の ASCReader でCAN行を生成する。"""

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        reader = ASCReader(handle)
        for message in reader:
            yield CsvRow(
                source_file=str(path),
                record_type="CAN",
                timestamp=format_unix_timestamp(message.timestamp),
                channel="" if message.channel is None else str(message.channel),
                can_id=format_can_id(message.arbitration_id),
                dlc=str(message.dlc),
                can_data=bytes_to_hex(message.data),
            )


def iter_asc_ethernet_rows(path: Path) -> Iterator[CsvRow]:
    """ASC生テキストからEthernet行を生成する。

    ASCのEthernet表記はCANoeのバージョン/設定で差があるため、
    複数パターンを受け入れる実装としている。
    """

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parsed = parse_asc_ethernet_line(line)
            if parsed is None:
                continue
            yield CsvRow(source_file=str(path), record_type="ETHERNET", **parsed)


def parse_asc_ethernet_line(line: str) -> Optional[dict[str, str]]:
    """ASC 1行をEthernet行として解析できる場合に辞書を返す。

    対応している主な形式:
    - MACが明示される形式: "... 66:77:... 00:11:... ..."
    - 生フレームHEXの短縮形式: "... ETH ... 3c:<frame_hex>"
    """

    macs = MAC_RE.findall(line)
    timestamp_match = TIMESTAMP_RE.match(line)
    timestamp = timestamp_match.group(1) if timestamp_match else ""

    if len(macs) < 2:
        # CANoeでよく出る短縮形式:
        # "<ts> ETH ... <len_hex>:<raw_frame_hex>"
        compact_match = re.search(
            r"\bETH\b.*?\b([0-9A-Fa-f]{2,4}):([0-9A-Fa-f]+)\b",
            line,
        )
        if not compact_match:
            return None
        frame_hex = compact_match.group(2)
        if len(frame_hex) < 28 or len(frame_hex) % 2 != 0:
            return None
        try:
            # BLFと同じデコーダを使うため、HEXをバイト列へ変換して解析する。
            parsed = decode_ethernet_frame(bytes.fromhex(frame_hex))
        except ValueError:
            return None
        return {
            "timestamp": timestamp,
            "src_mac": parsed.get("src_mac", ""),
            "dst_mac": parsed.get("dst_mac", ""),
            "ethertype": parsed.get("ethertype", ""),
            "ip_version": parsed.get("ip_version", ""),
            "src_ip": parsed.get("src_ip", ""),
            "dst_ip": parsed.get("dst_ip", ""),
            "transport_protocol": parsed.get("transport_protocol", ""),
            "src_port": parsed.get("src_port", ""),
            "dst_port": parsed.get("dst_port", ""),
            "tcp_flags": parsed.get("tcp_flags", ""),
        }

    ethertype = ""
    # 0x0600以上の先頭HEXトークンをEtherType候補として採用する。
    for token in HEX_RE.findall(line):
        value = int(token, 16)
        if value >= 0x0600:
            ethertype = f"0x{value:04X}"
            break

    ipv4s = [candidate for candidate in IPV4_RE.findall(line) if is_valid_ip(candidate)]
    ipv6s = [candidate for candidate in IPV6_RE.findall(line) if is_valid_ip(candidate)]
    src_ip = ""
    dst_ip = ""
    ip_version = ""
    if len(ipv4s) >= 2:
        src_ip, dst_ip = ipv4s[0], ipv4s[1]
        ip_version = "IPv4"
    elif len(ipv6s) >= 2:
        src_ip, dst_ip = ipv6s[0], ipv6s[1]
        ip_version = "IPv6"

    protocol = ""
    upper = line.upper()
    if " TCP " in f" {upper} ":
        protocol = "TCP"
    elif " UDP " in f" {upper} ":
        protocol = "UDP"
    elif " ICMP " in f" {upper} ":
        protocol = "ICMP"

    src_port = ""
    dst_port = ""
    if protocol in {"TCP", "UDP"}:
        # IPv4アドレスのオクテット誤検出を避けるため、TCP/UDP以降だけを対象にする。
        transport_match = re.search(
            r"\b(?:TCP|UDP)\b(.*)$",
            line,
            flags=re.IGNORECASE,
        )
        transport_tail = transport_match.group(1) if transport_match else line
        port_pairs = re.findall(
            r"(?<![\d.])(\d{1,5})\s*(?:->|>|to)\s*(\d{1,5})(?![\d.])",
            transport_tail,
            flags=re.IGNORECASE,
        )
        if port_pairs:
            src_port, dst_port = port_pairs[0]

    tcp_flags = ""
    # ASC行内の代表的なTCPフラグ表記を抽出する。
    flags_match = re.search(r"\b(?:SYN|ACK|FIN|RST|PSH|URG)(?:[,|/ ]+(?:SYN|ACK|FIN|RST|PSH|URG))*\b", upper)
    if flags_match and protocol == "TCP":
        tcp_flags = flags_match.group(0).replace(" ", "")

    return {
        "timestamp": timestamp,
        "src_mac": normalize_mac(macs[0]),
        "dst_mac": normalize_mac(macs[1]),
        "ethertype": ethertype,
        "ip_version": ip_version,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "transport_protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": tcp_flags,
    }


def decode_ethernet_frame(frame_data: bytes) -> dict[str, str]:
    """生のEthernetフレームをCSV列用の辞書へデコードする。

    解析する層:
    - L2: dst/src MAC, EtherType
    - 任意: 802.1Q VLANヘッダ（単一タグ）
    - L3: IPv4 または IPv6
    - L4: 可能なら TCP/UDP
    """

    if len(frame_data) < 14:
        return {}

    dst_mac = format_mac(frame_data[0:6])
    src_mac = format_mac(frame_data[6:12])
    ethertype_value = int.from_bytes(frame_data[12:14], "big")
    parsed: dict[str, str] = {
        "dst_mac": dst_mac,
        "src_mac": src_mac,
        "ethertype": f"0x{ethertype_value:04X}",
    }

    payload = frame_data[14:]
    # VLANタグ付きフレーム。0x8100 の後ろ2バイトが内側EtherType。
    if ethertype_value == 0x8100 and len(payload) >= 4:
        ethertype_value = int.from_bytes(payload[2:4], "big")
        parsed["ethertype"] = f"0x{ethertype_value:04X}"
        payload = payload[4:]

    if ethertype_value == 0x0800:
        parsed.update(decode_ipv4_packet(payload))
    elif ethertype_value == 0x86DD:
        parsed.update(decode_ipv6_packet(payload))
    return parsed


def decode_ipv4_packet(payload: bytes) -> dict[str, str]:
    """IPv4ヘッダを解析し、残りをトランスポート層デコーダへ渡す。"""

    if len(payload) < 20:
        return {"ip_version": "IPv4"}

    version = payload[0] >> 4
    ihl = (payload[0] & 0x0F) * 4
    if version != 4 or len(payload) < ihl:
        return {"ip_version": "IPv4"}

    protocol = payload[9]
    src_ip = str(ipaddress.IPv4Address(payload[12:16]))
    dst_ip = str(ipaddress.IPv4Address(payload[16:20]))
    result = {
        "ip_version": "IPv4",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }
    result.update(decode_transport(protocol, payload[ihl:]))
    return result


def decode_ipv6_packet(payload: bytes) -> dict[str, str]:
    """固定長のIPv6ヘッダを解析し、残りをトランスポート層デコーダへ渡す。"""

    if len(payload) < 40:
        return {"ip_version": "IPv6"}

    version = payload[0] >> 4
    if version != 6:
        return {"ip_version": "IPv6"}

    next_header = payload[6]
    src_ip = str(ipaddress.IPv6Address(payload[8:24]))
    dst_ip = str(ipaddress.IPv6Address(payload[24:40]))
    result = {
        "ip_version": "IPv6",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }
    result.update(decode_transport(next_header, payload[40:]))
    return result


def decode_transport(protocol: int, payload: bytes) -> dict[str, str]:
    """IPプロトコル番号に応じてL4を解析する。"""

    if protocol == 6:
        return decode_tcp_segment(payload)
    if protocol == 17:
        return decode_udp_datagram(payload)
    return {"transport_protocol": ip_protocol_name(protocol)}


def decode_udp_datagram(payload: bytes) -> dict[str, str]:
    """UDPの送信元/宛先ポートを解析する。"""

    if len(payload) < 8:
        return {"transport_protocol": "UDP"}
    return {
        "transport_protocol": "UDP",
        "src_port": str(int.from_bytes(payload[0:2], "big")),
        "dst_port": str(int.from_bytes(payload[2:4], "big")),
    }


def decode_tcp_segment(payload: bytes) -> dict[str, str]:
    """TCPの送信元/宛先ポートとフラグを解析する。"""

    if len(payload) < 20:
        return {"transport_protocol": "TCP"}
    flags = payload[13]
    return {
        "transport_protocol": "TCP",
        "src_port": str(int.from_bytes(payload[0:2], "big")),
        "dst_port": str(int.from_bytes(payload[2:4], "big")),
        "tcp_flags": decode_tcp_flags(flags),
    }


def decode_tcp_flags(flags: int) -> str:
    """TCPフラグのビット値を `|` 区切りの名前へ変換する。"""

    names = [
        ("FIN", 0x01),
        ("SYN", 0x02),
        ("RST", 0x04),
        ("PSH", 0x08),
        ("ACK", 0x10),
        ("URG", 0x20),
        ("ECE", 0x40),
        ("CWR", 0x80),
    ]
    return "|".join(name for name, bit in names if flags & bit)


def ip_protocol_name(protocol: int) -> str:
    """既知のIPプロトコル番号を名前へ変換し、未知値は数値文字列を返す。"""

    names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        58: "ICMPv6",
    }
    return names.get(protocol, str(protocol))


def format_blf_timestamp(base_time: dt.datetime, flags: ObjFlags, raw_value: int) -> str:
    """BLFの相対時刻をISO-8601(UTC)へ変換する。

    BLFオブジェクト時刻の単位はフラグで変わる:
    - TIME_ONE_NANS: ナノ秒
    - それ以外: 10マイクロ秒
    """

    if flags & ObjFlags.TIME_ONE_NANS:
        delta = dt.timedelta(microseconds=raw_value / 1000)
    else:
        delta = dt.timedelta(microseconds=raw_value * 10)
    return (base_time + delta).isoformat()


def system_time_to_datetime(system_time: object) -> dt.datetime:
    """BLFのSystemTime相当オブジェクトをタイムゾーン付きdatetimeへ変換する。

    公開サンプルの一部には開始時刻がゼロ埋めのものがあるため、
    変換を継続できるようにUnix epochへフォールバックする。
    """

    try:
        return dt.datetime(
            year=system_time.year,
            month=system_time.month,
            day=system_time.day,
            hour=system_time.hour,
            minute=system_time.minute,
            second=system_time.second,
            microsecond=system_time.milliseconds * 1000,
            tzinfo=dt.timezone.utc,
        )
    except ValueError:
        # 公開BLFサンプルの一部で measurement_start_time がゼロ埋めになる。
        return dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def format_unix_timestamp(timestamp: float) -> str:
    """Unix時刻(float)をISO-8601(UTC)へ変換する。"""

    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat()


def format_can_id(frame_id: int) -> str:
    """CAN IDを `0x` 付き大文字16進文字列へ整形する。"""

    return f"0x{frame_id:X}"


def bytes_to_hex(data: bytes) -> str:
    """ペイロードバイト列を空白区切り大文字HEX文字列へ整形する。"""

    return " ".join(f"{byte:02X}" for byte in data)


def format_mac(data: bytes) -> str:
    """6バイトMACを大文字コロン区切り形式へ整形する。"""

    return ":".join(f"{byte:02X}" for byte in data[:6])


def normalize_mac(value: str) -> str:
    """文字列表現のMACを大文字コロン区切りに正規化する。"""

    return value.replace("-", ":").upper()


def is_valid_ip(value: str) -> bool:
    """文字列が有効なIPv4/IPv6アドレスならTrueを返す。"""

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
