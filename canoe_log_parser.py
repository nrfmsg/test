#!/usr/bin/env python3
"""
CANoe Log Parser
================
Vector CANoe が生成した ASC / BLF ログファイルを解析してコンソールに表示するツールです。
CAN / CAN FD / Ethernet フレームが混在するログに対応しています。

【使い方】
    python canoe_log_parser.py <ファイルパス>

    例:
        python canoe_log_parser.py log.asc
        python canoe_log_parser.py log.blf

【必要なライブラリ】
    pip install python-can vblf

    ・python-can : ASC ファイルの CAN / CAN FD フレーム解析に使用
    ・vblf       : BLF ファイルの CAN / CAN FD / Ethernet 解析に使用
    ※ ASC の Ethernet は標準ライブラリのみで解析します
"""

# ===================================================================
# 標準ライブラリのインポート
# ===================================================================
import re           # 正規表現（テキストのパターンマッチに使う）
import sys          # コマンドライン引数・エラー出力に使う
import datetime as dt   # 日時・タイムスタンプの処理に使う
import ipaddress        # IP アドレスの検証・変換に使う
from dataclasses import dataclass   # データクラスを簡単に作るための機能
from pathlib import Path            # ファイルパスを扱いやすくするクラス
from typing import List, Optional, Union  # 型ヒント（変数の型を明示するための記法）


# ===================================================================
# 外部ライブラリのインポート
# ===================================================================

# --- python-can（ASC の CAN / CAN FD 解析に使用）---
# try〜except は「試してみて失敗したら別の処理をする」という構文です。
try:
    from can.io.asc import ASCReader  # ASC ファイルを読み込むクラス
    PYTHON_CAN_AVAILABLE = True
except ImportError:
    PYTHON_CAN_AVAILABLE = False

# --- vblf（BLF の CAN / CAN FD / Ethernet 解析に使用）---
try:
    from vblf.reader import BlfReader as VblfReader          # BLF ファイルを読み込むクラス
    from vblf.can import CanMessage, CanMessage2             # Classic CAN オブジェクト
    from vblf.can_fd import CanFdMessage, CanFdMessage64     # CAN FD オブジェクト
    from vblf.ethernet import EthernetFrameEx                # Ethernet オブジェクト
    from vblf.constants import ObjFlags                      # タイムスタンプ単位フラグ
    VBLF_AVAILABLE = True
except ImportError:
    VBLF_AVAILABLE = False


# ===================================================================
# CAN FD の DLC → 実データバイト数 変換テーブル
# ===================================================================
# Classic CAN は最大 8 バイトですが、CAN FD は最大 64 バイトです。
# DLC の値 9〜15 は以下の表のバイト数に対応しています。
# 例: DLC=9 → 12 バイト、DLC=15 → 64 バイト
FD_DLC_TO_LEN = {
    0:  0,   1:  1,   2:  2,   3:  3,
    4:  4,   5:  5,   6:  6,   7:  7,
    8:  8,   9: 12,  10: 16,  11: 20,
    12: 24,  13: 32,  14: 48,  15: 64,
}

def fd_dlc_to_len(dlc: int) -> int:
    """DLC の値を実際のデータバイト数に変換して返す関数"""
    # .get(key, default) は辞書からキーに対応する値を取り出す。
    # キーが見つからなければ第2引数の値（ここでは dlc そのまま）を返す。
    return FD_DLC_TO_LEN.get(dlc, dlc)


# ===================================================================
# 既知 EtherType の名前テーブル
# ===================================================================
# EtherType は Ethernet フレームが何のプロトコルを運ぶかを示す 2 バイトの値です。
ETHER_TYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN(802.1Q)",
    0x8892: "PROFINET",
    0x88A4: "EtherCAT",
    0x88CC: "LLDP",
    0x22F0: "AVB(IEEE 1722)",
    0x88F7: "PTP(IEEE 1588)",
    0x8912: "SOME/IP-SD",
    0x88B8: "GOOSE",
}


# ===================================================================
# 正規表現パターン（ASC の Ethernet 行テキスト解析用）
# ===================================================================
# re.compile() であらかじめコンパイルすると処理が速くなります。

# MAC アドレスのパターン（例: "FF:FF:FF:FF:FF:FF" や "FF-FF-FF-FF-FF-FF"）
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

# IPv4 アドレスのパターン（例: "192.168.0.1"）
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6 アドレスのパターン（例: "fe80::1"）
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")

# タイムスタンプのパターン（行頭の数値、例: "0.001234"）
TIMESTAMP_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)")

# 16 進数トークンのパターン（例: "0x0800"）
HEX_RE = re.compile(r"0x[0-9A-Fa-f]+")

# ASC の Ethernet 行パターン
# 例: "0.001234  ETH  1  Rx  60  FF FF FF FF FF FF 00 11 22 33 44 55 08 00 ..."
ETH_RE = re.compile(
    r"^\s*(?P<ts>\d+\.\d+)"         # タイムスタンプ
    r"\s+ETH"                       # "ETH" キーワード
    r"\s+(?P<ch>\d+)"               # チャンネル番号
    r"\s+(?P<dir>Rx|Tx)"            # 受信 / 送信
    r"\s+(?P<len>\d+)"              # フレーム長
    r"(?P<raw>(?:\s+[0-9A-Fa-f]{2})+)"  # 生バイト列
)


# ===================================================================
# CANFrame データクラス（CAN / CAN FD フレームのデータを保持する）
# ===================================================================
@dataclass
class CANFrame:
    """
    CAN または CAN FD の 1 フレーム分のデータを保持するクラスです。
    is_fd が True のとき CAN FD フレーム、False のとき Classic CAN フレームです。
    """
    timestamp:    float       # タイムスタンプ（秒・相対時刻）
    abs_time:     str         # 絶対時刻（ISO-8601 UTC 文字列、不明なら空文字）
    channel:      int         # チャンネル番号
    can_id:       int         # CAN ID（整数値）
    dlc:          int         # DLC 値（CAN FD では 0〜15）
    data:         bytes       # データバイト列（CAN FD は最大 64 バイト）
    direction:    str = ""    # "Rx" または "Tx"
    is_extended:  bool = False    # True なら 29bit 拡張 ID
    is_remote:    bool = False    # True なら RTR フレーム
    is_error:     bool = False    # True なら エラーフレーム
    is_fd:        bool = False    # True なら CAN FD フレーム
    brs:          bool = False    # Bit Rate Switch（CAN FD）
    esi:          bool = False    # Error State Indicator（CAN FD）

    @property
    def frame_type(self) -> str:
        """フレーム種別を文字列で返す（表示用）"""
        return "CANFD" if self.is_fd else "CAN  "

    @property
    def data_length(self) -> int:
        """実際のデータバイト数（CAN FD は DLC から変換が必要）"""
        return fd_dlc_to_len(self.dlc) if self.is_fd else min(self.dlc, 8)

    @property
    def can_id_str(self) -> str:
        """CAN ID を 16 進数文字列で返す（拡張ID:8桁 / 標準ID:3桁）"""
        return f"{self.can_id:08X}" if self.is_extended else f"{self.can_id:03X}"

    @property
    def data_str(self) -> str:
        """データバイト列を '00 11 22 ...' 形式の文字列で返す"""
        return " ".join(f"{b:02X}" for b in self.data)

    @property
    def flags_str(self) -> str:
        """有効なフラグを空白区切りの文字列で返す（例: 'EXT FD BRS'）"""
        flags = []
        if self.is_extended: flags.append("EXT")
        if self.is_remote:   flags.append("RTR")
        if self.is_error:    flags.append("ERR")
        if self.is_fd:       flags.append("FD")
        if self.brs:         flags.append("BRS")
        if self.esi:         flags.append("ESI")
        return " ".join(flags) if flags else "-"

    def __str__(self) -> str:
        """print() で呼ばれたときのコンソール表示フォーマット"""
        # 絶対時刻があれば使い、なければ相対時刻を表示する
        ts_str = self.abs_time if self.abs_time else f"{self.timestamp:13.6f}s"
        return (
            f"[{ts_str}]  {self.frame_type}  "
            f"CH:{self.channel:2d}  "
            f"ID:0x{self.can_id_str}  "
            f"DLC:{self.dlc:2d}({self.data_length:2d}B)  "
            f"Data:[{self.data_str}]  "
            f"Flags:[{self.flags_str}]  "
            f"{self.direction}"
        )


# ===================================================================
# EthernetFrame データクラス（Ethernet フレームのデータを保持する）
# ===================================================================
@dataclass
class EthernetFrame:
    """
    Ethernet の 1 フレーム分のデータを保持するクラスです。
    L2（MAC・EtherType）から L4（TCP/UDP のポート番号）まで保持します。
    """
    timestamp:          float     # タイムスタンプ（秒・相対時刻）
    abs_time:           str       # 絶対時刻（ISO-8601 UTC 文字列）
    channel:            int       # チャンネル番号
    dst_mac:            str       # 宛先 MAC アドレス（例: "FF:FF:FF:FF:FF:FF"）
    src_mac:            str       # 送信元 MAC アドレス
    ether_type:         int       # EtherType（整数値）
    frame_length:       int       # フレーム長（バイト）
    direction:          str = ""  # "Rx" または "Tx"
    # L3 情報
    ip_version:         str = ""  # "IPv4" または "IPv6"
    src_ip:             str = ""  # 送信元 IP アドレス
    dst_ip:             str = ""  # 宛先 IP アドレス
    # L4 情報
    transport_protocol: str = ""  # "TCP" / "UDP" / "ICMP" など
    src_port:           str = ""  # 送信元ポート番号
    dst_port:           str = ""  # 宛先ポート番号
    tcp_flags:          str = ""  # TCP フラグ（例: "SYN|ACK"）

    @property
    def ether_type_str(self) -> str:
        """EtherType を '0x0800(IPv4)' のような文字列で返す"""
        label = ETHER_TYPE_NAMES.get(self.ether_type, "Unknown")
        return f"0x{self.ether_type:04X}({label})"

    def __str__(self) -> str:
        """print() で呼ばれたときのコンソール表示フォーマット"""
        ts_str = self.abs_time if self.abs_time else f"{self.timestamp:13.6f}s"

        # L3/L4 情報を持つ場合は追加で表示する
        l3_l4 = ""
        if self.ip_version:
            l3_l4 += f"  {self.ip_version}  {self.src_ip} -> {self.dst_ip}"
        if self.transport_protocol:
            l3_l4 += f"  {self.transport_protocol}"
        if self.src_port:
            l3_l4 += f"  Port:{self.src_port}->{self.dst_port}"
        if self.tcp_flags:
            l3_l4 += f"  TCPFlags:[{self.tcp_flags}]"

        return (
            f"[{ts_str}]  ETH    "
            f"CH:{self.channel:2d}  "
            f"DST:{self.dst_mac}  "
            f"SRC:{self.src_mac}  "
            f"Type:{self.ether_type_str:<22}  "
            f"Len:{self.frame_length:5d}B  "
            f"{self.direction}"
            f"{l3_l4}"
        )


# ===================================================================
# Ethernet フレームのデコード関数群（L2 → L4）
# ===================================================================

def decode_ethernet_frame(frame_data: bytes) -> dict:
    """
    生の Ethernet フレームバイト列を辞書にデコードします。
    L2（MAC・EtherType）→ L3（IPv4/IPv6）→ L4（TCP/UDP）の順に解析します。

    引数:
        frame_data: Ethernet フレームの生バイト列
    戻り値:
        解析結果の辞書（dst_mac, src_mac, ether_type, ip_version, ... など）
    """
    if len(frame_data) < 14:
        return {}  # 14 バイト未満はヘッダすら揃わないので空辞書を返す

    # --- L2: Ethernet ヘッダの解析 ---
    # 構造: 宛先MAC(6B) + 送信元MAC(6B) + EtherType(2B) + ペイロード
    dst_mac       = format_mac(frame_data[0:6])
    src_mac       = format_mac(frame_data[6:12])
    # int.from_bytes(..., "big") は バイト列をビッグエンディアンの整数に変換する
    ethertype_val = int.from_bytes(frame_data[12:14], "big")
    payload       = frame_data[14:]

    parsed = {
        "dst_mac":    dst_mac,
        "src_mac":    src_mac,
        "ether_type": ethertype_val,
    }

    # --- L3: IPv4 / IPv6 の解析 ---
    if ethertype_val == 0x0800:
        parsed.update(decode_ipv4_packet(payload))
    elif ethertype_val == 0x86DD:
        parsed.update(decode_ipv6_packet(payload))

    return parsed


def decode_ipv4_packet(payload: bytes) -> dict:
    """
    IPv4 パケットを解析して IP アドレスとプロトコル情報を返します。

    IPv4 ヘッダ構造（最小 20 バイト）:
        byte 0    : Version(4bit) + IHL(4bit)  ← IHL×4 がヘッダのバイト数
        byte 9    : プロトコル番号（6=TCP, 17=UDP, 1=ICMP）
        bytes12-15: 送信元 IP アドレス（4B）
        bytes16-19: 宛先 IP アドレス（4B）
    """
    if len(payload) < 20:
        return {"ip_version": "IPv4"}

    version = payload[0] >> 4           # 上位 4 ビットがバージョン
    ihl     = (payload[0] & 0x0F) * 4  # 下位 4 ビット × 4 = ヘッダバイト数
    if version != 4 or len(payload) < ihl:
        return {"ip_version": "IPv4"}

    protocol = payload[9]
    # ipaddress モジュールで 4 バイトを IPv4 アドレス文字列に変換
    src_ip   = str(ipaddress.IPv4Address(payload[12:16]))
    dst_ip   = str(ipaddress.IPv4Address(payload[16:20]))

    result = {"ip_version": "IPv4", "src_ip": src_ip, "dst_ip": dst_ip}
    # ヘッダを読み飛ばして L4 を解析
    result.update(decode_transport(protocol, payload[ihl:]))
    return result


def decode_ipv6_packet(payload: bytes) -> dict:
    """
    IPv6 パケットを解析して IP アドレスとプロトコル情報を返します。

    IPv6 ヘッダは固定 40 バイト:
        byte 6    : Next Header（次のプロトコル番号）
        bytes 8-23: 送信元 IP アドレス（16B）
        bytes24-39: 宛先 IP アドレス（16B）
    """
    if len(payload) < 40:
        return {"ip_version": "IPv6"}

    version = payload[0] >> 4
    if version != 6:
        return {"ip_version": "IPv6"}

    next_header = payload[6]
    src_ip      = str(ipaddress.IPv6Address(payload[8:24]))
    dst_ip      = str(ipaddress.IPv6Address(payload[24:40]))

    result = {"ip_version": "IPv6", "src_ip": src_ip, "dst_ip": dst_ip}
    result.update(decode_transport(next_header, payload[40:]))
    return result


def decode_transport(protocol: int, payload: bytes) -> dict:
    """
    IP プロトコル番号に応じて L4（トランスポート層）を解析します。

    引数:
        protocol: IP ヘッダのプロトコル番号（6=TCP, 17=UDP, など）
        payload : L4 以降のバイト列
    """
    if protocol == 6:
        return decode_tcp_segment(payload)
    if protocol == 17:
        return decode_udp_datagram(payload)
    # 上記以外はプロトコル名だけ返す（ICMPv6 など）
    return {"transport_protocol": ip_protocol_name(protocol)}


def decode_tcp_segment(payload: bytes) -> dict:
    """
    TCP セグメントを解析してポート番号とフラグを返します。

    TCP ヘッダ構造（最小 20 バイト）:
        bytes 0-1: 送信元ポート番号
        bytes 2-3: 宛先ポート番号
        byte 13  : フラグバイト（各ビットが FIN/SYN/RST/... に対応）
    """
    if len(payload) < 20:
        return {"transport_protocol": "TCP"}

    flags = payload[13]
    return {
        "transport_protocol": "TCP",
        "src_port":  str(int.from_bytes(payload[0:2], "big")),
        "dst_port":  str(int.from_bytes(payload[2:4], "big")),
        "tcp_flags": decode_tcp_flags(flags),
    }


def decode_udp_datagram(payload: bytes) -> dict:
    """
    UDP データグラムを解析してポート番号を返します。

    UDP ヘッダ構造（固定 8 バイト）:
        bytes 0-1: 送信元ポート番号
        bytes 2-3: 宛先ポート番号
    """
    if len(payload) < 8:
        return {"transport_protocol": "UDP"}
    return {
        "transport_protocol": "UDP",
        "src_port": str(int.from_bytes(payload[0:2], "big")),
        "dst_port": str(int.from_bytes(payload[2:4], "big")),
    }


def decode_tcp_flags(flags: int) -> str:
    """
    TCP フラグのビット値を '|' 区切りの名前文字列に変換します。
    例: 0x12（SYN + ACK）→ "SYN|ACK"
    """
    names = [
        ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
        ("ACK", 0x10), ("URG", 0x20), ("ECE", 0x40), ("CWR", 0x80),
    ]
    # フラグビットが立っている名前だけを '|' で結合する
    return "|".join(name for name, bit in names if flags & bit)


def ip_protocol_name(protocol: int) -> str:
    """IP プロトコル番号を名前文字列に変換します。未知の番号は数値文字列を返します。"""
    return {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(protocol, str(protocol))


# ===================================================================
# タイムスタンプ関連のユーティリティ関数
# ===================================================================

def format_blf_timestamp(base_time: dt.datetime, flags, raw_value: int) -> str:
    """
    BLF の相対時刻を ISO-8601 UTC 絶対時刻文字列に変換します。

    BLF オブジェクトのタイムスタンプ単位はフラグで決まります:
        ObjFlags.TIME_ONE_NANS が立っている → ナノ秒単位
        それ以外                            → 10 マイクロ秒単位
    """
    if flags & ObjFlags.TIME_ONE_NANS:
        # ナノ秒 → マイクロ秒に変換（1ns = 0.001µs）
        delta = dt.timedelta(microseconds=raw_value / 1000)
    else:
        # 10マイクロ秒 → マイクロ秒に変換（1単位 = 10µs）
        delta = dt.timedelta(microseconds=raw_value * 10)
    # 基準時刻 + 経過時間 = 絶対時刻
    return (base_time + delta).isoformat()


def blf_system_time_to_datetime(system_time) -> dt.datetime:
    """
    BLF の SystemTime オブジェクトを Python の datetime に変換します。

    BLF の開始時刻がゼロ埋めの場合は Unix epoch（1970-01-01）にフォールバックします。
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
            tzinfo=dt.timezone.utc,  # UTC として扱う
        )
    except ValueError:
        # 無効な日時（ゼロ埋め等）の場合は Unix epoch を返す
        return dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def format_unix_timestamp(timestamp: float) -> str:
    """
    Unix 時刻（浮動小数点数・秒）を ISO-8601 UTC 文字列に変換します。
    例: 1700000000.123 → "2023-11-14T22:13:20.123000+00:00"
    """
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat()


# ===================================================================
# フォーマットユーティリティ関数
# ===================================================================

def format_mac(data: bytes) -> str:
    """6 バイトの MAC アドレスを 'FF:FF:FF:FF:FF:FF' 形式の文字列に変換します。"""
    return ":".join(f"{b:02X}" for b in data[:6])


def is_valid_ip(value: str) -> bool:
    """文字列が有効な IPv4 / IPv6 アドレスであれば True を返します。"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ===================================================================
# ASC パーサークラス
# ===================================================================
class AscParser:
    """
    ASC（ASCII Log）ファイルを解析するクラスです。

    ・CAN / CAN FD フレーム : python-can の ASCReader を使用
    ・Ethernet フレーム     : 独自の正規表現テキスト解析を使用
      （Ethernet は python-can が非対応のため）

    【ASC フォーマット例】

    Classic CAN:
        0.001234  1  0A0             Rx   d 8 00 11 22 33 44 55 66 77
        ↑タイムスタンプ  ↑CH ↑ID  ↑方向 ↑d ↑DLC ↑データ

    CAN FD:
        0.002000 CANFD  1  Rx  0A0  0  0  9  12  AA BB CC DD ...
        ↑タイムスタンプ ↑CANFD ↑CH ↑方向 ↑ID ↑BRS ↑ESI ↑DLC ↑データ長 ↑データ

    Ethernet:
        0.003000  ETH  1  Rx  60  FF FF FF FF FF FF 00 11 22 33 44 55 08 00 ...
        ↑タイムスタンプ ↑ETH ↑CH ↑方向 ↑長さ ↑生バイト列（宛先MAC から始まる）
    """

    def parse(self, filepath: Path) -> List[Union[CANFrame, EthernetFrame]]:
        """
        ASC ファイルを解析してフレームのリストを返します。

        CAN / CAN FD フレームは python-can で取得し、
        Ethernet フレームは独自のテキスト解析で取得して、
        タイムスタンプ順にマージして返します。
        """
        if not PYTHON_CAN_AVAILABLE:
            print("[ERROR] python-can がインストールされていません。", file=sys.stderr)
            print("        pip install python-can  を実行してください。", file=sys.stderr)
            sys.exit(1)

        # --- CAN / CAN FD フレームの取得（python-can 使用）---
        can_frames: List[CANFrame] = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                reader = ASCReader(f)
                for msg in reader:
                    # msg.is_fd が True なら CAN FD フレーム
                    is_fd = getattr(msg, "is_fd", False)

                    # CAN FD フラグの取得（属性がなければ False）
                    brs = getattr(msg, "bitrate_switch", False)
                    esi = getattr(msg, "error_state_indicator", False)

                    # DLC から実データ長を算出
                    actual_len = fd_dlc_to_len(msg.dlc) if is_fd else min(msg.dlc, 8)

                    # ASC の相対タイムスタンプを絶対時刻に変換
                    abs_time = format_unix_timestamp(msg.timestamp)

                    can_frames.append(CANFrame(
                        timestamp   = msg.timestamp,
                        abs_time    = abs_time,
                        channel     = int(msg.channel) if msg.channel else 1,
                        can_id      = msg.arbitration_id,
                        dlc         = msg.dlc,
                        data        = bytes(msg.data)[:actual_len],
                        direction   = "Tx" if msg.is_tx else "Rx",
                        is_extended = msg.is_extended_id,
                        is_remote   = msg.is_remote_frame,
                        is_error    = msg.is_error_frame,
                        is_fd       = is_fd,
                        brs         = brs,
                        esi         = esi,
                    ))
        except Exception as e:
            print(f"[WARN] CAN 解析中にエラーが発生しました: {e}", file=sys.stderr)

        # --- Ethernet フレームの取得（独自テキスト解析）---
        eth_frames = self._parse_eth(filepath)

        # --- CAN + Ethernet をタイムスタンプ順にマージ ---
        all_frames: List[Union[CANFrame, EthernetFrame]] = can_frames + eth_frames
        all_frames.sort(key=lambda f: f.timestamp)
        return all_frames

    def _parse_eth(self, filepath: Path) -> List[EthernetFrame]:
        """
        ASC ファイルから Ethernet フレームをテキスト解析で取得します。
        ETH キーワードを含む行を正規表現でマッチして解析します。
        """
        frames = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = ETH_RE.match(line)
                    if not m:
                        continue  # ETH 行でなければスキップ

                    # 生バイト列（空白区切り 16 進数）を bytes に変換
                    raw = bytes(int(b, 16) for b in m.group("raw").split() if b)

                    # Ethernet フレームをデコード（L2〜L4）
                    decoded = decode_ethernet_frame(raw)

                    ts = float(m.group("ts"))
                    frames.append(EthernetFrame(
                        timestamp          = ts,
                        abs_time           = format_unix_timestamp(ts),
                        channel            = int(m.group("ch")),
                        dst_mac            = decoded.get("dst_mac", "??:??:??:??:??:??"),
                        src_mac            = decoded.get("src_mac", "??:??:??:??:??:??"),
                        ether_type         = decoded.get("ether_type", 0),
                        frame_length       = int(m.group("len")),
                        direction          = m.group("dir"),
                        ip_version         = decoded.get("ip_version", ""),
                        src_ip             = decoded.get("src_ip", ""),
                        dst_ip             = decoded.get("dst_ip", ""),
                        transport_protocol = decoded.get("transport_protocol", ""),
                        src_port           = decoded.get("src_port", ""),
                        dst_port           = decoded.get("dst_port", ""),
                        tcp_flags          = decoded.get("tcp_flags", ""),
                    ))
        except OSError as e:
            print(f"[ERROR] ファイルを開けません: {e}", file=sys.stderr)
        return frames


# ===================================================================
# BLF パーサークラス
# ===================================================================
class BlfParser:
    """
    BLF（Binary Logging Format）ファイルを解析するクラスです。
    vblf ライブラリを使って CAN / CAN FD / Ethernet をすべて解析します。

    【事前準備】
        pip install vblf
    """

    def parse(self, filepath: Path) -> List[Union[CANFrame, EthernetFrame]]:
        """
        BLF ファイルを解析してフレームのリストを返します。

        vblf の BlfReader でオブジェクトを 1 つずつ取り出し、
        種別に応じて CANFrame / EthernetFrame に変換します。
        """
        if not VBLF_AVAILABLE:
            print("[ERROR] vblf がインストールされていません。", file=sys.stderr)
            print("        pip install vblf  を実行してください。", file=sys.stderr)
            sys.exit(1)

        frames: List[Union[CANFrame, EthernetFrame]] = []

        try:
            with VblfReader(str(filepath)) as reader:
                # BLF の計測開始時刻を取得して絶対時刻変換の基準にする
                base_time = blf_system_time_to_datetime(
                    reader.file_statistics.measurement_start_time
                )

                for obj in reader:
                    # --- Classic CAN フレーム ---
                    if isinstance(obj, (CanMessage, CanMessage2)):
                        f = self._build_can(obj, is_fd=False, base_time=base_time)
                        if f:
                            frames.append(f)

                    # --- CAN FD フレーム ---
                    # CanFdMessage   : データ長 8B 以下
                    # CanFdMessage64 : データ長 最大 64B
                    elif isinstance(obj, (CanFdMessage, CanFdMessage64)):
                        f = self._build_can(obj, is_fd=True, base_time=base_time)
                        if f:
                            frames.append(f)

                    # --- Ethernet フレーム ---
                    elif isinstance(obj, EthernetFrameEx):
                        f = self._build_eth(obj, base_time=base_time)
                        if f:
                            frames.append(f)

        except Exception as e:
            print(f"[ERROR] BLF 解析中にエラーが発生しました: {e}", file=sys.stderr)

        return frames

    def _build_can(self, obj, is_fd: bool, base_time: dt.datetime) -> Optional[CANFrame]:
        """
        vblf の CAN / CAN FD オブジェクトから CANFrame を生成します。
        失敗した場合は None を返します。
        """
        try:
            # BLF の相対タイムスタンプを絶対時刻に変換
            abs_time = format_blf_timestamp(
                base_time,
                obj.header.object_flags,
                obj.header.object_time_stamp
            )
            # 相対時刻（秒）も保持しておく（ソートに使う）
            ts = obj.header.object_time_stamp * 1e-7

            # CAN ID の取得と拡張フレーム判定
            # vblf では 29bit 拡張 ID の場合、MSB（最上位ビット: bit31）が立っている
            raw_id      = obj.id if hasattr(obj, "id") else obj.arb_id
            is_extended = bool(raw_id & 0x80000000)  # MSB が 1 なら拡張 ID
            can_id      = raw_id & 0x1FFFFFFF         # 下位 29 ビットが実際の ID

            dlc     = obj.dlc
            data    = bytes(obj.data) if obj.data else b""
            channel = getattr(obj, "channel", 1) or 1

            # flags ビットの意味:
            #   bit2 (0x04): Tx フレーム
            #   bit4 (0x10): RTR フレーム
            flags     = getattr(obj, "flags", 0)
            is_remote = bool(flags & 0x10)
            is_tx     = bool(flags & 0x04)

            # CAN FD フラグの取得
            brs = bool(getattr(obj, "brs_bit", 0))
            esi = bool(getattr(obj, "esi_bit", 0))

            actual_len = fd_dlc_to_len(dlc) if is_fd else min(dlc, 8)

            return CANFrame(
                timestamp   = ts,
                abs_time    = abs_time,
                channel     = channel,
                can_id      = can_id,
                dlc         = dlc,
                data        = data[:actual_len],
                direction   = "Tx" if is_tx else "Rx",
                is_extended = is_extended,
                is_remote   = is_remote,
                is_fd       = is_fd,
                brs         = brs,
                esi         = esi,
            )
        except Exception as e:
            print(f"[WARN] CAN フレームのデコードに失敗しました: {e}", file=sys.stderr)
            return None

    def _build_eth(self, obj, base_time: dt.datetime) -> Optional[EthernetFrame]:
        """
        vblf の EthernetFrameEx オブジェクトから EthernetFrame を生成します。
        失敗した場合は None を返します。
        """
        try:
            abs_time = format_blf_timestamp(
                base_time,
                obj.header.object_flags,
                obj.header.object_time_stamp
            )
            ts      = obj.header.object_time_stamp * 1e-7
            channel = getattr(obj, "channel", 1) or 1

            # frame_data から L2〜L4 をデコード
            raw     = bytes(obj.frame_data) if hasattr(obj, "frame_data") else b""
            decoded = decode_ethernet_frame(raw)

            frame_length  = getattr(obj, "frame_length", len(raw))
            direction_val = getattr(obj, "direction", 1)
            direction     = "Tx" if direction_val == 0 else "Rx"

            return EthernetFrame(
                timestamp          = ts,
                abs_time           = abs_time,
                channel            = channel,
                dst_mac            = decoded.get("dst_mac", "??:??:??:??:??:??"),
                src_mac            = decoded.get("src_mac", "??:??:??:??:??:??"),
                ether_type         = decoded.get("ether_type", 0),
                frame_length       = frame_length,
                direction          = direction,
                ip_version         = decoded.get("ip_version", ""),
                src_ip             = decoded.get("src_ip", ""),
                dst_ip             = decoded.get("dst_ip", ""),
                transport_protocol = decoded.get("transport_protocol", ""),
                src_port           = decoded.get("src_port", ""),
                dst_port           = decoded.get("dst_port", ""),
                tcp_flags          = decoded.get("tcp_flags", ""),
            )
        except Exception as e:
            print(f"[WARN] Ethernet フレームのデコードに失敗しました: {e}", file=sys.stderr)
            return None


# ===================================================================
# 統計サマリー表示関数
# ===================================================================
def print_summary(frames: List[Union[CANFrame, EthernetFrame]]) -> None:
    """
    解析したフレームの統計情報をコンソールに表示します。

    表示内容:
        - 総フレーム数 / CAN / CAN FD / Ethernet の内訳
        - 記録時間（最初〜最後のタイムスタンプ差）
        - CAN チャンネル別フレーム数（Rx/Tx 内訳）
        - CAN ID 出現回数 Top 10
        - CAN FD フラグ（BRS / ESI）統計
        - Ethernet EtherType 別フレーム数（L3/L4 情報付き）
    """
    can_frames = [f for f in frames if isinstance(f, CANFrame) and not f.is_fd]
    fd_frames  = [f for f in frames if isinstance(f, CANFrame) and f.is_fd]
    eth_frames = [f for f in frames if isinstance(f, EthernetFrame)]
    sep = "=" * 74

    print(f"\n{sep}")
    print("  解析サマリー")
    print(sep)
    print(f"  総フレーム数              : {len(frames):>8,}")
    print(f"  Classic CAN フレーム数    : {len(can_frames):>8,}")
    print(f"  CAN FD フレーム数         : {len(fd_frames):>8,}")
    print(f"  Ethernet フレーム数       : {len(eth_frames):>8,}")

    if frames:
        ts_list  = [f.timestamp for f in frames]
        duration = max(ts_list) - min(ts_list)
        # 絶対時刻があれば先頭フレームの絶対時刻も表示する
        first_abs = frames[0].abs_time if frames[0].abs_time else "（不明）"
        print(f"  記録開始（絶対時刻）      : {first_abs}")
        print(f"  記録時間                  : {duration:>14.6f} s")

    # ---- CAN / CAN FD 統計 ----
    all_can = can_frames + fd_frames
    if all_can:
        print(f"\n  {'─' * 34}")
        print("  [CAN / CAN FD チャンネル別フレーム数]")
        print(f"  {'CH':>4}  {'Classic CAN':>12}  {'CAN FD':>8}  {'Rx':>8}  {'Tx':>8}")

        ch_stats: dict = {}
        for f in all_can:
            s = ch_stats.setdefault(f.channel, {"can": 0, "fd": 0, "rx": 0, "tx": 0})
            s["fd" if f.is_fd else "can"] += 1
            s["rx" if f.direction == "Rx" else "tx"] += 1

        for ch in sorted(ch_stats):
            s = ch_stats[ch]
            print(f"  {ch:>4}  {s['can']:>12,}  {s['fd']:>8,}  {s['rx']:>8,}  {s['tx']:>8,}")

        print(f"\n  [CAN ID 出現回数 Top 10（CAN + CAN FD 合算）]")
        print(f"  {'CAN ID':<14}  {'出現回数':>8}  {'FD':>5}  {'平均DLC':>8}")

        id_stats: dict = {}
        for f in all_can:
            key = (f.can_id_str, f.is_extended)
            s   = id_stats.setdefault(key, {"count": 0, "fd": 0, "dlc_sum": 0})
            s["count"]   += 1
            s["dlc_sum"] += f.dlc
            if f.is_fd:
                s["fd"] += 1

        top10 = sorted(id_stats.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
        for (id_str, is_ext), s in top10:
            ext_mark = "(X)" if is_ext else "   "
            avg_dlc  = s["dlc_sum"] / s["count"]
            fd_mark  = "Yes" if s["fd"] > 0 else "-"
            print(f"  0x{id_str}{ext_mark}  {s['count']:>8,}  {fd_mark:>5}  {avg_dlc:>8.1f}")

        if fd_frames:
            brs_cnt = sum(1 for f in fd_frames if f.brs)
            esi_cnt = sum(1 for f in fd_frames if f.esi)
            print(f"\n  [CAN FD フラグ統計]")
            print(f"  BRS（Bit Rate Switch）あり : {brs_cnt:>8,}")
            print(f"  ESI（Error State）あり     : {esi_cnt:>8,}")

        err_cnt = sum(1 for f in all_can if f.is_error)
        if err_cnt:
            print(f"\n  ⚠ エラーフレーム検出: {err_cnt:,} 件")

    # ---- Ethernet 統計 ----
    if eth_frames:
        print(f"\n  {'─' * 34}")
        print("  [Ethernet EtherType 別フレーム数]")
        print(f"  {'EtherType':<24}  {'フレーム数':>8}  {'IPv4':>6}  {'IPv6':>6}  {'TCP':>6}  {'UDP':>6}")

        et_stats: dict = {}
        for f in eth_frames:
            label = ETHER_TYPE_NAMES.get(f.ether_type, "Unknown")
            key   = f"0x{f.ether_type:04X}({label})"
            s     = et_stats.setdefault(key, {"count": 0, "ipv4": 0, "ipv6": 0, "tcp": 0, "udp": 0})
            s["count"] += 1
            if f.ip_version == "IPv4": s["ipv4"] += 1
            if f.ip_version == "IPv6": s["ipv6"] += 1
            if f.transport_protocol == "TCP": s["tcp"] += 1
            if f.transport_protocol == "UDP": s["udp"] += 1

        for et_str, s in sorted(et_stats.items(), key=lambda x: x[1]["count"], reverse=True):
            print(
                f"  {et_str:<24}  {s['count']:>8,}  "
                f"{s['ipv4']:>6,}  {s['ipv6']:>6,}  {s['tcp']:>6,}  {s['udp']:>6,}"
            )

    print(f"{sep}\n")


# ===================================================================
# メイン処理（プログラムの開始点）
# ===================================================================
def main() -> None:
    """
    コマンドライン引数としてファイルパスを 1 つ受け取り、解析を実行します。

    使い方:
        python canoe_log_parser.py <ファイルパス>
    """

    # sys.argv はコマンドライン引数のリストです。
    # sys.argv[0] = スクリプト名、sys.argv[1] = 最初の引数（ファイルパス）
    if len(sys.argv) != 2:
        print("使い方: python canoe_log_parser.py <ファイルパス>")
        print("例:     python canoe_log_parser.py log.asc")
        print("        python canoe_log_parser.py log.blf")
        sys.exit(1)

    filepath = Path(sys.argv[1])  # Path クラスで OS の違いを吸収

    if not filepath.exists():
        print(f"[ERROR] ファイルが見つかりません: {filepath}", file=sys.stderr)
        sys.exit(1)

    suffix = filepath.suffix.lower()  # 拡張子を小文字に統一

    # ヘッダ表示
    print(f"\n{'=' * 74}")
    print(f"  CANoe Log Parser  （CAN / CAN FD / Ethernet 対応）")
    print(f"  ファイル : {filepath}")
    print(f"  形式     : {suffix.lstrip('.')}")
    print(f"{'=' * 74}\n")

    # 拡張子に応じてパーサーを選択する
    if suffix == ".asc":
        parser_obj = AscParser()   # ASC 用（python-can + 独自実装）
    elif suffix == ".blf":
        parser_obj = BlfParser()   # BLF 用（vblf のみ）
    else:
        print(f"[ERROR] 未対応の拡張子: {suffix}（.asc または .blf を指定してください）",
              file=sys.stderr)
        sys.exit(1)

    # 解析実行
    print("[INFO] 解析中...")
    frames = parser_obj.parse(filepath)

    # 種別カウントを表示
    can_cnt = sum(1 for f in frames if isinstance(f, CANFrame) and not f.is_fd)
    fd_cnt  = sum(1 for f in frames if isinstance(f, CANFrame) and f.is_fd)
    eth_cnt = sum(1 for f in frames if isinstance(f, EthernetFrame))
    print(f"[INFO] 解析完了: 総 {len(frames):,} フレーム "
          f"（CAN: {can_cnt:,} / CAN FD: {fd_cnt:,} / ETH: {eth_cnt:,}）\n")

    # フレーム一覧表示
    sep_line = "-" * 140
    print(sep_line)
    print(f"  {'絶対時刻 / 相対時刻':<32}  {'種別':<5}  {'CH':>2}  {'詳細'}")
    print(sep_line)
    for frame in frames:
        # CANFrame / EthernetFrame の __str__ メソッドで整形表示される
        print(f"  {frame}")

    # 統計サマリー表示
    print_summary(frames)


# ===================================================================
# スクリプトとして直接実行されたときだけ main() を呼ぶ
# ===================================================================
# 他のファイルから import されたときは main() を実行しない
if __name__ == "__main__":
    main()
