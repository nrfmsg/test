#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
blf2asc.py — Vector CANoe BLF → ASC 変換ツール (CAN / CAN FD / Ethernet 対応)

依存ライブラリ:
    python-can (LGPL-3.0)  ※import利用のため商用利用可
        pip install python-can

使い方:
    python blf2asc.py input.blf                # → input.asc
    python blf2asc.py input.blf -o out.asc

設計:
- CAN / CAN FD / CANエラーフレーム:
    python-can の BLFReader で読み取り、ASCWriter で CANoe互換のASC行を出力。
- Ethernet (BLFオブジェクト型 71 / 120 / 124):
    python-can は Ethernet を読み飛ばすため、本スクリプト独自の
    BLFパーサ(struct/zlibのみ使用)で抽出し、ASCに "ETH" 行として出力。
    ※ Vector の ASC Ethernet 行の正式仕様は非公開のため、
      format_eth_line() を環境のCANoe出力に合わせて調整できる構成にしている。
- 両ストリームをタイムスタンプでマージし、時系列順に1つのASCへ書き込む。
"""

import argparse
import heapq
import struct
import sys
import zlib
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional

import can
from can.io.asc import ASCWriter

# ---------------------------------------------------------------------------
# BLF フォーマット定義 (Vector Binary Logging Format)
# ---------------------------------------------------------------------------
FILE_HEADER = struct.Struct("<4sLBBBBBBBBQQLL8H8H")  # 先頭144バイト中の有効部
OBJ_BASE = struct.Struct("<4sHHLL")    # signature, headerSize, headerVersion, objectSize, objectType
OBJ_V1 = struct.Struct("<LHHQ")        # objectFlags, clientIndex, objectVersion, objectTimeStamp
OBJ_V2 = struct.Struct("<LBxHQ8x")     # objectFlags, timeStampStatus, objectVersion, objectTimeStamp
CONTAINER = struct.Struct("<H6xL4x")   # compressionMethod, uncompressedSize

LOG_CONTAINER = 10
ETHERNET_FRAME = 71            # ペイロードのみ保持(ヘッダ情報はフィールド)
ETHERNET_FRAME_EX = 120        # 完全フレーム保持
ETHERNET_FRAME_FORWARDED = 124 # 完全フレーム保持 (転送フレーム)
ETHERNET_TYPES = (ETHERNET_FRAME, ETHERNET_FRAME_EX, ETHERNET_FRAME_FORWARDED)

TIME_TEN_MICS = 0x01   # タイムスタンプ単位 10µs
TIME_ONE_NANS = 0x02   # タイムスタンプ単位 1ns
ZLIB_DEFLATE = 2

# ETHERNET_FRAME(71) 本体: src(6) ch(u16) dst(6) dir(u16) type(u16) tpid(u16) tci(u16) payloadLen(u16) reserved(8)
ETH_FRAME_STRUCT = struct.Struct("<6sH6sHHHHH8x")
# ETHERNET_FRAME_EX/FORWARDED 本体: structLen flags ch hwCh frameDuration frameChecksum dir frameLen frameHandle reserved
ETH_FRAME_EX_STRUCT = struct.Struct("<HHHHQLHHL4x")

DIR_STR = {0: "Rx", 1: "Tx", 2: "TxRq"}


@dataclass
class EthFrame:
    timestamp: float   # 絶対時刻 (epoch秒)
    channel: int
    direction: str
    data: bytes        # MACヘッダを含む完全なEthernetフレーム


# ---------------------------------------------------------------------------
# Ethernet 抽出用 BLF パーサ (独自実装)
# ---------------------------------------------------------------------------
def _systemtime_to_epoch(st: tuple) -> float:
    """SYSTEMTIME(year,month,dow,day,hour,min,sec,ms) → epoch秒"""
    try:
        return datetime(
            st[0], st[1], st[3], st[4], st[5], st[6], st[7] * 1000
        ).timestamp()
    except ValueError:
        return 0.0


def _parse_eth_object(obj_type: int, header_version: int,
                      obj: memoryview, header_size: int,
                      start_ts: float) -> Optional[EthFrame]:
    """1オブジェクト(LOBJ先頭からのバイト列)からEthernetフレームを抽出"""
    # オブジェクトヘッダ(タイムスタンプ)
    if header_version == 1:
        flags, _, _, ts_raw = OBJ_V1.unpack_from(obj, OBJ_BASE.size)
    else:
        flags, _, _, ts_raw = OBJ_V2.unpack_from(obj, OBJ_BASE.size)
    factor = 1e-5 if flags == TIME_TEN_MICS else 1e-9
    timestamp = start_ts + ts_raw * factor

    body = obj[header_size:]

    if obj_type == ETHERNET_FRAME:
        src, ch, dst, dir_, eth_type, tpid, tci, plen = ETH_FRAME_STRUCT.unpack_from(body)
        payload = bytes(body[ETH_FRAME_STRUCT.size: ETH_FRAME_STRUCT.size + plen])
        if tpid:  # VLANタグ付き
            frame = bytes(dst) + bytes(src) + struct.pack(">HHH", tpid, tci, eth_type) + payload
        else:
            frame = bytes(dst) + bytes(src) + struct.pack(">H", eth_type) + payload
        return EthFrame(timestamp, ch, DIR_STR.get(dir_, "Rx"), frame)

    # ETHERNET_FRAME_EX / FORWARDED: 完全フレームをそのまま保持
    (_, _, ch, _, _, _, dir_, flen, _) = ETH_FRAME_EX_STRUCT.unpack_from(body)
    frame = bytes(body[ETH_FRAME_EX_STRUCT.size: ETH_FRAME_EX_STRUCT.size + flen])
    return EthFrame(timestamp, ch, DIR_STR.get(dir_, "Rx"), frame)


def iter_ethernet(path: str) -> Iterator[EthFrame]:
    """BLFファイルからEthernetフレームのみを時系列(ファイル順)で取り出す"""
    with open(path, "rb") as f:
        header = FILE_HEADER.unpack(f.read(FILE_HEADER.size))
        if header[0] != b"LOGG":
            raise ValueError(f"{path}: BLFファイルではありません")
        header_size = header[1]
        start_ts = _systemtime_to_epoch(header[14:22])
        f.read(header_size - FILE_HEADER.size)  # ヘッダ残りを読み飛ばし

        buf = bytearray()  # コンテナ展開後のオブジェクトストリーム

        def parse_buffer() -> Iterator[EthFrame]:
            """bufから完結したオブジェクトを順次パースし、未完部分はbufに残す。
            オブジェクト間のパディングは「次のLOBJ署名を8バイト以内で探す」
            方式でスキップする(python-can BLFReaderと同じ手法)。"""
            pos = 0
            while True:
                idx = buf.find(b"LOBJ", pos, pos + 8)
                if idx < 0:
                    if pos + 8 > len(buf):
                        break  # データ不足 → 次コンテナを待つ
                    raise ValueError("BLF構造が壊れています (LOBJ署名が見つかりません)")
                pos = idx
                if len(buf) - pos < OBJ_BASE.size:
                    break
                _, hdr_size, hdr_ver, obj_size, obj_type = OBJ_BASE.unpack_from(buf, pos)
                if len(buf) - pos < obj_size:
                    break  # オブジェクト未完 → 次コンテナを待つ
                if obj_type in ETHERNET_TYPES:
                    frame = _parse_eth_object(
                        obj_type, hdr_ver,
                        memoryview(buf)[pos:pos + obj_size], hdr_size, start_ts,
                    )
                    if frame:
                        yield frame
                pos += obj_size
            del buf[:pos]

        # トップレベルオブジェクトの走査
        while True:
            base = f.read(OBJ_BASE.size)
            if len(base) < OBJ_BASE.size:
                break
            sig, hdr_size, hdr_ver, obj_size, obj_type = OBJ_BASE.unpack(base)
            if sig != b"LOBJ":
                break
            rest = f.read(obj_size - OBJ_BASE.size)
            f.read(obj_size % 4)  # パディング

            if obj_type == LOG_CONTAINER:
                method, _ = CONTAINER.unpack_from(rest)
                payload = rest[CONTAINER.size:]
                buf += zlib.decompress(payload) if method == ZLIB_DEFLATE else payload
                yield from parse_buffer()
            elif obj_type in ETHERNET_TYPES:
                # コンテナ外に直接置かれたオブジェクト
                frame = _parse_eth_object(
                    obj_type, hdr_ver, memoryview(base + rest), hdr_size, start_ts
                )
                if frame:
                    yield frame


# ---------------------------------------------------------------------------
# ASC 出力
# ---------------------------------------------------------------------------
def format_eth_line(eth: EthFrame) -> str:
    """
    Ethernetフレーム1件分のASC行(タイムスタンプ以降)を生成する。

    注意: VectorはASCのEthernet行仕様を公開していないため、ここでは
    「ETH <ch> <dir> <バイト長> <フレーム全体のhex>」形式で出力する。
    手元のCANoeでBLF→ASC変換した実ファイルと比較し、必要に応じて
    この関数だけを書き換えれば全体に反映される。
    """
    hex_bytes = " ".join(f"{b:02X}" for b in eth.data)
    return f"ETH {eth.channel} {eth.direction} {len(eth.data)} {hex_bytes}"


def convert(blf_path: str, asc_path: str) -> dict:
    stats = {"can": 0, "canfd": 0, "error": 0, "eth": 0}

    def can_stream():
        with can.BLFReader(blf_path) as reader:
            for msg in reader:
                yield (msg.timestamp, 0, msg)

    def eth_stream():
        for eth in iter_ethernet(blf_path):
            yield (eth.timestamp, 1, eth)

    with ASCWriter(asc_path) as writer:
        for ts, kind, obj in heapq.merge(can_stream(), eth_stream(),
                                         key=lambda t: t[0]):
            if kind == 0:  # CAN / CAN FD / Error frame
                writer.on_message_received(obj)
                if obj.is_error_frame:
                    stats["error"] += 1
                elif obj.is_fd:
                    stats["canfd"] += 1
                else:
                    stats["can"] += 1
            else:          # Ethernet
                writer.log_event(format_eth_line(obj), ts)
                stats["eth"] += 1
    return stats


def main() -> int:
    p = argparse.ArgumentParser(
        description="Vector BLF → ASC 変換 (CAN / CAN FD / Ethernet)")
    p.add_argument("input", help="入力BLFファイル")
    p.add_argument("-o", "--output", help="出力ASCファイル (省略時: 入力名.asc)")
    args = p.parse_args()

    out = args.output or (args.input.rsplit(".", 1)[0] + ".asc")
    stats = convert(args.input, out)
    print(f"変換完了: {out}")
    print(f"  CAN:      {stats['can']:>8} frames")
    print(f"  CAN FD:   {stats['canfd']:>8} frames")
    print(f"  CANエラー: {stats['error']:>8} frames")
    print(f"  Ethernet: {stats['eth']:>8} frames")
    return 0


if __name__ == "__main__":
    sys.exit(main())
