"""
Docstring for erm_exam.utils.decryption_utils
"""

import csv
import io
import struct
from pathlib import Path

import zstandard as zstd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

ER_REGULATION_KEY = bytes([
    0x99, 0xBF, 0xFC, 0x36, 0x6A, 0x6B, 0xC8, 0xC6,
    0xF5, 0x82, 0x7D, 0x09, 0x36, 0x02, 0xD6, 0x76,
    0xC4, 0x28, 0x92, 0xA0, 0x1C, 0x20, 0x7F, 0xB0,
    0x24, 0xD3, 0xAF, 0x4E, 0x49, 0x3F, 0xEF, 0x99
])


def _reverse_byte_bits(byte_value: int) -> int:
    return int(f"{byte_value:08b}"[::-1], 2)


def _parse_binder_flags(raw_flags: int, bit_little_endian: bool) -> int:
    """Mirror `BinderFlags.from_byte()` behavior used by SoulsStruct for BND4."""
    flags = raw_flags
    bit_big_endian = not bit_little_endian
    is_big_endian = bool(flags & 0b0000_0001)
    has_flag_7 = bool(flags & 0b1000_0000)
    if not bit_big_endian and not (is_big_endian and not has_flag_7):
        flags = _reverse_byte_bits(flags)
    return flags


def _parse_entry_flags(raw_flags: int, bit_little_endian: bool) -> int:
    """Mirror `BinderEntryFlags.from_byte()` behavior used by SoulsStruct for BND4 entries."""
    bit_big_endian = not bit_little_endian
    return raw_flags if bit_big_endian else _reverse_byte_bits(raw_flags)


def _read_cstring(data: bytes, start: int, encoding: str) -> str:
    if encoding == "utf-16-le":
        terminator_index = -1
        for i in range(start, len(data) - 1, 2):
            if data[i:i+2] == b"\x00\x00":
                terminator_index = i
                break
        if terminator_index == -1:
            raise ValueError(f"Unterminated UTF-16 string at offset {start}")
        raw = data[start:terminator_index]
    else:
        terminator_index = data.find(b"\x00", start)
        if terminator_index == -1:
            raise ValueError(f"Unterminated Shift-JIS string at offset {start}")
        raw = data[start:terminator_index]
    return raw.decode(encoding, errors="replace")


def decrypt_aes_layer(reg_path: str|Path):
    
    reg_path = Path(reg_path)

    # -----------------------
    # 1. Read encrypted file
    # -----------------------
    with open(reg_path, "rb") as f:
        encrypted = f.read()

    # -----------------------
    # 2. AES-256-CBC decrypt
    # -----------------------
    iv = encrypted[:16]
    encrypted_content = encrypted[16:]

    # Match SoulsFormats behavior:
    # pad to 16-byte boundary BEFORE decrypting
    remainder = len(encrypted_content) % 16
    if remainder != 0:
        encrypted_content += b"\x00" * (16 - remainder)

    cipher = AES.new(ER_REGULATION_KEY, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_content)

    assert decrypted[0:4] == b"DCX\x00", "Not a DCX file"

    return decrypted


class EldenRingRegulationDecoder():

    def __init__(self, regulation_bin_path: str|Path):
        self.regulation_bin_path = Path(regulation_bin_path).absolute()    

    
    def get_param_names(self) -> list:
        pass

    def reset(self):
        pass
