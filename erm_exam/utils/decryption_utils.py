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


def _get_param_stem_from_name(name: str | None) -> str | None:
    if not name:
        return None
    return Path(name.replace("\\", "/")).stem


def _rows_to_csv(csv_path: Path, rows: dict) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["row_id"])
        return

    field_names = {"row_id"}
    for row_data in rows.values():
        field_names.update(row_data.keys())
    ordered_fields = ["row_id"] + sorted([f for f in field_names if f != "row_id"])

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered_fields)
        writer.writeheader()
        for row_id in sorted(rows):
            row_record = {"row_id": row_id}
            row_record.update(rows[row_id])
            writer.writerow(row_record)


def _read_null_terminated_string(data: bytes, offset: int, encoding: str) -> str:
    if offset == 0:
        return ""
    if encoding.startswith("utf-16"):
        terminator = -1
        for i in range(offset, len(data) - 1, 2):
            if data[i:i+2] == b"\x00\x00":
                terminator = i
                break
        if terminator == -1:
            terminator = len(data)
        raw = data[offset:terminator]
    else:
        terminator = data.find(b"\x00", offset)
        if terminator == -1:
            terminator = len(data)
        raw = data[offset:terminator]
    return raw.decode(encoding, errors="replace")


def _parse_param_rows_minimal(param_data: bytes) -> dict[int, dict]:
    if len(param_data) < 0x30:
        return {}

    big_endian = param_data[0x2C] == 0xFF
    endian = ">" if big_endian else "<"
    flags1 = param_data[0x2D]
    flags2 = param_data[0x2E]
    row_count = struct.unpack_from(f"{endian}H", param_data, 0x0A)[0]

    long_data_offset = bool(flags1 & 0x04)
    unicode_row_names = bool(flags2 & 0x01)
    row_name_encoding = "utf-16-be" if (unicode_row_names and big_endian) else (
        "utf-16-le" if unicode_row_names else "shift_jis_2004"
    )

    header_size = 0x40 if long_data_offset else 0x30
    if len(param_data) < header_size:
        return {}

    row_struct_size = 24 if long_data_offset else 12
    pointer_table_offset = header_size

    pointers: list[tuple[int, int, int]] = []
    for i in range(row_count):
        row_ptr_offset = pointer_table_offset + i * row_struct_size
        if row_ptr_offset + row_struct_size > len(param_data):
            break
        if long_data_offset:
            row_id = struct.unpack_from(f"{endian}i", param_data, row_ptr_offset)[0]
            data_offset = struct.unpack_from(f"{endian}q", param_data, row_ptr_offset + 8)[0]
            name_offset = struct.unpack_from(f"{endian}q", param_data, row_ptr_offset + 16)[0]
        else:
            row_id = struct.unpack_from(f"{endian}i", param_data, row_ptr_offset)[0]
            data_offset = struct.unpack_from(f"{endian}I", param_data, row_ptr_offset + 4)[0]
            name_offset = struct.unpack_from(f"{endian}I", param_data, row_ptr_offset + 8)[0]
        pointers.append((row_id, data_offset, name_offset))

    if not pointers:
        return {}

    if len(pointers) > 1:
        row_size = max(0, pointers[1][1] - pointers[0][1])
    else:
        row_size = max(0, len(param_data) - pointers[0][1])

    rows: dict[int, dict] = {}
    for row_id, data_offset, name_offset in pointers:
        if data_offset < 0 or data_offset >= len(param_data):
            row_bytes = b""
        else:
            end = min(len(param_data), data_offset + row_size)
            row_bytes = param_data[data_offset:end]
        rows[row_id] = {
            "name": _read_null_terminated_string(param_data, name_offset, row_name_encoding) if name_offset else "",
            "row_data_hex": row_bytes.hex(),
        }
    return rows


class EldenRingRegulationDecoder():

    def __init__(self, regulation_bin_path: str|Path):
        self.regulation_bin_path = Path(regulation_bin_path).absolute()    

    
    def get_param_names(self) -> list:
        pass

    def reset(self):
        pass
