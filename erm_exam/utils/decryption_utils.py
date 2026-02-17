"""
Docstring for erm_exam.utils.decryption_utils
"""

import csv
import io
import struct
from pathlib import Path
from tqdm import tqdm

import zstandard as zstd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from loguru import logger

BLOCK_SIZE = 16

ER_REGULATION_KEY = bytes([
    0x99, 0xBF, 0xFC, 0x36, 0x6A, 0x6B, 0xC8, 0xC6,
    0xF5, 0x82, 0x7D, 0x09, 0x36, 0x02, 0xD6, 0x76,
    0xC4, 0x28, 0x92, 0xA0, 0x1C, 0x20, 0x7F, 0xB0,
    0x24, 0xD3, 0xAF, 0x4E, 0x49, 0x3F, 0xEF, 0x99
])


def extract_params_from_elden_ring_regulation_binary(reg_path: str|Path) -> dict:
    """
    Docstring for extract_elden_ring_regulation_binary
    
    :param reg_path: Description
    :type reg_path: str | Path
    :return: Description
    :rtype: dict
    """

    # 1. Decrypt Advanced Encryption Standard (AES) layer from regulation.bin
    with open(reg_path, "rb") as f:
        encrypted = f.read()

    logger.info("Step 1 / 10: Starting AES layer decryption")
    iv = encrypted[:16]
    encrypted_content = encrypted[16:]

    # Match SoulsFormats behavior:
    # pad to 16-byte boundary BEFORE decrypting
    remainder = len(encrypted_content) % 16
    if remainder != 0:
        encrypted_content += b"\x00" * (16 - remainder)

    cipher = AES.new(ER_REGULATION_KEY, AES.MODE_CBC, iv)
    dcx_bytes = cipher.decrypt(encrypted_content)

    if dcx_bytes[:4] != b"DCX\x00":
        raise ValueError("Missing DCX block")
    # 2. Parse DCX header
    logger.info("Step 2 / 10: Parsing DCX header")

    offset = 4

    version1 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    unk1 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    unk2 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    version2 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    version3 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    # 3. Parse DCS block
    logger.info("Step 3 / 10: Parsing DCS header")
    dcs_magic = dcx_bytes[offset:offset+4]; offset += 4
    if dcs_magic != b"DCS\x00":
        raise ValueError("Missing DCS block")
    
    decompressed_size = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    compressed_size = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    # 4. Parse DCP block substructures inside DCX
    logger.info("Step 4 / 10: Parsing DCP header")
    dcp_magic = dcx_bytes[offset:offset+4]; offset += 4
    if dcp_magic != b"DCP\x00":
        raise ValueError("Missing DCP block")
    
    compression_type = dcx_bytes[offset:offset+4]; offset += 4
    unk3 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4

    compression_level = dcx_bytes[offset]
    offset += 1
    offset += 3  # padding

    version5 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    version6 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    unk5 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    version7 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    # 5. Parse DCA block substructures inside DCX
    logger.info("Step 5 / 10: Parsing DCA header")
    dca_magic = dcx_bytes[offset:offset+4]; offset += 4
    if dca_magic != b"DCA\x00":
        raise ValueError("Missing DCA block")

    dca_size = struct.unpack_from(">I", dcx_bytes, offset)[0]
    offset += 4
    # DO NOT skip dca_size bytes here.
    # ZSTD frame begins immediately after the size field.
    """
    DCS	Decompression size metadata
    DCP	Compression type metadata
    DCA	Compression parameters block
    DCB	Block-based compression metadata (rare / older)
    """
    print(dcx_bytes[offset:offset+4].hex())

    print("version1:", hex(version1))
    print("version2:", hex(version2))
    print("version3:", hex(version3))
    print("compression_type:", compression_type)
    print("decompressed_size:", decompressed_size)
    print("compressed_size:", compressed_size)
    print("compression_level:", compression_level)

    # 6. Extract compressed payload
    logger.info("Step 6 / 10: Extracting compressed payload")
    remaining = len(dcx_bytes) - offset
    if remaining < compressed_size:
        raise ValueError("Not enough bytes for compressed payload")

    compressed_data = dcx_bytes[offset : offset + compressed_size]

    # 7. Decompress ZSTD payload
    logger.info("Step 7 / 10: Decompressing ZSTD payload")
    dctx = zstd.ZstdDecompressor()
    with dctx.stream_reader(io.BytesIO(compressed_data)) as r:
        decompressed_data = r.read()  # read() until EOF
    # zstandard.backend_c.ZstdError: could not determine content size in frame header
    # decompressed_data = dctx.decompress(compressed_data)
    # 8. Validate decompressed size
    logger.info("Step 8 / 10: Validating decompressed size")
    if len(decompressed_data) != decompressed_size:
        raise ValueError(
            f"Size mismatch: expected {decompressed_size}, got {len(decompressed_data)}"
            "Decompressed DCX data size does not match size in header"
        )

    # 9. Parse BND4 header
    logger.info("Step 9 / 10: Parsing BND4 header")
    print("Total archive size:", len(decompressed_data))
    offset = 0

    magic = decompressed_data[offset:offset+4]; offset += 4
    if magic != b'BND4':
        raise ValueError("Not a BND4 archive")

    print("BND magic:", magic)

    # SoulsStruct checks byte index 9 to determine BND4 byte order.
    bit_little_endian = bool(decompressed_data[10])
    endian = "<" if bit_little_endian else ">"

    unknown1 = bool(decompressed_data[4])
    unknown2 = bool(decompressed_data[5])
    big_endian = bool(decompressed_data[9])
    file_count = struct.unpack_from(f"{endian}i", decompressed_data, 12)[0]
    header_size = struct.unpack_from(f"{endian}q", decompressed_data, 16)[0]
    signature = decompressed_data[24:32].rstrip(b"\x00").decode("ascii", errors="replace")
    entry_header_size = struct.unpack_from(f"{endian}q", decompressed_data, 32)[0]
    data_offset = struct.unpack_from(f"{endian}q", decompressed_data, 40)[0]
    unicode_names = bool(decompressed_data[48])
    raw_binder_flags = decompressed_data[49]
    hash_table_type = decompressed_data[50]
    hash_table_offset = struct.unpack_from(f"{endian}q", decompressed_data, 56)[0]

    binder_flags = _parse_binder_flags(raw_binder_flags, bit_little_endian)
    has_ids = bool(binder_flags & 0b0000_0010)
    has_names_1 = bool(binder_flags & 0b0000_0100)
    has_names_2 = bool(binder_flags & 0b0000_1000)
    has_names = has_names_1 or has_names_2
    has_long_offsets = bool(binder_flags & 0b0001_0000)
    has_compression = bool(binder_flags & 0b0010_0000)

    expected_entry_header_size = 16
    if has_ids:
        expected_entry_header_size += 4
    if has_names:
        expected_entry_header_size += 4
    if has_compression:
        expected_entry_header_size += 8
    expected_entry_header_size += 8 if has_long_offsets else 4

    print("unknown1:", unknown1)
    print("unknown2:", unknown2)
    print("big_endian:", big_endian)
    print("bit_little_endian:", bit_little_endian)
    print("signature:", signature)
    print("File count:", file_count)
    print("Header size:", header_size)
    print("Entry header size:", entry_header_size)
    print("Expected entry header size from flags:", expected_entry_header_size)
    print("Data offset:", data_offset)
    print("Unicode names:", unicode_names)
    print("Binder flags (decoded):", f"0b{binder_flags:08b}")
    print("Hash table type:", hash_table_type)
    print("Hash table offset:", hash_table_offset)

    if entry_header_size != expected_entry_header_size:
        raise ValueError(
            f"BND4 entry header size mismatch: expected {expected_entry_header_size}, got {entry_header_size}"
        )
    # 10. Parse BND4 file entries
    logger.info("Step 10 / 10: Parsing BND4 file entries")
    entries = []
    path_encoding = "utf-16-le" if unicode_names else "shift-jis"
    entry_table_offset = header_size

    for i in tqdm(range(file_count),
                  desc="Decoding parameter file entries",
                  unit="paramdef"):
        entry_offset = entry_table_offset + i * entry_header_size
        entry_cursor = entry_offset

        raw_entry_flags = decompressed_data[entry_cursor]
        entry_flags = _parse_entry_flags(raw_entry_flags, bit_little_endian)
        entry_cursor += 1

        entry_cursor += 3  # padding
        minus_one = struct.unpack_from(f"{endian}i", decompressed_data, entry_cursor)[0]
        entry_cursor += 4
        if minus_one != -1:
            raise ValueError(f"Entry {i}: expected -1 sentinel, got {minus_one}")

        file_size = struct.unpack_from(f"{endian}q", decompressed_data, entry_cursor)[0]
        entry_cursor += 8

        if has_compression:
            file_size_uncompressed = struct.unpack_from(f"{endian}q", decompressed_data, entry_cursor)[0]
            entry_cursor += 8
        else:
            file_size_uncompressed = None

        if has_long_offsets:
            file_data_offset = struct.unpack_from(f"{endian}q", decompressed_data, entry_cursor)[0]
            entry_cursor += 8
        else:
            file_data_offset = struct.unpack_from(f"{endian}I", decompressed_data, entry_cursor)[0]
            entry_cursor += 4

        if has_ids:
            file_id = struct.unpack_from(f"{endian}i", decompressed_data, entry_cursor)[0]
            entry_cursor += 4
        else:
            file_id = None

        if has_names:
            file_name_offset = struct.unpack_from(f"{endian}I", decompressed_data, entry_cursor)[0]
            entry_cursor += 4
            file_name = _read_cstring(decompressed_data, file_name_offset, path_encoding)
        else:
            file_name_offset = None
            file_name = None

        entries.append({
            "id": file_id,
            "flags": entry_flags,
            "data_offset": file_data_offset,
            "size": file_size,
            "size_uncompressed": file_size_uncompressed,
            "name_offset": file_name_offset,
            "name": file_name,
            "param": _get_param_stem_from_name(file_name),
        })
    return entries


def _reverse_byte_bits(byte_value: int) -> int:
    """
    Docstring for _reverse_byte_bits
    
    :param byte_value: Description
    :type byte_value: int
    :return: Description
    :rtype: int
    """
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


    # 1. Decrypt AES layer from regulation.bin
    dcx_bytes = decrypt_aes_layer(reg_path)
    # After decrypting, you get raw bytes starting with:

