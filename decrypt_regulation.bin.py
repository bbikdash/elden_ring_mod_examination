"""
Minimal Elden Ring Regulation.bin Decoder/Encoder

This module provides the minimum necessary code to decrypt and encrypt
Elden Ring regulation.bin files without platform-specific dependencies.


regulation.bin is not a single format.

It is a stacked container format:

[ AES-256 encrypted blob ]
    ↓ decrypt
[ DCX compressed container ]
    ↓ decompress
[ BND4 archive ]
    ↓ extract
[ PARAM files + other data ]


regulation.bin (logical view)
    └── BND4 archive
            ├── EquipParamWeapon.param
            ├── EquipParamArmor.param
            ├── SpEffectParam.param
            ├── NpcParam.param
            ├── ...

"""

import csv
import io
import os
import struct
import time
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
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


def fully_decrypt_regulation(path: str|Path) -> bytes:
    # -----------------------
    # 1. Read encrypted file
    # -----------------------
    with open(path, "rb") as f:
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

    # DO NOT strip padding (SoulsFormats does not)

    # -----------------------
    # 3. If already BND4, done
    # -----------------------
    if decrypted.startswith(b"BND4"):
        return decrypted

    # -----------------------
    # 4. If DCX, decompress
    # -----------------------
    if not decrypted.startswith(b"DCX\x00"):
        raise ValueError("Unexpected format after AES decrypt")

    offset = 4

    # ---- DCS block ----
    if decrypted[offset:offset+4] != b"DCS\x00":
        raise ValueError("Missing DCS block")
    offset += 4
    dcs_size = struct.unpack(">I", decrypted[offset:offset+4])[0]
    offset += 4 + dcs_size

    # ---- DCP block ----
    if decrypted[offset:offset+4] != b"DCP\x00":
        raise ValueError("Missing DCP block")
    offset += 4
    dcp_size = struct.unpack(">I", decrypted[offset:offset+4])[0]
    offset += 4 + dcp_size

    # ---- DCA block ----
    if decrypted[offset:offset+4] != b"DCA\x00":
        raise ValueError("Missing DCA block")
    offset += 4

    compressed_size = struct.unpack(">I", decrypted[offset:offset+4])[0]
    offset += 4

    compressed_data = decrypted[offset:offset+compressed_size]

    # -----------------------
    # 5. ZSTD decompress
    # -----------------------
    dctx = zstd.ZstdDecompressor()
    result = dctx.decompress(compressed_data)

    return result


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

def read_utf16_string(data, offset):
    chars = []
    while True:
        c = data[offset:offset+2]
        if c == b'\x00\x00':
            break
        chars.append(c)
        offset += 2
    return b''.join(chars).decode('utf-16-be')

def main():

    parser = ArgumentParser(description="Find conflicting references",
                            formatter_class=ArgumentDefaultsHelpFormatter)

    parser.add_argument("-r", "--regulation-file", type=str, default="./data/reference/regulation_v1.16.1.bin",
                        help="")
    args = parser.parse_args()

    reg_path = Path(args.regulation_file).absolute()

    # 1. Decrypt AES layer from regulation.bin
    dcx_bytes = decrypt_aes_layer(reg_path)
    # After decrypting, you get raw bytes starting with:

    # 2. Parse DCX header
    offset = 4

    version1 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    unk1 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    unk2 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    version2 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    version3 = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4

    dcs_magic = dcx_bytes[offset:offset+4]; offset += 4
    if dcs_magic != b"DCS\x00":
        raise ValueError("Missing DCS block")
    
    decompressed_size = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4
    compressed_size = struct.unpack_from(">I", dcx_bytes, offset)[0]; offset += 4

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

    # Parse DCA block
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

    # 3. Extract compressed payload
    remaining = len(dcx_bytes) - offset
    if remaining < compressed_size:
        raise ValueError("Not enough bytes for compressed payload")

    compressed_data = dcx_bytes[offset : offset + compressed_size]

    # 4. Decompress ZSTD
    dctx = zstd.ZstdDecompressor()
    with dctx.stream_reader(io.BytesIO(compressed_data)) as r:
        decompressed_data = r.read()  # read() until EOF
    # zstandard.backend_c.ZstdError: could not determine content size in frame header
    # decompressed_data = dctx.decompress(compressed_data)

    # 5. Validate size
    if len(decompressed_data) != decompressed_size:
        raise ValueError(
            f"Size mismatch: expected {decompressed_size}, got {len(decompressed_data)}"
            "Decompressed DCX data size does not match size in header"
        )

    print("Decompression successful.")
    print("First 4 bytes of decompressed data:", decompressed_data[:4])

    # 6. Parse BND4 header
    offset = 0

    magic = decompressed_data[offset:offset+4]; offset += 4
    if magic != b'BND4':
        raise ValueError("Not a BND4 archive")

    print("BND magic:", magic)

    # Endianness + version info block
    unk1 = struct.unpack_from("<I", decompressed_data, offset)[0]; offset += 4
    unk2 = struct.unpack_from("<I", decompressed_data, offset)[0]; offset += 4

    # File count
    file_count = struct.unpack_from("<I", decompressed_data, offset)[0]; offset += 4

    # Header size
    header_size = struct.unpack_from("<I", decompressed_data, offset)[0]; offset += 4

    # File header offset
    file_headers_offset = struct.unpack_from("<I", decompressed_data, offset)[0]; offset += 4

    print("File count:", file_count)
    print("Header size:", header_size)
    print("File headers offset:", file_headers_offset)

    # 7. Parse file entries
    entries = []

    offset = file_headers_offset

    for i in range(file_count):
        entry_offset = offset + i * 0x28

        file_flags = struct.unpack_from(">I", decompressed_data, entry_offset)[0]
        file_id = struct.unpack_from(">I", decompressed_data, entry_offset + 4)[0]
        file_data_offset = struct.unpack_from(">I", decompressed_data, entry_offset + 8)[0]
        file_size = struct.unpack_from(">I", decompressed_data, entry_offset + 12)[0]
        file_name_offset = struct.unpack_from(">I", decompressed_data, entry_offset + 16)[0]

        entries.append({
            "id": file_id,
            "data_offset": file_data_offset,
            "size": file_size,
            "name_offset": file_name_offset
        })

    print("Parsed", len(entries), "file entries")

    # Resolve filenames
    for entry in entries:
        name = read_utf16_string(decompressed_data, entry["name_offset"])
        entry["name"] = name

    print("First 5 files:")
    for e in entries[:5]:
        print(e["name"])

    # Access parameters - each parameter is a dictionary-like object
    # For example, to view Radahn's parameters
    # radahn = regulation.NpcParam[47300000]
    # print(radahn)


if __name__ == "__main__":
    main()
