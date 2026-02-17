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

import io
import struct
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from pathlib import Path
import time

from erm_exam.utils.decryption_utils import (
    extract_params_from_elden_ring_regulation_binary,
    _rows_to_csv,
)

def main():

    parser = ArgumentParser(description="Find conflicting references",
                            formatter_class=ArgumentDefaultsHelpFormatter)

    parser.add_argument("-r", "--regulation-file", type=str,
                        default="./data/reference/regulation_v1.16.1.bin",
                        help="Default")
    parser.add_argument(
        "--csv-output-dir",
        type=str,
        default="./data/reference/regulation_csv_dump",
        help="Output directory for section 8 PARAM CSV dumps.",
    )
    args = parser.parse_args()

    start = time.time()

    reg_path = Path(args.regulation_file).absolute()
    csv_output_dir = Path(args.csv_output_dir).absolute()

    entries = extract_params_from_elden_ring_regulation_binary(reg_path)
    print()

    # 8. Dump PARAM contents to CSV (minimal row parser).
    # dumped_count = 0
    # for entry in entries:
    #     if not entry["name"] or not str(entry["name"]).endswith(".param"):
    #         continue
    #     param_name = entry["param"] or f"entry_{entry['id']}"
    #     data_start = entry["data_offset"]
    #     data_end = data_start + entry["size"]
    #     if data_start < 0 or data_end > len(decompressed_data):
    #         continue
    #     param_bytes = decompressed_data[data_start:data_end]
    #     rows = _parse_param_rows_minimal(param_bytes)
    #     csv_path = csv_output_dir / f"{param_name}.csv"
    #     _rows_to_csv(csv_path, rows)
    #     dumped_count += 1
    # print(f"Dumped {dumped_count} param CSV files to: {csv_output_dir}")

    # Access parameters - each parameter is a dictionary-like object
    # For example, to view Radahn's parameters
    # radahn = regulation.NpcParam[47300000]
    # print(radahn)


if __name__ == "__main__":
    main()
