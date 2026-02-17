"""
@author Bassam Bikdash

Given a path to a regulation.bin and a parameter name, this script will decode the .bin,
save the decrypted file to a temporary location, load the parameter with the given name,
and that param as a CSV file.

"""

import io
import struct
import time
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from pathlib import Path

from loguru import logger

from erm_exam.utils.decryption_utils import (
    _rows_to_csv, extract_params_from_elden_ring_regulation_binary, paramdef_xml_to_datatype_dict)


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
    
    print("Parsed", len(entries), "file entries")

    # TODO: Now that I've extracted the params from the regulation.bin, I want to decode the raw bytes of the entry dict data value into a csv file. 
    # Load the right paramdef file to know how to properly parse the raw bytes into columns and their data types. Use paramdef_xml_to_datatype_dict to convert the raw bytes into a CSV for BehaviorParamPC.xml



if __name__ == "__main__":
    main()
