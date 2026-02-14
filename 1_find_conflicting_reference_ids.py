"""
@author Bassam Bikdash

A script to automate updating a mod set of parameter CSV files.

Given 2 CSV files dumped from smithbox, one for the original parameter CSV from the original Elden Ring regulation.bin
and one from the mod, this script will find conflicting reference IDs in the mod param list that must be updated.
"""

import csv
import time
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from pathlib import Path

import pandas as pd
from loguru import logger
from sty import (  # Terminal coloring library: foreground, background, effects, resetting
    bg, ef, fg, rs)
from tqdm import tqdm


def count_csv_rows(filename: str|Path):
    """
    Use generator expression to efficiently count the number of rows in a CSV file.
    Does not include the header (the first row) in the number of row counts.
    
    :param filename: Path to CSV file
    :type filename: str | Path
    """
    filename = Path(filename).resolve()
    with open(filename, 'r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        # Using a generator expression with sum() to count rows
        row_count = sum(1 for _ in reader)
    return row_count - 1


def compute_ID_set(filename: str|Path):
    """
    Docstring for compute_ID_set
    """
    filename = Path(filename).resolve()
    row_count = count_csv_rows(filename)
    csv_id_set = set()
    with open(filename, 'r', newline='', encoding='utf-8') as file:
        csv_reader = csv.reader(file)

        header = next(csv_reader)   # skip header

        # Iterate through the rest of the rows
        for row in tqdm(csv_reader, desc="Computing ID set", total=row_count, unit="row"):
            csv_id_set.add(int(row[0]))

    return csv_id_set

def main():
    parser = ArgumentParser(description="Fine conflicting references",
                            formatter_class=ArgumentDefaultsHelpFormatter)

    parser.add_argument("-m", "--modified-csv", type=str, default="./data/unlocked_unique_skills_free/BehaviorParam_PC.csv",
                        help="Dir path to dump augmentations images to")
    parser.add_argument("-r", "--reference-csv", type=str, default="./data/reference/BehaviorParam_PC.csv",
                        help="")
    args = parser.parse_args()

    start = time.time()

    # Use absolute paths for CSV files    
    reference_csv_path = Path(args.reference_csv).absolute()
    modified_csv_path = Path(args.modified_csv).absolute()

    # Precompute number of rows in each CSV. Also makes sure that the files can be opened
    reference_num_rows = count_csv_rows(reference_csv_path)
    modified_num_rows = count_csv_rows(modified_csv_path)

    print(
        f"{fg.li_yellow}{ef.bold}Comparison Inputs:{ef.rs}\n"
        f"    reference_csv_path: {ef.underl}{reference_csv_path}{ef.rs}\n"
        f"    reference_csv rows: {reference_num_rows}\n"
        f"    modified_csv_path:  {ef.underl}{modified_csv_path}{ef.rs}\n"
        f"    modified_csv rows:  {modified_num_rows}\n"
        f"{rs.all}"
    )

    reference_id_set = compute_ID_set(reference_csv_path)
    modified_id_set = compute_ID_set(modified_csv_path)

    intersection = reference_id_set & modified_id_set
    logger.info(f"{len(intersection)} ID conflicts detected between the mod and reference CSV")    
    end = time.time()

    logger.info(f"Elapsed time: {end - start} seconds")

    logger.success("done")



if __name__ == "__main__":
    main()
