"""
@author Bassam Bikdash
Docstring for 0_find_conflicting_reference_ids
"""

import csv
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser

import pandas as pd
from loguru import logger


def main():
    parser = ArgumentParser(description="Fine conflicting references",
                            formatter_class=ArgumentDefaultsHelpFormatter)

    parser.add_argument("-o", "--output-dir", type=str, default="./augmentations_test",
                        help="Dir path to dump augmentations images to")
    

    args = parser.parse_args()

if __name__ == "__main__":
    main()
