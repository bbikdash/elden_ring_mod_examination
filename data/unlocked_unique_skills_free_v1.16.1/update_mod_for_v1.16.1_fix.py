#!/usr/bin/env python3
import csv
import os
from pathlib import Path

# Define directories
OUTPUT_DIR = Path('data/unlocked_unique_skills_free_v1.16.1')

# Generate ID mappings
gem_id_mapping = {}
for i in range(1, 87):
    gem_id_mapping[f'85{i:03d}'] = f'86{i:03d}'

# Process ShopLineupParam_Recipe.csv to fix equipId references
shop_file = OUTPUT_DIR / 'ShopLineupParam_Recipe.csv'
temp_shop_file = OUTPUT_DIR / 'ShopLineupParam_Recipe.csv.tmp'

with open(shop_file, 'r', newline='') as infile, open(temp_shop_file, 'w', newline='') as outfile:
    reader = csv.reader(infile)
    writer = csv.writer(outfile)

    # Write header
    header = next(reader)
    writer.writerow(header)

    # Process each row
    for row in reader:
        if row and len(row) > 2 and row[2] in gem_id_mapping:
            row[2] = gem_id_mapping[row[2]]
        writer.writerow(row)

# Replace original file with the fixed version
os.replace(temp_shop_file, shop_file)

print(f"Fixed equipId references in {shop_file}")