#!/usr/bin/env python3
import csv
import os
from pathlib import Path

# Define directories
MOD_DIR = Path('data/unlocked_unique_skills_free_v1.06')
REF_DIR = Path('data/reference')
OUTPUT_DIR = Path('data/unlocked_unique_skills_free_v1.16.1')

# Create output directory if it doesn't exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Define ID mapping
behavior_id_mapping = {
    # Map 400000xxx to 910000xxx
    # Map 500000xxx to 920000xxx
    # Map 600000xxx to 930000xxx
    # Map 700000xxx to 940000xxx
    # Map 800000xxx to 950000xxx
    # Map 900000xxx to 960000xxx
}

gem_id_mapping = {}  # Map 85001-85086 to 86001-86086
shop_id_mapping = {}  # Map 32500-32583 to 38500-38583

# Generate ID mappings
for i in range(1, 87):
    gem_id_mapping[f'85{i:03d}'] = f'86{i:03d}'

for i in range(500, 584):
    shop_id_mapping[f'32{i}'] = f'38{i}'

# Function to determine prefix for behavior ID
def map_behavior_id(old_id):
    if old_id.startswith('400000'):
        return '910000' + old_id[6:]
    elif old_id.startswith('500000'):
        return '920000' + old_id[6:]
    elif old_id.startswith('600000'):
        return '930000' + old_id[6:]
    elif old_id.startswith('700000'):
        return '940000' + old_id[6:]
    elif old_id.startswith('800000'):
        return '950000' + old_id[6:]
    elif old_id.startswith('900000'):
        return '960000' + old_id[6:]
    return old_id  # Return unchanged if no mapping

# Process BehaviorParam_PC.csv
behavior_file = MOD_DIR / 'BehaviorParam_PC.csv'
output_behavior_file = OUTPUT_DIR / 'BehaviorParam_PC.csv'

with open(behavior_file, 'r', newline='') as infile, open(output_behavior_file, 'w', newline='') as outfile:
    reader = csv.reader(infile)
    writer = csv.writer(outfile)

    # Write header
    header = next(reader)
    writer.writerow(header)

    # Process each row
    for row in reader:
        if row and row[0] and (row[0].startswith('4') or row[0].startswith('5') or
                              row[0].startswith('6') or row[0].startswith('7') or
                              row[0].startswith('8') or row[0].startswith('9')):
            row[0] = map_behavior_id(row[0])
        writer.writerow(row)

print(f"Created {output_behavior_file}")

# Process EquipParamGem.csv
gem_file = MOD_DIR / 'EquipParamGem.csv'
output_gem_file = OUTPUT_DIR / 'EquipParamGem.csv'

with open(gem_file, 'r', newline='') as infile, open(output_gem_file, 'w', newline='') as outfile:
    reader = csv.reader(infile)
    writer = csv.writer(outfile)

    # Write header
    header = next(reader)
    writer.writerow(header)

    # Process each row
    for row in reader:
        if row and row[0] in gem_id_mapping:
            row[0] = gem_id_mapping[row[0]]
        writer.writerow(row)

print(f"Created {output_gem_file}")

# Process ShopLineupParam_Recipe.csv
shop_file = MOD_DIR / 'ShopLineupParam_Recipe.csv'
output_shop_file = OUTPUT_DIR / 'ShopLineupParam_Recipe.csv'

with open(shop_file, 'r', newline='') as infile, open(output_shop_file, 'w', newline='') as outfile:
    reader = csv.reader(infile)
    writer = csv.writer(outfile)

    # Write header
    header = next(reader)
    writer.writerow(header)

    # Process each row
    for row in reader:
        if row and row[0] in shop_id_mapping:
            row[0] = shop_id_mapping[row[0]]
        writer.writerow(row)

print(f"Created {output_shop_file}")

# Create README.md for the new mod version
readme_content = f"""# Unlocked Unique Skills Free for Elden Ring v1.16.1

This is a port of the original "Unlocked Unique Skills Free" mod for Elden Ring v1.06,
updated to work with v1.16.1.

The original mod allowed unique weapon skills from special weapons to be used on standard weapons.
This version has been modified to avoid ID conflicts with the DLC content in v1.16.1.

## Changes from the original mod:

1. BehaviorParam_PC.csv entries:
   - ID ranges changed from 400000xxx-900000xxx to 910000xxx-960000xxx

2. EquipParamGem.csv entries:
   - ID ranges changed from 85001-85086 to 86001-86086

3. ShopLineupParam_Recipe.csv entries:
   - ID ranges changed from 32500-32583 to 38500-38583

All functionality should remain the same as the original mod.
"""

readme_file = OUTPUT_DIR / 'README.md'
with open(readme_file, 'w') as f:
    f.write(readme_content)

print(f"Created {readme_file}")
print("Mod conversion complete!")