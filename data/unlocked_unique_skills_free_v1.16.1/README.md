# Unlocked Unique Skills Free for Elden Ring v1.16.1

This is a port of the original "Unlocked Unique Skills Free" mod for Elden Ring v1.06, updated to work with v1.16.1 (including Shadow of the Erdtree DLC).

## Overview

The original mod allowed unique weapon skills from special weapons to be used on standard weapons, effectively letting players apply special weapon skills to any compatible weapon. This port maintains that functionality while avoiding conflicts with the new content added in v1.16.1.

## Why This Port Was Necessary

The original mod was designed for Elden Ring v1.06, but with v1.16.1 and the Shadow of the Erdtree DLC, FromSoftware added new entries to the game parameters that conflict with the IDs used in the original mod. This causes issues when using the original mod with the newer game version.

## Changes Made in This Port

1. **BehaviorParam_PC.csv**:
   - Original ID ranges (400000xxx-900000xxx) have been shifted to new ranges (910000xxx-960000xxx) to avoid conflicts with DLC entries.
   - Example: 400000900 (Maliketh's Black Blade) → 910000900

2. **EquipParamGem.csv**:
   - ID ranges changed from 85001-85086 to 86001-86086
   - Example: 85001 (Destined Death) → 86001

3. **ShopLineupParam_Recipe.csv**:
   - ID ranges changed from 32500-32583 to 38500-38583
   - References to EquipParamGem entries updated to match the new IDs
   - Example: 32500 (Destined Death) → 38500, and equipId updated from 85001 to 86001

## Installation

1. Make a backup of your original `regulation.bin` file
2. Use a tool like Yabber, UXM, or SoulsFormats to unpack the `regulation.bin`
3. Replace the following files with the ones from this mod:
   - BehaviorParam_PC.csv
   - EquipParamGem.csv
   - ShopLineupParam_Recipe.csv
4. Repack the `regulation.bin` file
5. Replace your game's `regulation.bin` with the modified version

## Credits

- Original mod creator for "Unlocked Unique Skills Free" for Elden Ring v1.06
- This port was created to update the mod for compatibility with v1.16.1

## Compatibility

This mod has been specifically designed for Elden Ring v1.16.1 and should be compatible with the Shadow of the Erdtree DLC. It is not compatible with older game versions.

## Known Issues

- None currently identified. If you encounter any issues, please report them.
