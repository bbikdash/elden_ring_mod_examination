# Elden Ring regulation.bin Analysis and Python Implementation

This document explains how regulation.bin files work in Elden Ring and how to decode/encode them with Python.

## What is regulation.bin?

The regulation.bin file in Elden Ring (and other FromSoftware games) is essentially a container that holds various game parameters in tables. These parameters control many aspects of the game, including:

- Player and enemy stats
- Weapon properties
- Item effects
- Spell properties
- Equipment stats
- And much more

## File Format Structure

Based on the code examination, the regulation.bin file is:

1. **Encrypted** - Using AES encryption with a specific key
2. **BND4 Format** - When decrypted, it's a Binder file (BND4) containing multiple PARAM files
3. **PARAM Structure** - Each PARAM file contains rows of game parameters with specific formats

## The Decryption/Encryption Process

In the ERModsMerger repository, the decryption is handled by the `SFUtil.DecryptERRegulation()` method. Here are the key components:

1. The encryption key for Elden Ring regulation.bin is defined as a byte array:
```csharp
private static readonly byte[] erRegulationKey = ParseHexString("99 BF FC 36 6A 6B C8 C6 F5 82 7D 09 36 02 D6 76 C4 28 92 A0 1C 20 7F B0 24 D3 AF 4E 49 3F EF 99");
```

2. The decryption process uses AES in CBC mode with a 256-bit key size
3. The IV (Initialization Vector) is stored in the first 16 bytes of the file
4. The encrypted content starts after the IV

## Implementing in Python

Here's a Python implementation to decrypt and encrypt regulation.bin files:

```python
import os
import io
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Elden Ring regulation.bin encryption key (from SFUtil.cs)
ER_REGULATION_KEY = bytes([
    0x99, 0xBF, 0xFC, 0x36, 0x6A, 0x6B, 0xC8, 0xC6,
    0xF5, 0x82, 0x7D, 0x09, 0x36, 0x02, 0xD6, 0x76,
    0xC4, 0x28, 0x92, 0xA0, 0x1C, 0x20, 0x7F, 0xB0,
    0x24, 0xD3, 0xAF, 0x4E, 0x49, 0x3F, 0xEF, 0x99
])

def decrypt_regulation(file_path):
    """
    Decrypts an Elden Ring regulation.bin file

    Args:
        file_path: Path to the regulation.bin file

    Returns:
        bytes: Decrypted BND4 data
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    # Check if already decrypted by looking for BND4 magic
    if data[0:4] == b'BND4':
        print("File appears to be already decrypted")
        return data

    # Extract IV (first 16 bytes) and encrypted content
    iv = data[0:16]
    encrypted_content = data[16:]

    # Create AES cipher in CBC mode
    cipher = Cipher(
        algorithms.AES(ER_REGULATION_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Decrypt the content
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_content) + decryptor.finalize()

    # Remove PKCS7 padding if present
    padding_length = decrypted[-1]
    if padding_length < 16:
        # Check if valid PKCS7 padding
        for i in range(1, padding_length + 1):
            if decrypted[-i] != padding_length:
                # Not valid padding, return as is
                return decrypted
        # Remove padding
        decrypted = decrypted[:-padding_length]

    return decrypted

def encrypt_regulation(bnd4_data, output_path):
    """
    Encrypts BND4 data and writes it as a regulation.bin file

    Args:
        bnd4_data: Bytes containing BND4 data
        output_path: Output path for the encrypted regulation.bin
    """
    # Generate random IV
    iv = os.urandom(16)

    # Create AES cipher in CBC mode
    cipher = Cipher(
        algorithms.AES(ER_REGULATION_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Add padding to make data length a multiple of AES block size (16 bytes)
    padding_length = 16 - (len(bnd4_data) % 16)
    if padding_length == 0:
        padding_length = 16  # Full block padding if already aligned

    padded_data = bnd4_data + bytes([padding_length] * padding_length)

    # Encrypt the content
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Write IV + encrypted data to file
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted)

    print(f"Encrypted regulation.bin written to {output_path}")
```

## Working with BND4 and PARAM Files

After decrypting the regulation.bin, you'll need to parse the BND4 container and PARAM files. Here's how to implement this:

```python
def read_bnd4(data):
    """
    Parses a BND4 file format

    Args:
        data: Bytes containing BND4 data

    Returns:
        dict: Dictionary of contained files with their paths as keys
    """
    # Verify magic bytes "BND4"
    if data[0:4] != b'BND4':
        raise ValueError("Not a valid BND4 file")

    # Parse BND4 header
    magic = data[0:4]
    version = struct.unpack('<B', data[4:5])[0]
    # More header fields would be parsed here

    # Get file count (bytes 0x10-0x14)
    file_count = struct.unpack('<I', data[0x10:0x14])[0]

    # Get files offset table offset (bytes 0x18-0x1C)
    file_table_offset = struct.unpack('<I', data[0x18:0x1C])[0]

    # Read file entries
    bnd_files = {}
    current_offset = file_table_offset

    for i in range(file_count):
        # Each entry has file info including name, size, offset
        file_offset = struct.unpack('<I', data[current_offset+8:current_offset+12])[0]
        file_size = struct.unpack('<I', data[current_offset+12:current_offset+16])[0]
        file_name_offset = struct.unpack('<I', data[current_offset+20:current_offset+24])[0]

        # Get null-terminated file name
        file_name = ""
        name_offset = file_name_offset
        while data[name_offset] != 0:
            file_name += chr(data[name_offset])
            name_offset += 1

        # Extract file data
        file_data = data[file_offset:file_offset+file_size]
        bnd_files[file_name] = file_data

        # Move to next entry
        current_offset += 24  # Entry size

    return bnd_files

def parse_param(data):
    """
    Parses a PARAM file

    Args:
        data: Bytes containing PARAM data

    Returns:
        dict: Dictionary of rows with their IDs as keys
    """
    # This is a simplified version - actual PARAM parsing is more complex
    # and would require understanding the PARAMDEF format for each table

    # PARAM header parsing
    # Offset 0x0C: Row count (2 bytes)
    row_count = struct.unpack('<H', data[0x0C:0x0E])[0]

    # Get param type (file type)
    param_type = data[0x10:0x30].decode('utf-8').strip('\0')

    # Parse row headers (IDs and offsets)
    rows = {}
    row_header_start = 0x40  # Typical start, but can vary

    for i in range(row_count):
        offset = row_header_start + i * 8
        row_id = struct.unpack('<I', data[offset:offset+4])[0]
        row_offset = struct.unpack('<I', data[offset+4:offset+8])[0]

        # Store row information
        # To fully parse cells, you would need corresponding PARAMDEF info
        rows[row_id] = {
            'offset': row_offset,
            'raw_data': data[row_offset:row_offset+100]  # Simplified; actual size varies
        }

    return {
        'param_type': param_type,
        'rows': rows
    }
```

## Complete Workflow for Modding

Here's a complete workflow for modding regulation.bin files with Python:

```python
def mod_regulation(regulation_path, output_path, modifications):
    """
    Modifies a regulation.bin file

    Args:
        regulation_path: Path to the original regulation.bin
        output_path: Path to save the modified regulation.bin
        modifications: Dictionary of parameter modifications
    """
    # Decrypt the regulation.bin
    decrypted_data = decrypt_regulation(regulation_path)

    # Parse the BND4 container
    bnd_files = read_bnd4(decrypted_data)

    # Process each PARAM file that needs modification
    for param_name, param_mods in modifications.items():
        if param_name + '.param' not in bnd_files:
            print(f"Warning: {param_name}.param not found in regulation.bin")
            continue

        param_data = bnd_files[param_name + '.param']

        # Parse the PARAM file
        param = parse_param(param_data)

        # Apply modifications
        for row_id, cell_mods in param_mods.items():
            if row_id not in param['rows']:
                print(f"Warning: Row ID {row_id} not found in {param_name}")
                continue

            # Apply cell modifications
            # This would need custom logic based on PARAMDEF structure

            # Example: modify_param_row(param, row_id, cell_mods)

    # Rebuild the BND4 file
    # rebuild_bnd4(bnd_files)

    # Encrypt and save the modified regulation.bin
    # encrypt_regulation(rebuilt_bnd4, output_path)
```

## Challenges and Complexities

There are several challenges to fully implementing this in Python:

1. **PARAMDEF Handling**: Each PARAM file's structure is defined by a corresponding PARAMDEF file. You would need the PARAMDEFs for Elden Ring to properly parse and modify cell values.

2. **Row Structure**: As seen in the C# code, rows have a complex structure with cells that can contain various data types.

3. **BND4 Rebuilding**: Properly rebuilding the BND4 container requires maintaining file offsets, sizes, and names.

## Python Libraries to Consider

For a more complete implementation, consider these Python libraries:

1. **[pycryptodome](https://pypi.org/project/pycryptodome/)** - For AES encryption/decryption
2. **[construct](https://pypi.org/project/construct/)** - For binary parsing
3. **[elden-ring-param-reconstruct](https://github.com/thefifthmatt/elden-ring-param-reconstruct)** - An existing Python project for Elden Ring param files

## Additional Resources and Implementation Tips

### Existing Python Tools for FromSoftware Games

1. **[SoulsFormats.py](https://github.com/JKAnderson/SoulsFormats.py)** - A Python port of the SoulsFormats library used in this repository
2. **[Yapped](https://github.com/vawser/Yapped-Rune-Bear)** - A tool for editing PARAM files with source code that might be helpful
3. **[DSMapStudio](https://github.com/soulsmods/DSMapStudio)** - Contains code for handling FromSoftware file formats

### Implementation Notes for PARAM Handling

When implementing the PARAM parser in Python, keep these points in mind:

1. **Field Types**: The PARAMDEF defines various field types (u8, s8, u16, s16, u32, s32, f32, etc.) which determine how to read/write values

2. **Bit Fields**: Some fields are "bit fields" where multiple values are packed into a single integer. You'll need to handle bit shifting and masking

3. **Strings**: String values in PARAM files have offsets to a string table at the end of the file

Here's an example of how to read a specific field value based on its type:

```python
def read_param_field(data, offset, field_type):
    """
    Reads a field value from PARAM data

    Args:
        data: PARAM file data
        offset: Offset to the field value
        field_type: Type of the field (from PARAMDEF)

    Returns:
        The field value
    """
    if field_type == 'u8':
        return struct.unpack('<B', data[offset:offset+1])[0]
    elif field_type == 's8':
        return struct.unpack('<b', data[offset:offset+1])[0]
    elif field_type == 'u16':
        return struct.unpack('<H', data[offset:offset+2])[0]
    elif field_type == 's16':
        return struct.unpack('<h', data[offset:offset+2])[0]
    elif field_type == 'u32':
        return struct.unpack('<I', data[offset:offset+4])[0]
    elif field_type == 's32':
        return struct.unpack('<i', data[offset:offset+4])[0]
    elif field_type == 'f32':
        return struct.unpack('<f', data[offset:offset+4])[0]
    elif field_type == 'fixstr':
        # Fixed-length string, null-terminated
        end = offset
        while data[end] != 0 and end < offset + 32:
            end += 1
        return data[offset:end].decode('utf-8')
    # Add other types as needed
    else:
        raise ValueError(f"Unsupported field type: {field_type}")
```

### Example Use Case

Here's a concrete example of how you might use this Python implementation to modify a specific game parameter:

```python
# Example: Change the HP of a specific enemy
def modify_enemy_hp(regulation_path, output_path, enemy_id, new_hp):
    # Decrypt regulation.bin
    decrypted_data = decrypt_regulation(regulation_path)

    # Parse BND4
    bnd_files = read_bnd4(decrypted_data)

    # Assuming enemy HP is in NpcParam.param
    param_data = bnd_files.get('NpcParam.param')
    if not param_data:
        print("NpcParam.param not found in regulation.bin")
        return

    # Modify the HP value for the specified enemy ID
    # This would require detailed knowledge of the NpcParam structure
    # and the location of the HP field within it

    # Re-encrypt and save
    # ...
```

## Conclusion

While implementing a complete solution requires extensive work, the framework above provides the essential components for decrypting, parsing, modifying, and re-encrypting regulation.bin files. For a production-ready solution, you would need to implement proper PARAMDEF handling and BND4 reconstruction.

For reference, the ERModsMerger tool uses the following process flow:
1. Decrypt the regulation.bin using the AES key
2. Parse the BND4 container
3. For each PARAM file, apply the corresponding PARAMDEF
4. Modify parameter values as needed
5. Re-encode PARAM files
6. Rebuild the BND4 container
7. Encrypt and save the modified regulation.bin