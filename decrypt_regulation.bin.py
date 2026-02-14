"""
Docstring for 0_dump_param_from_regulation
"""

import os
import io
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from pathlib import Path


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


def main():

    reg = Path("./data/regulation_original.bin").absolute()
    decrypted = decrypt_regulation(reg)



if __name__ == "__main__":
    main()
