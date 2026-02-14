"""
Minimal Elden Ring Regulation.bin Decoder/Encoder

This module provides the minimum necessary code to decrypt and encrypt
Elden Ring regulation.bin files without platform-specific dependencies.
"""

from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Elden Ring regulation.bin encryption key
ER_REGULATION_KEY = bytes([
    0x99, 0xBF, 0xFC, 0x36, 0x6A, 0x6B, 0xC8, 0xC6,
    0xF5, 0x82, 0x7D, 0x09, 0x36, 0x02, 0xD6, 0x76,
    0xC4, 0x28, 0x92, 0xA0, 0x1C, 0x20, 0x7F, 0xB0,
    0x24, 0xD3, 0xAF, 0x4E, 0x49, 0x3F, 0xEF, 0x99
])

def decrypt_regulation(input_path, output_path=None):
    """Decrypt an Elden Ring regulation.bin file.

    Args:
        input_path: Path to regulation.bin
        output_path: Path to save decrypted file (defaults to regulation.parambnd.dcx in same directory)

    Returns:
        Path to decrypted file
    """
    input_path = Path(input_path)

    # Default output path if not provided
    if output_path is None:
        output_path = input_path.parent / "regulation.parambnd.dcx"
    else:
        output_path = Path(output_path)

    # Read the encrypted file
    with open(input_path, 'rb') as f:
        data = f.read()

    # Extract IV (first 16 bytes) and encrypted content
    iv = data[:16]
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
        # Verify the padding
        padding_valid = True
        for i in range(padding_length):
            if decrypted[-i-1] != padding_length:
                padding_valid = False
                break

        if padding_valid:
            decrypted = decrypted[:-padding_length]

    # Write the decrypted file
    with open(output_path, 'wb') as f:
        f.write(decrypted)

    return output_path

def encrypt_regulation(input_path, output_path=None):
    """Encrypt a decrypted Elden Ring param file back to regulation.bin.

    Args:
        input_path: Path to the decrypted file
        output_path: Path to save encrypted file (defaults to regulation.bin in same directory)

    Returns:
        Path to encrypted file
    """
    input_path = Path(input_path)

    # Default output path if not provided
    if output_path is None:
        output_path = input_path.parent / "regulation.bin"
    else:
        output_path = Path(output_path)

    # Read the decrypted file
    with open(input_path, 'rb') as f:
        data = f.read()

    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Create AES cipher in CBC mode
    cipher = Cipher(
        algorithms.AES(ER_REGULATION_KEY),
        modes.CBC(iv),
        backend=default_backend()
    )

    # Apply PKCS7 padding
    block_size = 16  # AES block size is always 16 bytes (128 bits)
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size

    padded_data = data + bytes([padding_length] * padding_length)

    # Encrypt the data
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Write IV + encrypted data
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted)

    return output_path

def main():

    reg_path = Path("./data/regulation_original.bin").absolute()
    
    result_path = decrypt_regulation(reg_path, "./test.txt")

    # Access parameters - each parameter is a dictionary-like object
    # For example, to view Radahn's parameters
    # radahn = regulation.NpcParam[47300000]
    # print(radahn)


if __name__ == "__main__":
    main()
