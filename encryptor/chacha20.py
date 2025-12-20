#!/usr/bin/env python3
import sys
import os
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def chacha20_encrypt(plaintext, key):
    """
    Encrypt a payload with ChaCha20
    """
    # Generate a random 12-byte nonce
    nonce = get_random_bytes(12)
    
    # If the key is less than 32 bytes, pad it with zeros
    if len(key) < 32:
        key = key + b'\x00' * (32 - len(key))
    elif len(key) > 32:
        key = key[:32]
    
    # Create the ChaCha20 cipher
    cipher = ChaCha20.new(key=key, nonce=nonce)
    
    # Encrypt the payload
    ciphertext = cipher.encrypt(plaintext)
    
    return ciphertext, key, nonce

def drop_files(key, ciphertext, nonce):
    """
    Save the encrypted files
    """
    # Save the encrypted payload
    with open("cipher_chacha20.bin", "wb") as fc:
        fc.write(ciphertext)
    
    # Save the key (for HTTP retrieval)
    with open("key_chacha20.bin", "wb") as fk:
        fk.write(key)
    
    # Save the nonce (optional, can be derived from the key)
    with open("nonce_chacha20.bin", "wb") as fn:
        fn.write(nonce)
    
    print(f"[+] Generated files:")
    print(f"    - cipher_chacha20.bin ({len(ciphertext)} bytes)")
    print(f"    - key_chacha20.bin ({len(key)} bytes)")
    print(f"    - nonce_chacha20.bin ({len(nonce)} bytes)")
    
    # Display C++ arrays for debug (optional)
    print(f"\n[+] ChaCha20 Key (C++ format):")
    print('unsigned char chacha20_key[] = { 0x' + ', 0x'.join(f'{x:02x}' for x in key) + ' };')
    print(f"\n[+] ChaCha20 Nonce (C++ format):")
    print('unsigned char chacha20_nonce[] = { 0x' + ', 0x'.join(f'{x:02x}' for x in nonce) + ' };')

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 chacha20.py <PAYLOAD_FILE>")
        print("Example: python3 chacha20.py mimikatz.exe")
        sys.exit(1)
    
    payload_file = sys.argv[1]
    
    # Check if the file exists
    if not os.path.exists(payload_file):
        print(f"[-] Error: The file '{payload_file}' does not exist")
        sys.exit(1)
    
    try:
        # Read the payload
        with open(payload_file, "rb") as f:
            payload_content = f.read()
        
        print(f"[+] Payload read: {len(payload_content)} bytes")
        
        # Generate a random 32-byte key
        key = get_random_bytes(32)
        print("[+] ChaCha20 key generated")
        
        # Encrypt with ChaCha20
        ciphertext, key, nonce = chacha20_encrypt(payload_content, key)
        print("[+] Payload encrypted with ChaCha20")
        
        # Save the files
        drop_files(key, ciphertext, nonce)
        
        print("\n[+] ChaCha20 encryption completed successfully!")
        print("[+] Use 'CHACHA20' as cipher parameter in your FileLessAtfLoader")
        
    except Exception as e:
        print(f"[-] Error during encryption: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
