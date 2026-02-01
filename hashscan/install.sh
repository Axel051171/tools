#!/bin/bash
# HASHSCAN Quick Install Script

set -e

echo "╔════════════════════════════════════════╗"
echo "║     HASHSCAN v10.0 - Quick Install     ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Check for gcc
if ! command -v gcc &> /dev/null; then
    echo "[!] gcc not found. Please install build-essential:"
    echo "    sudo apt install build-essential"
    exit 1
fi

# Compile
echo "[*] Compiling..."
gcc -O2 -Wall -o hashscan hashscan.c -lm

if [ $? -eq 0 ]; then
    echo "[+] Build successful: $(ls -lh hashscan | awk '{print $5}')"
else
    echo "[!] Build failed"
    exit 1
fi

# Install
if [ "$1" == "--install" ] || [ "$1" == "-i" ]; then
    echo "[*] Installing to /usr/local/bin..."
    sudo cp hashscan /usr/local/bin/
    sudo chmod 755 /usr/local/bin/hashscan
    echo "[+] Installed! Run 'hashscan --help' to get started"
else
    echo ""
    echo "[*] To install system-wide, run:"
    echo "    sudo cp hashscan /usr/local/bin/"
    echo ""
    echo "[*] Or re-run this script with --install:"
    echo "    ./install.sh --install"
fi

echo ""
echo "[*] Quick test:"
./hashscan --version
