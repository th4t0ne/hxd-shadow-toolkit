#!/bin/bash

echo "[*] Installing hxd-shadow-toolkit requirements..."
sudo apt update && sudo apt install -y aircrack-ng dnsmasq hostapd xterm python3 curl figlet lolcat

echo "[*] Creating portal directories..."
bash hxd-shadow-toolkit.sh <<< "3"

echo "[*] Done. You can now run the toolkit with:"
echo "   bash hxd-shadow-toolkit.sh"
