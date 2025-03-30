![License: MIT](https://img.shields.io/badge/license-MIT-blue)
![Status: Alpha](https://img.shields.io/badge/status-active-blueviolet)
![Platform: Linux](https://img.shields.io/badge/platform-linux-informational)
![Author: h.exe](https://img.shields.io/badge/author-h.exe-black)

# hxd-shadow-toolkit – Phantom Wi-Fi Auditor by h.exe

> Full-featured Wi-Fi MITM and phishing automation toolkit for educational auditing only.

## 🔧 Setup
```bash
git clone https://github.com/h-exe/hxd-shadow-toolkit.git ~/hxd-shadow-toolkit
cd ~/hxd-shadow-toolkit
chmod +x hxd-shadow-toolkit.sh install.sh
./install.sh
```

## 🕹️ Usage
```bash
bash hxd-shadow-toolkit.sh
```
Or create an alias:
```bash
echo "alias hxdshadow='bash ~/hxd-shadow-toolkit/hxd-shadow-toolkit.sh'" >> ~/.bashrc
source ~/.bashrc
```

## ✨ Features
- Automatic handshake capture
- Evil Twin (Fake AP) with real SSID + MAC spoof
- Realistic phishing portals (Google, FB, iCloud, Dropbox)
- Web credential logger with optional Discord webhook
- Live client monitoring & session sniffer

> Created by **h.exe** for red team research and educational pentesting.
