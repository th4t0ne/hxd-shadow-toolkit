#!/bin/bash

# hxd-shadow-toolkit - Phantom Wi-Fi Auditor by h.exe

IFACE="wlan0"
MONITOR_IFACE="${IFACE}mon"
LOGDIR="$HOME/hxd-shadow-toolkit/logs/$(date +%F_%T)"
mkdir -p "$LOGDIR"
PORTALS_DIR="$HOME/hxd-shadow-toolkit/portals"

ASCII_LOGO='  
   _________.__                 __           ________  ________   
  /   _____/|  |__   ____ _____/  |_ ___.__. \_____  \ \_____  \  
  \_____  \ |  |  \_/ __ \\__  \   __<   |  |  /  ____/  /  ____/  
  /        \|   Y  \  ___/ / __ \|  |  \___  | /       \ /       \ 
 /_______  /|___|  /\___  >____  /__|  / ____| \_______ \\_______ \
         \/      \/     \/     \/      \/              \/       \/
            hxd-shadow-toolkit - Phantom Wi-Fi Auditor | by h.exe'

# Wyświetl logo
clear
echo "$ASCII_LOGO"
sleep 2

# Reszta menu, funkcji itd.
main_menu
