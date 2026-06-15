#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly APP_NAME="WAR SAILING"
readonly APP_VERSION="1.2.5"
readonly DATA_DIR="${HOME}/.warsailing"
readonly LOG_DIR="${DATA_DIR}/logs"
readonly BIN_DIR="${DATA_DIR}/bin"
readonly VENV_DIR="${DATA_DIR}/venv"
readonly STATE_DIR="${DATA_DIR}/run"
readonly INSTALL_MARKER="${DATA_DIR}/.installed"
readonly SCAN_ENGINE="${BIN_DIR}/scan_engine.py"
readonly SYSTEM_BIN="/usr/local/bin/war-sailing"

readonly APT_PACKAGES=(gpsd gpsd-clients iw wireless-tools aircrack-ng tshark jq python3 python3-venv python3-pip libpcap-dev git)

GPSD_DEVICE=""
WE_STARTED_GPSD=0
CURRENT_LOG_FILE=""
CLEANED_UP=0
SCAN_COUNT=0
declare -A SEEN_BSSIDS

readonly C_RESET=$'\033[0m'
readonly C_BOLD=$'\033[1m'
readonly C_OCEAN=$'\033[38;5;25m'
readonly C_OCEAN_LT=$'\033[38;5;67m'
readonly C_BLOOD=$'\033[38;5;124m'
readonly C_GOLD=$'\033[38;5;178m'
readonly C_STEEL=$'\033[38;5;245m'
readonly C_FOAM=$'\033[38;5;230m'
readonly C_GREEN=$'\033[38;5;112m'

log_info()  { printf '%s[*]%s %s\n' "${C_OCEAN_LT}${C_BOLD}" "${C_RESET}" "$1"; }
log_ok()    { printf '%s[+]%s %s\n' "${C_GREEN}${C_BOLD}"    "${C_RESET}" "$1"; }
log_warn()  { printf '%s[!]%s %s\n' "${C_GOLD}${C_BOLD}"     "${C_RESET}" "$1"; }
log_error() { printf '%s[x]%s %s\n' "${C_BLOOD}${C_BOLD}"    "${C_RESET}" "$1" >&2; }
die()       { log_error "$1"; exit 1; }

command_exists() { command -v "$1" &>/dev/null; }

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "Dit script vereist root-rechten. Start met: sudo war-sailing of sudo ./install.sh"
        return 1
    fi
    return 0
}

print_banner() {
    clear
    local cols
    cols=$(tput cols 2>/dev/null || echo 80)
    
    if (( cols >= 80 )); then
        printf '%s' "${C_GOLD}${C_BOLD}"
        cat <<'BANNER'
   ██╗    ██╗ █████╗ ██████╗     ███████╗ █████╗ ██╗██╗     ██╗███╗   ██╗ ██████╗
   ██║    ██║██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██║██║     ██║████╗  ██║██╔════╝
   ██║ █╗ ██║███████║██████╔╝    ███████╗███████║██║██║     ██║██╔██╗ ██║██║     
   ██║███╗██║██╔══██║██╔══██╗    ╚════██║██╔══██║██║██║     ██║██║╚██╗██║██║  ███
   ╚███╔███╔╝██║  ██║██║  ██║    ███████║██║  ██║██║███████╗██║██║ ╚████║╚██████╔╝
    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
BANNER
        printf '%s\n' "${C_RESET}"
        printf "%s          \"LETS EXPLORE THE 7 SEAS AND CONQUER FOR WALHALLA\"%s\n\n" "${C_STEEL}${C_BOLD}" "${C_RESET}"
    fi
}

detect_distro() { [[ -r /etc/os-release ]] && source /etc/os-release && echo "${ID:-unknown}" || echo "unknown"; }

create_global_link() {
    local script_path; script_path=$(realpath "$0")
    cat > "$SYSTEM_BIN" <<EOF
#!/usr/bin/env bash
exec "$script_path" "\$@"
EOF
    chmod +x "$SYSTEM_BIN"
}

setup_python_venv() {
    if [[ ! -d "$VENV_DIR" ]]; then python3 -m venv "$VENV_DIR"; fi
    "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
    "${VENV_DIR}/bin/pip" install --quiet scapy
}

write_scan_engine() {
    mkdir -p "$BIN_DIR"
    cat > "$SCAN_ENGINE" <<'PYEOF'
#!/usr/bin/env python3
import sys, json, time, threading, subprocess, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, Dot11Beacon, Dot11ProbeResp, RadioTap, Dot11Elt

def channel_hopper(iface):
    channels = list(range(1, 14))
    idx = 0
    while True:
        try: subprocess.run(["iw", "dev", iface, "set", "channel", str(channels[idx])], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass
        idx = (idx + 1) % len(channels)
        time.sleep(0.5)

def get_ssid_and_channel(pkt, stats):
    ssid = stats.get("ssid") or ""
    channel = stats.get("channel") or 0
    if not ssid or channel == 0:
        el = pkt[Dot11Elt]
        while el:
            if el.ID == 0:
                try: ssid = el.info.decode('utf-8', errors='replace')
                except: pass
            elif el.ID == 3:
                try: channel = int(el.info[0])
                except: pass
            el = el.payload.getlayer(Dot11Elt)
    if isinstance(ssid, bytes): ssid = ssid.decode("utf-8", errors="replace")
    return str(ssid), int(channel)

def crypto_string(stats):
    crypto = stats.get("crypto")
    return "[OPEN]" if not crypto else "[" + "-".join(sorted(str(c) for c in crypto)) + "]"

def handle_packet(pkt):
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)): return
    layer = pkt[Dot11Beacon] if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp]
    try: stats = layer.network_stats()
    except: stats = {}
    bssid = pkt.addr2
    if not bssid: return
    ssid, channel = get_ssid_and_channel(pkt, stats)
    rssi = -100
    if pkt.haslayer(RadioTap):
        signal = getattr(pkt[RadioTap], "dBm_AntSignal", None)
        if signal is not None: rssi = int(signal)
    record = {"bssid": bssid, "ssid": ssid, "channel": channel, "rssi": rssi, "auth": crypto_string(stats)}
    print(json.dumps(record), flush=True)

def main():
    if len(sys.argv) < 2: sys.exit(1)
    iface = sys.argv[1]
    threading.Thread(target=channel_hopper, args=(iface,), daemon=True).start()
    try: sniff(iface=iface, prn=handle_packet, store=0)
    except Exception as exc: sys.exit(1)

if __name__ == "__main__": main()
PYEOF
    chmod +x "$SCAN_ENGINE"
}

install_dependencies() {
    require_root || return 1
    apt-get update -qq
    apt-get install -y "${APT_PACKAGES[@]}"
    setup_python_venv
    write_scan_engine
    create_global_link
    mkdir -p "$LOG_DIR" "$STATE_DIR"
    touch "$INSTALL_MARKER"
    log_ok "Setup voltooid."
}

detect_gps_devices() { for dev in /dev/ttyUSB* /dev/ttyACM*; do [[ -e "$dev" ]] && echo "$dev"; done; }

get_gps_fix() {
    local json; json=$(timeout 2 gpspipe -w -n 15 2>/dev/null | tr -d '\0' | grep -m1 '"class":"TPV"' || true)
    json=$(echo -n "$json" | tr -cd '[:print:]')
    if [[ -z "$json" ]]; then printf '%s' "SIGNAL_LOSS,SIGNAL_LOSS,0.0,0.0"; return; fi
    local lat; lat=$(echo "$json" | jq -r '.lat // "SIGNAL_LOSS"')
    local lon; lon=$(echo "$json" | jq -r '.lon // "SIGNAL_LOSS"')
    local alt; alt=$(echo "$json" | jq -r '.alt // "0.0"')
    local acc; acc=$(echo "$json" | jq -r '.epx // .eph // "0.0"')
    printf '%s,%s,%s,%s' "$lat" "$lon" "$alt" "$acc"
}

detect_wlan_interfaces() { iw dev | awk '$1=="Interface"{print $2}'; }

supports_monitor_mode() { iw phy "$(iw dev "$1" info | awk '/wiphy/{print "phy"$2}')" info | grep -qi monitor; }

select_wlan_interface() {
    local ifaces=(); while IFS= read -r line; do [[ -n "$line" ]] && ifaces+=("$line"); done < <(detect_wlan_interfaces)
    [[ ${#ifaces[@]} -eq 0 ]] && { log_error "Geen interfaces gevonden."; return 1; }
    echo -e "${C_GOLD}Selecteer de interface voor de expeditie:${C_RESET}" >&2
    local choice; select choice in "${ifaces[@]}"; do [[ -n "$choice" ]] && { echo "$choice"; return 0; }; done
}

enable_monitor_mode() {
    local iface="$1"
    ip link set "$iface" down
    iw dev "$iface" set type monitor || airmon-ng start "$iface"
    ip link set "$iface" up
    echo "$iface"
}

disable_monitor_mode() {
    local mon="$1"
    ip link set "$mon" down
    iw dev "$mon" set type managed || airmon-ng stop "$mon"
    ip link set "$mon" up
}

run_loot_feed() {
    local iface="$1"; clear
    echo -e "${C_OCEAN}=== LOOT FEED (Ctrl+C om te stoppen) ===${C_RESET}"
    SEEN_BSSIDS=(); SCAN_COUNT=0
    while IFS= read -r raw; do
        local line; line=$(echo -n "$raw" | tr -cd '[:print:]')
        [[ -z "$line" ]] && continue
        local bssid; bssid=$(echo "$line" | jq -r '.bssid')
        [[ -n "${SEEN_BSSIDS[$bssid]:-}" ]] && continue
        SEEN_BSSIDS[$bssid]=1; SCAN_COUNT=$((SCAN_COUNT + 1))
        local lat lon alt acc; IFS=',' read -r lat lon alt acc <<< "$(get_gps_fix)"
        printf '%s,"%s",%s,%s,%s,%s,%s,%s,%s,%s,WIFI\n' "$bssid" "$(echo "$line" | jq -r '.ssid')" "$(echo "$line" | jq -r '.auth')" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$(echo "$line" | jq -r '.channel')" "$(echo "$line" | jq -r '.rssi')" "$lat" "$lon" "$alt" "$acc" >> "$CURRENT_LOG_FILE"
        printf "${C_GOLD}%-14.14s${C_RESET} rssi:%s\n" "$(echo "$line" | jq -r '.ssid')" "$(echo "$line" | jq -r '.rssi')"
    done < <("${VENV_DIR}/bin/python3" "$SCAN_ENGINE" "$iface" 2>/dev/null)
}

main_menu() {
    while true; do
        print_banner
        echo -e "[1] Start Expedition\n[2] Stop & Secure\n[3] View Logs\n[4] Update\n[5] Exit"
        read -rp "Keuze: " choice
        case "$choice" in
            1) local iface; iface=$(select_wlan_interface); CURRENT_LOG_FILE="${LOG_DIR}/wardrive_$(date +%Y%m%d_%H%M%S).csv"; local mon; mon=$(enable_monitor_mode "$iface"); trap 'disable_monitor_mode "$mon"; exit' INT; run_loot_feed "$mon"; disable_monitor_mode "$mon";;
            2) log_info "Beveiliging actief.";;
            3) ls -lh "$LOG_DIR";;
            4) git pull;;
            5) exit 0;;
        esac
    done
}

case "${1:-}" in
    --install) install_dependencies;;
    *) main_menu;;
esac
