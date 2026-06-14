#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

readonly APP_NAME="WAR SAILING"
readonly APP_VERSION="1.1.0"
readonly DATA_DIR="${HOME}/.warsailing"
readonly LOG_DIR="${DATA_DIR}/logs"
readonly BIN_DIR="${DATA_DIR}/bin"
readonly VENV_DIR="${DATA_DIR}/venv"
readonly STATE_DIR="${DATA_DIR}/run"
readonly INSTALL_MARKER="${DATA_DIR}/.installed"
readonly SCAN_ENGINE="${BIN_DIR}/scan_engine.py"

readonly APT_PACKAGES=(gpsd gpsd-clients iw wireless-tools aircrack-ng tshark jq python3 python3-venv python3-pip libpcap-dev)

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
        log_error "This action requires root. Re-run with: sudo $0"
        return 1
    fi
    return 0
}

print_banner() {
    clear
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
    printf "%s          \"LETS EXPLORE THE 7 SEA'S AND CONQUER FOR WALHALLA\"%s\n\n" "${C_STEEL}${C_BOLD}" "${C_RESET}"
}

detect_distro() {
    if [[ -r /etc/os-release ]]; then
        source /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

assert_debian_based() {
    local distro
    distro=$(detect_distro)
    case "$distro" in
        debian|ubuntu|kali|raspbian) return 0 ;;
        *)
            log_warn "Unrecognized distro '${distro}' — continuing, but apt may fail."
            ;;
    esac
}

setup_python_venv() {
    log_info "Setting up isolated Python environment..."
    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
    fi
    "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
    "${VENV_DIR}/bin/pip" install --quiet scapy
    log_ok "Python environment ready."
}

write_scan_engine() {
    mkdir -p "$BIN_DIR"
    cat > "$SCAN_ENGINE" <<'PYEOF'
#!/usr/bin/env python3
import sys
import json
import time
import threading
import subprocess
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, Dot11Beacon, Dot11ProbeResp, RadioTap, Dot11Elt

def channel_hopper(iface):
    channels = list(range(1, 14))
    idx = 0
    while True:
        ch = channels[idx]
        try:
            subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
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
                except Exception: pass
            elif el.ID == 3:
                try: channel = int(el.info[0])
                except Exception: pass
            el = el.payload.getlayer(Dot11Elt)
            
    if isinstance(ssid, bytes):
        ssid = ssid.decode("utf-8", errors="replace")
    return str(ssid), int(channel)

def crypto_string(stats):
    crypto = stats.get("crypto")
    if not crypto:
        return "[OPEN]"
    return "[" + "-".join(sorted(str(c) for c in crypto)) + "]"

def handle_packet(pkt):
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return
    layer = pkt[Dot11Beacon] if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp]
    
    try: stats = layer.network_stats()
    except Exception: stats = {}

    bssid = pkt.addr2
    if not bssid: return

    ssid, channel = get_ssid_and_channel(pkt, stats)
    
    rssi = -100
    if pkt.haslayer(RadioTap):
        signal = getattr(pkt[RadioTap], "dBm_AntSignal", None)
        if signal is not None:
            rssi = int(signal)

    record = {
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "rssi": rssi,
        "auth": crypto_string(stats),
    }
    print(json.dumps(record), flush=True)

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    iface = sys.argv[1]
    
    hop_thread = threading.Thread(target=channel_hopper, args=(iface,), daemon=True)
    hop_thread.start()

    try:
        sniff(iface=iface, prn=handle_packet, store=0)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
PYEOF
    chmod +x "$SCAN_ENGINE"
}

install_dependencies() {
    require_root || die "Installation must be run as root (sudo $0 --install)."
    assert_debian_based
    log_info "Updating package index..."
    apt-get update -qq

    local missing=()
    for pkg in "${APT_PACKAGES[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null; then missing+=("$pkg"); fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_ok "All required packages are present."
    else
        log_info "Installing required packages..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
    fi

    if command_exists dpkg-reconfigure; then
        echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
        DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common &>/dev/null || true
        usermod -aG wireshark "${SUDO_USER:-$USER}" 2>/dev/null || true
    fi

    setup_python_venv
    write_scan_engine
    mkdir -p "$LOG_DIR" "$STATE_DIR"
    touch "$INSTALL_MARKER"
    log_ok "Setup complete."
}

detect_gps_devices() {
    local devices=()
    for dev in /dev/ttyUSB* /dev/ttyACM*; do
        [[ -e "$dev" ]] && devices+=("$dev")
    done
    if [[ ${#devices[@]} -gt 0 ]]; then printf '%s\n' "${devices[@]}"; fi
}

ensure_gpsd_running() {
    if pgrep -x gpsd &>/dev/null; then
        log_ok "gpsd is running."
        return 0
    fi

    local candidates=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && candidates+=("$line")
    done < <(detect_gps_devices)

    if [[ ${#candidates[@]} -eq 0 ]]; then
        log_warn "No GPS hardware found. Logging with placeholder 0.0 coördinates."
        return 1
    fi

    GPSD_DEVICE="${candidates[0]}"
    log_info "Launching gpsd on ${GPSD_DEVICE}..."
    gpsd -n "$GPSD_DEVICE" -F "${STATE_DIR}/gpsd.sock"
    WE_STARTED_GPSD=1
    sleep 1
    return 0
}

stop_gpsd_if_we_started_it() {
    if [[ "$WE_STARTED_GPSD" -eq 1 ]]; then
        log_info "Terminating gpsd..."
        pkill -x gpsd 2>/dev/null || true
        WE_STARTED_GPSD=0
    fi
}

get_gps_fix() {
    local json
    json=$(timeout 2 gpspipe -w -n 15 2>/dev/null | grep -m1 '"class":"TPV"' || true)
    if [[ -z "$json" ]]; then
        printf '%s' "0.000000,0.000000,0.0,0.0"
        return
    fi
    printf '%s,%s,%s,%s' "$(echo "$json" | jq -r '.lat // 0')" "$(echo "$json" | jq -r '.lon // 0')" "$(echo "$json" | jq -r '.alt // 0')" "$(echo "$json" | jq -r '.epx // .eph // 0')"
}

detect_wlan_interfaces() {
    iw dev 2>/dev/null | awk '$1=="Interface"{print $2}'
}

interface_phy() {
    iw dev "$1" info 2>/dev/null | awk '/wiphy/{print "phy"$2}'
}

supports_monitor_mode() {
    local iface="$1" phy
    phy=$(interface_phy "$iface")
    [[ -z "$phy" ]] && return 1
    iw phy "$phy" info 2>/dev/null | awk '/Supported interface modes/{f=1;next} /^\t\t\*/{if(f)print} /^\t[A-Z]/{f=0}' | grep -qi monitor
}

select_wlan_interface() {
    local ifaces=()
    while IFS= read -r line; do [[ -n "$line" ]] && ifaces+=("$line"); done < <(detect_wlan_interfaces)
    if [[ ${#ifaces[@]} -eq 0 ]]; then log_error "No wireless interface detected."; return 1; fi

    local candidates=()
    for iface in "${ifaces[@]}"; do if supports_monitor_mode "$iface"; then candidates+=("$iface"); fi; done
    if [[ ${#candidates[@]} -eq 0 ]]; then echo "${ifaces[0]}"; return 0; fi
    if [[ ${#candidates[@]} -eq 1 ]]; then echo "${candidates[0]}"; return 0; fi

    echo -e "${C_GOLD}Multiple interfaces available:${C_RESET}" >&2
    local choice
    select choice in "${candidates[@]}"; do
        if [[ -n "$choice" ]]; then echo "$choice"; return 0; fi
    done
}

enable_monitor_mode() {
    local iface="$1"
    if command_exists airmon-ng; then
        airmon-ng check kill &>/dev/null || true
        airmon-ng start "$iface" &>/dev/null || true
        local mon
        mon=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -i "^${iface}mon" || true)
        if [[ -n "$mon" ]]; then echo "$mon"; return 0; fi
    fi
    ip link set "$iface" down
    iw dev "$iface" set type monitor
    ip link set "$iface" up
    echo "$iface"
}

disable_monitor_mode() {
    local mon_iface="$1"
    if command_exists airmon-ng && [[ "$mon_iface" == *mon ]]; then
        airmon-ng stop "$mon_iface" &>/dev/null || true
        systemctl restart NetworkManager &>/dev/null || service NetworkManager restart &>/dev/null || true
        return 0
    fi
    ip link set "$mon_iface" down 2>/dev/null || true
    iw dev "$mon_iface" set type managed 2>/dev/null || true
    ip link set "$mon_iface" up 2>/dev/null || true
}

init_log_file() {
    mkdir -p "$LOG_DIR"
    CURRENT_LOG_FILE="${LOG_DIR}/wardrive_$(date +"%Y%m%d_%H%M%S").csv"
    {
        echo "WigleWifi-1.6,appRelease=${APP_VERSION},model=WarSailing,release=Linux,device=$(hostname),display=cli,board=generic,brand=WarSailing"
        echo "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type"
    } > "$CURRENT_LOG_FILE"
    log_ok "Sails high. Writing logs to ${CURRENT_LOG_FILE}"
}

run_loot_feed() {
    local iface="$1"
    clear
    echo -e "${C_OCEAN}${C_BOLD}================== THE LOOT FEED ==================${C_RESET}"
    echo -e "${C_STEEL}Interface: ${C_GOLD}${iface}${C_STEEL}  |  Press ${C_BLOOD}Ctrl+C${C_STEEL} to drop anchor & secure camp${C_RESET}"
    echo -e "${C_OCEAN}====================================================${C_RESET}"

    SEEN_BSSIDS=()
    SCAN_COUNT=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local bssid ssid channel rssi auth
        bssid=$(echo "$line" | jq -r '.bssid // empty')
        [[ -z "$bssid" ]] && continue
        [[ -n "${SEEN_BSSIDS[$bssid]:-}" ]] && continue
        SEEN_BSSIDS[$bssid]=1
        SCAN_COUNT=$((SCAN_COUNT + 1))

        ssid=$(echo "$line" | jq -r '.ssid // ""')
        channel=$(echo "$line" | jq -r '.channel // 0')
        rssi=$(echo "$line" | jq -r '.rssi // -100')
        auth=$(echo "$line" | jq -r '.auth // "[UNKNOWN]"')

        local lat lon alt acc
        IFS=',' read -r lat lon alt acc <<< "$(get_gps_fix)"
        printf '%s,"%s",%s,%s,%s,%s,%s,%s,%s,%s,WIFI\n' "$bssid" "$ssid" "$auth" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$channel" "$rssi" "$lat" "$lon" "$alt" "$acc" >> "$CURRENT_LOG_FILE"

        local rssi_color="$C_STEEL"
        if   (( rssi >= -50 )); then rssi_color="$C_GREEN"
        elif (( rssi >= -70 )); then rssi_color="$C_GOLD"
        else                          rssi_color="$C_BLOOD"
        fi

        printf "${C_OCEAN}[%4d]${C_RESET} ${C_GOLD}%-24s${C_RESET} ${C_STEEL}%s${C_RESET} ch:${C_FOAM}%-3s${C_RESET} rssi:${rssi_color}%4s dBm${C_RESET} @ ${C_OCEAN_LT}%.5f,%.5f${C_RESET}\n" \
            "$SCAN_COUNT" "${ssid:-<hidden>}" "$bssid" "$channel" "$rssi" "$lat" "$lon"
    done < <("${VENV_DIR}/bin/python3" "$SCAN_ENGINE" "$iface" 2>/dev/null)
}

expedition_cleanup() {
    local mon_iface="$1"
    [[ "$CLEANED_UP" -eq 1 ]] && return 0
    CLEANED_UP=1
    echo
    log_info "Securing the ship and sails..."
    disable_monitor_mode "$mon_iface"
    stop_gpsd_if_we_started_it
    log_ok "Expedition terminated safely. Networks captured: ${SCAN_COUNT}"
}

menu_start_expedition() {
    require_root || return 0
    local iface mon_iface
    iface=$(select_wlan_interface) || return 0

    ensure_gpsd_running || true
    mon_iface=$(enable_monitor_mode "$iface")
    init_log_file

    CLEANED_UP=0
    trap 'expedition_cleanup "'"$mon_iface"'"; printf "\n%sFair winds, Viking. Walhalla awaits.%s\n" "${C_GOLD}${C_BOLD}" "${C_RESET}"; exit 0' INT TERM
    run_loot_feed "$mon_iface"
    expedition_cleanup "$mon_iface"
    trap - INT TERM
    read -rp "Press Enter to return to camp..." _ || true
}

menu_stop_and_secure() {
    require_root || return 0
    log_info "Inspecting active rigging..."
    local found=0 iface mode
    while IFS= read -r iface; do
        [[ -z "$iface" ]] && continue
        mode=$(iw dev "$iface" info 2>/dev/null | awk '/type/{print $2}')
        if [[ "$mode" == "monitor" ]]; then
            log_warn "Restoring ${iface} to normal state..."
            disable_monitor_mode "$iface"
            found=1
        fi
    done < <(detect_wlan_interfaces)

    if pgrep -x gpsd &>/dev/null; then
        pkill -x gpsd 2>/dev/null || true
        found=1
    fi
    [[ "$found" -eq 0 ]] && log_ok "Ship already secured." || log_ok "All hardware released."
}

menu_view_logs() {
    mkdir -p "$LOG_DIR"
    local files=()
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(ls -1t "${LOG_DIR}"/*.csv 2>/dev/null || true)
    if [[ ${#files[@]} -eq 0 ]]; then log_warn "No logs found."; return 0; fi

    echo -e "${C_GOLD}${C_BOLD}Saved expeditions:${C_RESET}"
    local i=1 count f_date
    for f in "${files[@]}"; do
        count=$(( $(wc -l < "$f") - 2 ))
        (( count < 0 )) && count=0
        f_date=$(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "unknown")
        printf "  %s[%2d]%s %-32s ${C_STEEL}(%d APs, %s)${C_RESET}\n" "$C_OCEAN_LT" "$i" "$C_RESET" "$(basename "$f")" "$count" "$f_date"
        i=$((i + 1))
    done

    echo
    local choice
    read -rp "$(printf '%sSelect a number to view, or press Enter to slip away: %s' "$C_GOLD" "$C_RESET")" choice || true
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#files[@]} )); then
        head -n 12 "${files[$((choice - 1))]}"
        echo
        read -rp "Press Enter to return..." _ || true
    fi
}

main_menu() {
    while true; do
        print_banner
        echo -e "${C_STEEL}Base: ${C_GOLD}${DATA_DIR}${C_RESET}\n"
        echo -e "  ${C_OCEAN_LT}${C_BOLD}[1]${C_RESET} Start Expedition (Scan)"
        echo -e "  ${C_OCEAN_LT}${C_BOLD}[2]${C_RESET} Stop & Secure Sails"
        echo -e "  ${C_OCEAN_LT}${C_BOLD}[3]${C_RESET} View Saved Logs"
        echo -e "  ${C_OCEAN_LT}${C_BOLD}[4]${C_RESET} Exit"
        echo
        local choice
        read -rp "$(printf '%sChoose your fate, Viking: %s' "$C_GOLD" "$C_RESET")" choice || choice=4
        case "$choice" in
            1) menu_start_expedition ;;
            2) menu_stop_and_secure; read -rp "Press Enter to continue..." _ || true ;;
            3) menu_view_logs ;;
            4) log_info "Fair winds. Walhalla awaits."; exit 0 ;;
            *) log_warn "Invalid selection."; sleep 1 ;;
        esac
    done
}

main() {
    mkdir -p "$DATA_DIR" "$LOG_DIR" "$STATE_DIR" "$BIN_DIR"
    case "${1:-}" in
        --install) print_banner; install_dependencies; exit 0 ;;
        --run) : ;;
        -h|--help) print_banner; echo "Usage: $0 [--install | --run | --help]"; exit 0 ;;
        "") if [[ ! -f "$INSTALL_MARKER" ]]; then print_banner; log_warn "First launch: deploying dependencies."; install_dependencies; fi ;;
        *) echo "Usage: $0 [--install | --run]"; exit 1 ;;
    esac
    main_menu
}

main "$@"
