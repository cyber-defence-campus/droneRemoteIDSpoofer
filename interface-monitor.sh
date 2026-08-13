#!/bin/bash
# Universal script to set an interface in monitor mode and optionally assign a channel.
# Attempts modern 'iw' commands first and falls back to 'iwconfig' if unsupported by driver.
#
# Features:
#   - Tab-completion for interface names (run with --install-completion)
#   - Interactive interface picker when no argument is given

# ── Helper: list wireless-capable network interfaces ──────────────────────────
_list_wireless_ifaces() {
    for iface in /sys/class/net/*/wireless; do
        [ -d "$iface" ] && basename "$(dirname "$iface")"
    done
}

_list_all_ifaces() {
    ls /sys/class/net/ 2>/dev/null
}

# ── Bash completion installer ─────────────────────────────────────────────────
if [ "$1" = "--install-completion" ]; then
    REAL_USER="${SUDO_USER:-$USER}"
    REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)
    [ -z "$REAL_HOME" ] && REAL_HOME="$HOME"

    COMP_CONTENT=$(cat << 'COMP_EOF'
_interface_monitor_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local cmd_idx=-1

    for i in "${!COMP_WORDS[@]}"; do
        case "${COMP_WORDS[$i]}" in
            *interface-monitor*)
                cmd_idx=$i
                break
                ;;
        esac
    done

    if [ "$cmd_idx" -ge 0 ]; then
        local arg_num=$((COMP_CWORD - cmd_idx))
        if [ "$arg_num" -eq 1 ]; then
            # First arg after script name: complete with network interface names
            COMPREPLY=( $(compgen -W "$(ls /sys/class/net/ 2>/dev/null) --install-completion" -- "$cur") )
        elif [ "$arg_num" -eq 2 ]; then
            # Second arg after script name: suggest common Wi-Fi channels
            COMPREPLY=( $(compgen -W "1 2 3 4 5 6 7 8 9 10 11 12 13 36 40 44 48 149 153 157 161 165" -- "$cur") )
        fi
    fi
}
complete -F _interface_monitor_completions interface-monitor.sh
complete -F _interface_monitor_completions ./interface-monitor.sh
complete -F _interface_monitor_completions interface-monitor
complete -F _interface_monitor_completions ./interface-monitor
COMP_EOF
)

    # 1. Install user-level completion files
    USER_COMP_DIR="${REAL_HOME}/.local/share/bash-completion/completions"
    mkdir -p "$USER_COMP_DIR"
    echo "$COMP_CONTENT" > "${USER_COMP_DIR}/interface-monitor"
    echo "$COMP_CONTENT" > "${USER_COMP_DIR}/interface-monitor.sh"
    [ -n "$SUDO_USER" ] && chown -R "$REAL_USER:$REAL_USER" "$USER_COMP_DIR"

    # 2. Persist in ~/.bashrc so completion loads on every login / reboot
    BASHRC="${REAL_HOME}/.bashrc"
    if [ -f "$BASHRC" ]; then
        SOURCE_LINE="[ -f \"${USER_COMP_DIR}/interface-monitor.sh\" ] && source \"${USER_COMP_DIR}/interface-monitor.sh\""
        if ! grep -q "interface-monitor" "$BASHRC"; then
            echo "" >> "$BASHRC"
            echo "# Auto-load interface-monitor bash completion" >> "$BASHRC"
            echo "$SOURCE_LINE" >> "$BASHRC"
            [ -n "$SUDO_USER" ] && chown "$REAL_USER:$REAL_USER" "$BASHRC"
        fi
    fi

    # 3. System-wide installation (if running as root/sudo)
    if [ "$(id -u)" -eq 0 ] && [ -d "/etc/bash_completion.d" ]; then
        echo "$COMP_CONTENT" > "/etc/bash_completion.d/interface-monitor"
        echo "$COMP_CONTENT" > "/etc/bash_completion.d/interface-monitor.sh"
        echo "[✓] System-wide Bash completion installed to /etc/bash_completion.d/"
    fi

    echo "[✓] Bash completion installed for user '${REAL_USER}' in: ${USER_COMP_DIR}/"
    echo "    Restart your shell or run:  source ~/.bashrc"
    exit 0
fi

# ── Interactive interface picker when no argument given ────────────────────────
INTERFACE=$1
CHANNEL=${2:-6}

if [ -z "$INTERFACE" ]; then
    # Gather wireless interfaces first, fall back to all interfaces
    mapfile -t WIRELESS_IFACES < <(_list_wireless_ifaces)
    mapfile -t ALL_IFACES < <(_list_all_ifaces)

    if [ ${#WIRELESS_IFACES[@]} -eq 0 ] && [ ${#ALL_IFACES[@]} -eq 0 ]; then
        echo "[!] No network interfaces found."
        echo "Usage: sudo $0 <interface> [channel (default: 6)]"
        exit 1
    fi

    # Prefer wireless interfaces, but show all as fallback
    if [ ${#WIRELESS_IFACES[@]} -gt 0 ]; then
        IFACES=("${WIRELESS_IFACES[@]}")
        echo "[*] Detected wireless interfaces:"
    else
        IFACES=("${ALL_IFACES[@]}")
        echo "[*] No wireless interfaces detected. Showing all interfaces:"
    fi

    # Display numbered menu
    for i in "${!IFACES[@]}"; do
        iface="${IFACES[$i]}"
        # Show current state (UP/DOWN) and driver info
        state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
        driver=$(basename "$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null)" 2>/dev/null || echo "–")
        mac=$(cat "/sys/class/net/$iface/address" 2>/dev/null || echo "–")
        printf "    [%d] %-16s  state=%-6s  driver=%-12s  mac=%s\n" $((i+1)) "$iface" "$state" "$driver" "$mac"
    done

    echo ""
    read -rp "Select interface [1-${#IFACES[@]}]: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#IFACES[@]} ]; then
        echo "[!] Invalid selection."
        exit 1
    fi
    INTERFACE="${IFACES[$((choice-1))]}"

    # Also prompt for channel if not provided
    read -rp "Channel [default: $CHANNEL]: " ch_input
    [ -n "$ch_input" ] && CHANNEL="$ch_input"
fi

echo ""
echo "[*] Taking $INTERFACE down..."
ip link set $INTERFACE down

echo "[*] Setting monitor mode on $INTERFACE..."
if ! iw dev $INTERFACE set type monitor 2>/dev/null; then
    echo "    -> 'iw' command not supported by driver. Falling back to 'iwconfig'..."
    iwconfig $INTERFACE mode monitor
else
    echo "    -> Successfully used 'iw'."
fi

echo "[*] Bringing $INTERFACE up..."
ip link set $INTERFACE up

if [ -n "$CHANNEL" ]; then
    echo "[*] Setting channel to $CHANNEL on $INTERFACE..."
    if ! iw dev $INTERFACE set channel $CHANNEL 2>/dev/null; then
        echo "    -> 'iw' command not supported/permitted. Falling back to 'iwconfig'..."
        iwconfig $INTERFACE channel $CHANNEL
    else
        echo "    -> Successfully used 'iw'."
    fi
fi

echo "[*] Done! $INTERFACE is configured in monitor mode (Channel: $CHANNEL)."
