# Bash completion for the drone-spoofer command (Drone Remote ID Spoofer).
#
# Completes interface names for -i/--interface, Wi-Fi channels for
# --wifi-channel, BLE adapters for --ble-adapter, and the fixed choice lists
# for --transport, --ble-mode and --nan-mode.
#
# Install with:  ./completion/install-completion.sh
# Or load once:  source completion/drone-spoofer.bash
#
# The spoofer needs root, so run the entry point by path:
#   sudo .venv/bin/drone-spoofer -i <tab>
# That bypasses sudo's secure_path and uses the venv interpreter, and completion
# still fires because bash-completion's sudo delegation matches the basename.
# (`drone-spoofer ...` without sudo completes too.)

_drone_spoofer_wireless_ifaces() {
    local iface found=0
    for iface in /sys/class/net/*/wireless; do
        if [ -d "$iface" ]; then
            basename "$(dirname "$iface")"
            found=1
        fi
    done
    # Fall back to all interfaces if no wireless-capable ones are detected.
    [ "$found" -eq 0 ] && ls /sys/class/net/ 2>/dev/null
}

_drone_spoofer_ble_adapters() {
    # Only top-level adapters (hci0, hci1, ...), not child device entries (hci0:51).
    ls /sys/class/bluetooth/ 2>/dev/null | grep -E '^hci[0-9]+$'
}

_drone_spoofer_completions() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local flags="-i --interface -m --manual -r --random -s --serial \
-n --interval -l --location -c --config -v --verbose -t --transport \
--ble-adapter --ble-interval --ble-extended-interval --ble-mode \
--wifi-ess --no-self-id --no-operator-id --wifi-channel --wifi-beacon-interval \
--nan-port --nan-mode --nan-cluster-id --nan-instance-id -h --help"

    local channels="1 2 3 4 5 6 7 8 9 10 11 12 13 36 40 44 48 149 153 157 161 165"

    case "$prev" in
        -i|--interface)
            COMPREPLY=( $(compgen -W "$(_drone_spoofer_wireless_ifaces)" -- "$cur") )
            return 0
            ;;
        --wifi-channel)
            COMPREPLY=( $(compgen -W "$channels" -- "$cur") )
            return 0
            ;;
        -t|--transport)
            COMPREPLY=( $(compgen -W "wifi ble nan both all" -- "$cur") )
            return 0
            ;;
        --ble-mode)
            COMPREPLY=( $(compgen -W "extended ext-legacy legacy dual" -- "$cur") )
            return 0
            ;;
        --nan-mode)
            COMPREPLY=( $(compgen -W "bridge manual" -- "$cur") )
            return 0
            ;;
        --ble-adapter)
            COMPREPLY=( $(compgen -W "$(_drone_spoofer_ble_adapters)" -- "$cur") )
            return 0
            ;;
        -c|--config)
            # Scenario JSON path: fall back to filename completion.
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
    esac

    # Default: complete option flags (only when the user is typing one).
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
    else
        COMPREPLY=( $(compgen -f -- "$cur") )
    fi
    return 0
}

# Console-script entry point (pip install -e .): `drone-spoofer` on PATH.
# This also covers `sudo .venv/bin/drone-spoofer ...` via bash-completion's
# sudo delegation, which matches on the command basename.
complete -F _drone_spoofer_completions drone-spoofer
