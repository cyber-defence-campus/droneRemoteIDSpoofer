#!/bin/bash
# Install bash completion for spoof_drones.py.
#
# Installs the completion for the invoking user (and system-wide when run with
# sudo), and adds a source line to ~/.bashrc so it loads in new shells.
#
# Usage:
#   ./completion/install-completion.sh
#   sudo ./completion/install-completion.sh   # also installs system-wide

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMP_SRC="${SCRIPT_DIR}/drone-spoofer.bash"

if [ ! -f "$COMP_SRC" ]; then
    echo "[!] Completion file not found: $COMP_SRC"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)
[ -z "$REAL_HOME" ] && REAL_HOME="$HOME"

# 1. User-level completion file. bash-completion lazy-loads a file named after
#    the command being completed, so install it as `drone-spoofer`.
USER_COMP_DIR="${REAL_HOME}/.local/share/bash-completion/completions"
mkdir -p "$USER_COMP_DIR"
cp "$COMP_SRC" "${USER_COMP_DIR}/drone-spoofer"
[ -n "$SUDO_USER" ] && chown -R "$REAL_USER:$REAL_USER" "${REAL_HOME}/.local/share/bash-completion"

# 2. Persist a source line in ~/.bashrc so completion loads on every shell
BASHRC="${REAL_HOME}/.bashrc"
SOURCE_LINE="[ -f \"${USER_COMP_DIR}/drone-spoofer\" ] && source \"${USER_COMP_DIR}/drone-spoofer\""
if [ -f "$BASHRC" ] && ! grep -q "drone-spoofer bash completion" "$BASHRC"; then
    {
        echo ""
        echo "# Auto-load drone-spoofer bash completion"
        echo "$SOURCE_LINE"
    } >> "$BASHRC"
    [ -n "$SUDO_USER" ] && chown "$REAL_USER:$REAL_USER" "$BASHRC"
fi

# 3. System-wide installation (only when run as root)
if [ "$(id -u)" -eq 0 ] && [ -d "/etc/bash_completion.d" ]; then
    cp "$COMP_SRC" "/etc/bash_completion.d/drone-spoofer"
    echo "[✓] System-wide completion installed to /etc/bash_completion.d/drone-spoofer"
fi

echo "[✓] Completion installed for user '${REAL_USER}' in: ${USER_COMP_DIR}/"
echo "    Restart your shell or run:  source \"${USER_COMP_DIR}/spoof_drones.py\""
