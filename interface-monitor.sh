#!/bin/bash
# Universal script to set an interface in monitor mode and optionally assign a channel.
# Attempts modern 'iw' commands first and falls back to 'iwconfig' if unsupported by driver.

INTERFACE=$1
CHANNEL=${2:-6}

if [ -z "$INTERFACE" ]; then
    echo "Usage: sudo $0 <interface> [channel (default: 6)]"
    exit 1
fi

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
