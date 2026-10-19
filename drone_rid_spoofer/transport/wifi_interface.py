"""Monitor-mode configuration for Wi-Fi injection interfaces.

The spoofer already runs as root (raw AF_PACKET injection needs it), so the
transports configure monitor mode themselves rather than relying on an external
helper script. This mirrors the approach used by the RID_Scanner project.
"""
import logging
import subprocess
from typing import Optional, Set

logger = logging.getLogger(__name__)

# Interfaces this process took from NetworkManager, handed back by restore_managed_mode().
_released_from_network_manager: Set[str] = set()


def interface_type(interface: str) -> Optional[str]:
    """The interface's 802.11 type as iw reports it ("monitor", "managed", ...), or None if unknown."""
    try:
        res = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "type":
            return parts[1]
    return None


def _managed_by_network_manager(interface: str) -> bool:
    """True if NetworkManager manages the interface (GENERAL.STATE other than "10 (unmanaged)")."""
    try:
        res = subprocess.run(["nmcli", "-t", "-g", "GENERAL.STATE", "device", "show", interface],
                             capture_output=True, text=True, check=False)
    except OSError:
        return False  # no NetworkManager
    return res.returncode == 0 and bool(res.stdout.strip()) and not res.stdout.strip().startswith("10 ")


def setup_monitor_mode(interface: str, channel: int = 6) -> bool:
    """Put ``interface`` into monitor mode on ``channel``.

    Releases the interface from NetworkManager first so it is not reconfigured
    underneath us. Returns True if the interface is in monitor mode afterwards
    (including when it already was and a later step failed), False otherwise.
    """
    logger.info(f"Configuring {interface} into monitor mode on channel {channel}...")
    if _managed_by_network_manager(interface):
        res = subprocess.run(["nmcli", "dev", "set", interface, "managed", "no"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if res.returncode == 0:
            _released_from_network_manager.add(interface)
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["iw", "dev", interface, "set", "type", "monitor"], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        if interface_type(interface) != "monitor":
            logger.error(f"Could not put {interface} into monitor mode: {e}")
            return False
        logger.warning(f"{interface} is in monitor mode, but a setup step failed: {e}")
        return True
    if interface_type(interface) != "monitor":
        logger.error(f"{interface} did not switch to monitor mode (driver without monitor support?)")
        return False
    logger.info(f"{interface} is ready in monitor mode on channel {channel}.")
    return True


def restore_managed_mode(interface: str) -> None:
    """Restore managed mode and hand the interface back to NetworkManager if it was taken from it."""
    logger.info(f"Restoring {interface} to managed mode...")
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as e:
        logger.warning(f"Failed to restore {interface} to managed mode: {e}")
    if interface in _released_from_network_manager:
        subprocess.run(["nmcli", "dev", "set", interface, "managed", "yes"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        _released_from_network_manager.discard(interface)
