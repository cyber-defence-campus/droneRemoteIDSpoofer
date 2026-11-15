"""
Finding the nRF BLE sniffer's serial port and freeing it from this scanner's own stale processes.

The sniffer is recognised by its USB vendor, never by the device name alone: any /dev/ttyACM* or
/dev/ttyUSB* could be a GPS receiver or a modem, and talking the sniffer protocol to it would
disturb that device and capture nothing.
"""

import logging
import os
import signal
from typing import Iterable, List, Optional, Tuple

logger = logging.getLogger("CombinedRIDListener.NrfDevice")

# USB vendors of nRF sniffer hardware: Nordic (nRF52840 dongle, native USB) and SEGGER (the J-Link
# serial port of an nRF52840 DK)
NORDIC_USB_VID = "1915"
SEGGER_USB_VID = "1366"
SNIFFER_USB_VIDS = (NORDIC_USB_VID, SEGGER_USB_VID)
SERIAL_PORT_PREFIXES = ("ttyACM", "ttyUSB")
NRF_SNIFFER_SCRIPT = "nrf_bt_sniffer_json.py"


def usb_vendor_of_tty(name: str, sys_root: str = "/sys") -> Optional[str]:
    """USB vendor ID (4 hex digits) of a tty device such as "ttyACM0", or None if it is not USB."""
    device = os.path.join(sys_root, "class", "tty", name, "device")
    if not os.path.exists(device):
        return None
    path = os.path.realpath(device)
    devices_root = os.path.realpath(os.path.join(sys_root, "devices"))
    while path.startswith(devices_root) and path != devices_root:
        try:
            with open(os.path.join(path, "idVendor")) as f:
                return f.read().strip().lower()
        except OSError:
            path = os.path.dirname(path)
    return None


def find_sniffer_ports(sys_root: str = "/sys", dev_root: str = "/dev") -> List[str]:
    """Serial ports of connected nRF sniffer hardware, Nordic devices first."""
    try:
        names = sorted(n for n in os.listdir(os.path.join(sys_root, "class", "tty")) if n.startswith(SERIAL_PORT_PREFIXES))
    except OSError:
        return []
    ports = []
    for name in names:
        vendor = usb_vendor_of_tty(name, sys_root)
        if vendor in SNIFFER_USB_VIDS:
            ports.append((SNIFFER_USB_VIDS.index(vendor), os.path.join(dev_root, name)))
    return [port for _, port in sorted(ports)]


def resolve_sniffer_port(configured: Optional[str], sys_root: str = "/sys", dev_root: str = "/dev") -> Optional[str]:
    """
    The serial port to use: the configured one if it exists, otherwise the first connected sniffer
    (a dongle can come back under another name after a USB reset), otherwise None.
    """
    if configured and os.path.exists(configured):
        return configured
    detected = find_sniffer_ports(sys_root, dev_root)
    if configured and detected:
        logger.warning(f"[!] Configured nRF port {configured} not found; using the nRF sniffer on {detected[0]}")
    return detected[0] if detected else None


def _read(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def _pids(proc_root: str) -> Iterable[int]:
    try:
        return [int(n) for n in os.listdir(proc_root) if n.isdigit()]
    except OSError:
        return []


def _comm(pid: int, proc_root: str) -> str:
    return (_read(os.path.join(proc_root, str(pid), "comm")) or b"").decode(errors="replace").strip()


def _holds_open(pid: int, target: str, proc_root: str) -> bool:
    fd_dir = os.path.join(proc_root, str(pid), "fd")
    try:
        fds = os.listdir(fd_dir)
    except OSError:
        return False
    for fd in fds:
        try:
            if os.path.realpath(os.path.join(fd_dir, fd)) == target:
                return True
        except OSError:
            continue
    return False


def stop_stale_sniffer_processes(port: str, script_path: str, proc_root: str = "/proc",
                                 kill=os.kill) -> List[int]:
    """
    Stops what is left of an earlier run of this scanner on port: sniffer scripts (script_path)
    started for that port, which hold the port themselves. Other processes using the port are left
    alone (see port_holders). Returns the PIDs signalled.
    """
    target = os.path.realpath(port)
    script = os.path.realpath(script_path)
    own_pid = os.getpid()
    killed = []
    for pid in _pids(proc_root):
        if pid == own_pid:
            continue
        cmdline = _read(os.path.join(proc_root, str(pid), "cmdline"))
        if not cmdline:
            continue
        args = [a.decode(errors="replace") for a in cmdline.split(b"\0") if a]
        if not any(os.path.realpath(a) == script for a in args if a.endswith(NRF_SNIFFER_SCRIPT)):
            continue
        if "--nrf-port" in args[:-1] and os.path.realpath(args[args.index("--nrf-port") + 1]) == target:
            logger.warning(f"[!] Stopping stale nRF sniffer script (PID {pid}) left on {port} by an earlier run")
            try:
                kill(pid, signal.SIGKILL)
                killed.append(pid)
            except OSError:
                pass
    return killed


def port_holders(port: str, proc_root: str = "/proc") -> List[Tuple[int, str]]:
    """(PID, command name) of the other processes that have port open."""
    target = os.path.realpath(port)
    own_pid = os.getpid()
    return [(pid, _comm(pid, proc_root) or "?") for pid in _pids(proc_root)
            if pid != own_pid and _holds_open(pid, target, proc_root)]
