"""BLE transport backend for ASTM F3411-22 Remote ID.

Uses raw HCI sockets to send BLE ADV_NONCONN_IND advertisements.
Requires Linux with root privileges (same as Wi-Fi monitor mode).

BLE AD structure (31 bytes — legacy advertising limit):
  Length:    1 byte  (0x1E = 30)
  AD Type:  1 byte  (0x16 = Service Data - 16-bit UUID)
  UUID:     2 bytes (0xFFFA little-endian → 0xFA 0xFF)
  App Code: 1 byte  (0x0D for ASTM F3411)
  Counter:  1 byte  (increments per advertisement)
  Payload:  25 bytes (one ASTM message type)

One message per advertisement — rotates through types with Location
sent at higher frequency (3x).
"""

import logging
import select
import socket
import struct
import time
from typing import Dict, List, Optional

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.messages import MsgType
from drone_rid_spoofer.transport.base import TransportBackend

logger = logging.getLogger(__name__)

# HCI command opcodes (OGF << 10 | OCF)
HCI_CMD_LE_SET_ADV_PARAMS = 0x2006
HCI_CMD_LE_SET_ADV_DATA = 0x2008
HCI_CMD_LE_SET_ADV_ENABLE = 0x200A
HCI_CMD_LE_SET_RANDOM_ADDR = 0x2005

# HCI socket options (Linux)
SOL_HCI = 0
HCI_FILTER = 2

# HCI packet / event codes
HCI_EVENT_PKT = 0x04
EVT_CMD_COMPLETE = 0x0E
EVT_CMD_STATUS = 0x0F


def _build_event_filter() -> bytes:
    """HCI socket filter: receive Event packets, all event codes.

    Padded to 16 bytes to match sizeof(struct hci_filter) on Linux (the trailing
    uint16 opcode is followed by 2 bytes of struct alignment padding).
    """
    type_mask = 1 << HCI_EVENT_PKT
    event_mask_lo = 0xFFFFFFFF
    event_mask_hi = 0xFFFFFFFF
    return struct.pack("<IIIH", type_mask, event_mask_lo, event_mask_hi, 0) + b'\x00\x00'

# BLE RID constants
ASTM_UUID = b'\xFA\xFF'  # 0xFFFA little-endian
ASTM_APP_CODE = 0x0D
AD_TYPE_SERVICE_DATA_16 = 0x16

# Location message type is 1 (upper 4 bits)
def _mac_to_bytes(mac: str) -> bytes:
    """Convert MAC address string to 6 bytes (reverse order for HCI)."""
    parts = mac.split(':')
    return bytes(int(p, 16) for p in reversed(parts))


def _build_hci_command(opcode: int, data: bytes) -> bytes:
    """Build an HCI command packet."""
    # HCI command packet: type(1) + opcode(2) + param_len(1) + params
    return struct.pack('<BHB', 0x01, opcode, len(data)) + data


class BleBackend(TransportBackend):
    """BLE advertisement transport for ASTM F3411-22 RID.

    Sends one ASTM message per BLE advertisement, rotating through
    message types. Location is sent at 3x frequency for compliance.

    Multi-drone constraint: BLE has one radio, so drones are
    time-multiplexed. Each cycle emits 3x Location plus one rotating
    static message (BasicID, Self-ID, System, OperatorID), i.e. 4 ads
    per drone. At 200ms per ad and a 1s interval, two drones fit per
    cycle; reduce advertising_interval_ms (e.g. 100) to fit more.
    """

    def __init__(self, adapter: str = "hci0", advertising_interval_ms: int = 200):
        self.adapter = adapter
        self.adapter_id = int(adapter.replace("hci", ""))
        self.advertising_interval_ms = advertising_interval_ms
        self._sock: Optional[socket.socket] = None
        self._counters: Dict[bytes, int] = {}  # per-drone message counter
        self._static_index: Dict[bytes, int] = {}  # per-drone static-msg rotation pointer
        self._adv_enabled: bool = False  # tracked controller state; avoids redundant ENABLE/DISABLE
        self._open_socket()

    def _open_socket(self) -> None:
        """Open raw HCI socket and ensure the adapter is up."""
        try:
            # Bring the adapter up (equivalent to `hciconfig hci0 up`)
            import subprocess
            subprocess.run(
                ["hciconfig", self.adapter, "up"],
                check=True, capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise RuntimeError(
                f"Failed to bring up {self.adapter}. "
                f"Run 'sudo hciconfig {self.adapter} up' manually. Error: {e}"
            ) from e

        try:
            self._sock = socket.socket(
                socket.AF_BLUETOOTH,
                socket.SOCK_RAW,
                socket.BTPROTO_HCI,
            )
            self._sock.bind((self.adapter_id,))
        except (OSError, PermissionError) as e:
            raise RuntimeError(
                f"Failed to open HCI socket on {self.adapter}. "
                f"Requires root and Linux with Bluetooth adapter. Error: {e}"
            ) from e

        # Subscribe to HCI events so we can drain Command Complete/Status
        # responses. The kernel default filter already allows all events on
        # raw HCI sockets, so failure here is not fatal — we just keep going.
        try:
            self._sock.setsockopt(SOL_HCI, HCI_FILTER, _build_event_filter())
        except OSError as e:
            logger.warning(
                f"Could not set HCI event filter (using kernel default): {e}"
            )

        logger.info(f"BLE backend: opened HCI socket on {self.adapter}")

    def _send_hci_command(self, opcode: int, data: bytes) -> None:
        """Send an HCI command and wait for the controller's Command Complete."""
        cmd = _build_hci_command(opcode, data)
        self._sock.send(cmd)
        self._wait_for_command_complete(opcode)

    def _wait_for_command_complete(self, opcode: int, timeout: float = 0.5) -> None:
        """Drain HCI events until Command Complete/Status for `opcode` arrives.

        Logs (but does not raise) on non-zero status so a single rejected MAC
        or transient error doesn't tear down the whole session.
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.debug(
                    f"HCI cmd 0x{opcode:04x}: no response within {timeout}s"
                )
                return
            ready, _, _ = select.select([self._sock], [], [], remaining)
            if not ready:
                continue
            try:
                pkt = self._sock.recv(258)  # max HCI event packet
            except OSError as e:
                logger.debug(f"HCI recv error: {e}")
                return
            if len(pkt) < 3 or pkt[0] != HCI_EVENT_PKT:
                continue
            event_code = pkt[1]
            if event_code == EVT_CMD_COMPLETE and len(pkt) >= 7:
                evt_opcode = struct.unpack("<H", pkt[4:6])[0]
                status = pkt[6]
            elif event_code == EVT_CMD_STATUS and len(pkt) >= 7:
                status = pkt[3]
                evt_opcode = struct.unpack("<H", pkt[5:7])[0]
            else:
                continue  # unrelated event, keep draining
            if evt_opcode != opcode:
                continue
            if status != 0:
                # 0x0C "Command Disallowed" on LE_SET_ADV_ENABLE just means
                # advertising was already in the requested state — benign.
                if (opcode == HCI_CMD_LE_SET_ADV_ENABLE and status == 0x0C):
                    logger.debug(
                        f"HCI cmd 0x{opcode:04x} no-op: status=0x{status:02x}"
                    )
                else:
                    logger.warning(
                        f"HCI cmd 0x{opcode:04x} failed: status=0x{status:02x}"
                    )
            return

    def _set_advertising_enable(self, enable: bool) -> None:
        """Enable or disable BLE advertising. No-op when already in that state."""
        if enable == self._adv_enabled:
            return
        self._send_hci_command(HCI_CMD_LE_SET_ADV_ENABLE, bytes([int(enable)]))
        self._adv_enabled = enable

    def _set_random_address(self, mac: str) -> None:
        """Set the random advertising address."""
        addr_bytes = _mac_to_bytes(mac)
        self._send_hci_command(HCI_CMD_LE_SET_RANDOM_ADDR, addr_bytes)

    def _set_advertising_params(self) -> None:
        """Set advertising parameters for ADV_NONCONN_IND."""
        # Interval in units of 0.625ms
        interval = int(self.advertising_interval_ms / 0.625)
        params = struct.pack('<HH', interval, interval)  # min, max interval
        params += bytes([
            0x03,  # ADV_NONCONN_IND
            0x01,  # own address type: random
            0x00,  # peer address type
        ])
        params += b'\x00' * 6  # peer address
        params += bytes([
            0x07,  # channel map: all three channels (37, 38, 39)
            0x00,  # filter policy: allow all
        ])
        self._send_hci_command(HCI_CMD_LE_SET_ADV_PARAMS, params)

    def _set_advertising_data(self, message: bytes, counter: int) -> None:
        """Set the advertising data payload (31 bytes max).

        AD structure:
          [length=30][AD type=0x16][UUID 0xFFFA LE][app=0x0D][counter][25-byte payload]
        """
        ad_data = bytes([
            30,  # length of remaining AD data
            AD_TYPE_SERVICE_DATA_16,
        ]) + ASTM_UUID + bytes([
            ASTM_APP_CODE,
            counter & 0xFF,
        ]) + message

        # HCI LE Set Advertising Data: length(1) + data(31)
        hci_data = bytes([len(ad_data)]) + ad_data + b'\x00' * (31 - len(ad_data))
        self._send_hci_command(HCI_CMD_LE_SET_ADV_DATA, hci_data)

    def _build_send_sequence(self, drone_key: bytes,
                             messages: List[bytes]) -> List[bytes]:
        """Return per-cycle send sequence: 3x Location + 1 rotating static msg.

        Static messages (BasicID, Self-ID, System, OperatorID) rotate one per
        cycle so each is refreshed every N cycles, where N = number of statics.
        """
        location_msgs = [m for m in messages if m and (m[0] >> 4) == MsgType.LOCATION]
        static_msgs = [m for m in messages if m and (m[0] >> 4) != MsgType.LOCATION]

        sequence = location_msgs * 3
        if static_msgs:
            idx = self._static_index.get(drone_key, 0) % len(static_msgs)
            sequence.append(static_msgs[idx])
            self._static_index[drone_key] = (idx + 1) % len(static_msgs)
        return sequence

    def send_messages(self, drone: DroneState, messages: List[bytes]) -> None:
        """Send ASTM messages as individual BLE advertisements.

        Each cycle sends Location at 3x and one rotating static message
        (BasicID/Self-ID/System/OperatorID), keeping the per-drone budget
        at 4 advertisements.
        """
        if not self._sock:
            logger.error("BLE socket not open")
            return

        # Get or initialize counter for this drone
        drone_key = drone.serial
        counter = self._counters.get(drone_key, 0)

        # Disable advertising before reconfiguring
        self._set_advertising_enable(False)

        # Set random address to drone's MAC
        self._set_random_address(drone.ble_address)
        self._set_advertising_params()

        send_sequence = self._build_send_sequence(drone_key, messages)

        for msg in send_sequence:
            self._set_advertising_data(msg, counter)
            self._set_advertising_enable(True)

            # Let the advertisement transmit
            time.sleep(self.advertising_interval_ms / 1000.0)

            self._set_advertising_enable(False)
            counter = (counter + 1) & 0xFF

        self._counters[drone_key] = counter

    def close(self) -> None:
        """Disable advertising and close HCI socket."""
        if self._sock:
            try:
                self._set_advertising_enable(False)
            except OSError:
                pass
            self._sock.close()
            self._sock = None
            logger.info("BLE backend: closed HCI socket")
