"""BLE transport backend for ASTM F3411-22 Remote ID.

Two backend classes for different hardware capabilities:

  BleLegacyBackend — BLE 4 legacy HCI API (0x2005–0x200A).
    Uses ADV_NONCONN_IND with one 25-byte ASTM message per advertisement,
    rotating through types with Location sent at 3x frequency.
    Works on any BLE 4+ adapter.

  BleExtendedBackend — BLE 5 Extended Advertising HCI API (0x2035–0x2039).
    Handle 0: legacy PDU (properties=0x0010), 1M PHY — BLE 4 compat.
              Sends one ASTM message per advertisement, rotating through
              message types. Location is sent at 3x frequency for compliance.
    Handle 1: extended PDU (properties=0x0000), LE Coded PHY — carries
              a full ODID Message Pack with all messages in one shot.
    Requires a BLE 5 capable adapter.

Select via CLI: default is legacy, --ble-extended switches to extended.

Requires Linux with root privileges.
"""

import logging
import select
import socket
import struct
import subprocess
import time
from typing import Dict, List, Optional

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.messages import MsgType
from drone_rid_spoofer.transport.base import TransportBackend

logger = logging.getLogger(__name__)

# HCI socket options (Linux)
SOL_HCI = 0
HCI_FILTER = 2

# HCI packet / event codes
HCI_EVENT_PKT = 0x04
EVT_CMD_COMPLETE = 0x0E
EVT_CMD_STATUS = 0x0F

# BLE 4 Legacy HCI opcodes (BT Core §7.8.5–10)
HCI_CMD_LE_SET_RANDOM_ADDR = 0x2005
HCI_CMD_LE_SET_ADV_PARAMS = 0x2006
HCI_CMD_LE_SET_ADV_DATA = 0x2008
HCI_CMD_LE_SET_ADV_ENABLE = 0x200A

# BLE 5 Extended Advertising HCI opcodes (BT Core §7.8.52–56)
HCI_CMD_LE_SET_EXT_RANDOM_ADDR = 0x2035
HCI_CMD_LE_SET_EXT_ADV_PARAMS = 0x2036
HCI_CMD_LE_SET_EXT_ADV_DATA = 0x2037
HCI_CMD_LE_SET_EXT_ADV_ENABLE = 0x2039

# BLE RID constants
ASTM_UUID = b'\xFA\xFF'  # 0xFFFA little-endian
ASTM_APP_CODE = 0x0D
AD_TYPE_SERVICE_DATA_16 = 0x16


def _build_event_filter() -> bytes:
    """HCI socket filter: receive Event packets, all event codes.

    Padded to 16 bytes to match sizeof(struct hci_filter) on Linux (the trailing
    uint16 opcode is followed by 2 bytes of struct alignment padding).
    """
    type_mask = 1 << HCI_EVENT_PKT
    event_mask_lo = 0xFFFFFFFF
    event_mask_hi = 0xFFFFFFFF
    return struct.pack("<IIIH", type_mask, event_mask_lo, event_mask_hi, 0) + b'\x00\x00'


def _mac_to_bytes(mac: str) -> bytes:
    """Convert MAC address string to 6 bytes (reverse order for HCI)."""
    parts = mac.split(':')
    return bytes(int(p, 16) for p in reversed(parts))


def _build_hci_command(opcode: int, data: bytes) -> bytes:
    """Build an HCI command packet."""
    # HCI command packet: type(1) + opcode(2) + param_len(1) + params
    return struct.pack('<BHB', 0x01, opcode, len(data)) + data


# ── Shared base class ─────────────────────────────────────────────────────────

class _BleBase(TransportBackend):
    """Shared HCI plumbing for BLE backends.

    Handles socket setup, HCI command/event processing, and the ASTM
    message rotation sequence. Subclasses implement the actual advertising
    parameter/data/enable commands for their HCI API version.
    """

    # Subclasses set this so 0x0C "Command Disallowed" on enable/disable
    # is logged at debug level (benign) instead of warning.
    _ADV_ENABLE_OPCODES: tuple = ()

    def __init__(self, adapter: str = "hci0", advertising_interval_ms: int = 200,
                 protocol_version: int = 2):
        self.adapter = adapter
        self.adapter_id = int(adapter.replace("hci", ""))
        self.advertising_interval_ms = advertising_interval_ms
        self.protocol_version = protocol_version
        # Message pack header: msg_type (0xF = Pack) + ver, msg_size (0x19 = 25 bytes)
        self.pack_header_prefix = bytes([(MsgType.PACK << 4) | self.protocol_version, 0x19])
        self._sock: Optional[socket.socket] = None
        self._counters: Dict[bytes, int] = {}  # per-drone message counter
        self._static_index: Dict[bytes, int] = {}  # per-drone static-msg rotation pointer
        self._open_socket()
        self._init_advertising()

    def _open_socket(self) -> None:
        """Open raw HCI socket and ensure the adapter is up."""
        try:
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
                # 0x0C "Command Disallowed" on advertising enable/disable just
                # means advertising was already in the requested state — benign.
                if opcode in self._ADV_ENABLE_OPCODES and status == 0x0C:
                    logger.debug(
                        f"HCI cmd 0x{opcode:04x} no-op: status=0x{status:02x}"
                    )
                else:
                    logger.warning(
                        f"HCI cmd 0x{opcode:04x} failed: status=0x{status:02x}"
                    )
            return

    def _warn_if_bad_random_address(self, mac: str, addr_bytes: bytes) -> None:
        """Log a warning if MAC doesn't satisfy BLE Static Random Address format."""
        if addr_bytes[-1] & 0xC0 != 0xC0:
            logger.warning(
                f"BLE address {mac} does not have top 2 bits set — "
                f"not a valid BLE Static Random Address (BT Core Vol 6, Part B §1.3.2)"
            )

    def _build_send_sequence(self, drone_key: bytes,
                             messages: List[bytes]) -> List[bytes]:
        """Return per-cycle send sequence: 2x Location + 2 rotating static msgs.

        ASTM F3411-22a Timing Requirements:
          - Location/Vector: 1 Hz (at least once per second)
          - Other messages: 0.33 Hz (at least once every 3 seconds)

        With up to 4 static types (BasicID, SelfID, System, OperatorID),
        sending 2 rotating statics per cycle ensures a full refresh every
        2 seconds, satisfying the 3s requirement.
        """
        location_msgs = [m for m in messages if m and (m[0] >> 4) == MsgType.LOCATION]
        static_msgs = [m for m in messages if m and (m[0] >> 4) != MsgType.LOCATION]

        # Send location twice (if available)
        sequence = (location_msgs[:1] * 2) if location_msgs else []

        if static_msgs:
            idx = self._static_index.get(drone_key, 0)
            # Send 2 rotating statics
            for _ in range(min(2, len(static_msgs))):
                sequence.append(static_msgs[idx % len(static_msgs)])
                idx += 1
            self._static_index[drone_key] = idx % len(static_msgs)
        return sequence

    def _build_legacy_ad(self, message: bytes, counter: int) -> bytes:
        """Build a 31-byte legacy AD element for a single ASTM message."""
        return bytes([
            30,  # length of remaining AD data
            AD_TYPE_SERVICE_DATA_16,
        ]) + ASTM_UUID + bytes([
            ASTM_APP_CODE,
            counter & 0xFF,
        ]) + message

    def _init_advertising(self) -> None:
        """Subclasses configure their advertising sets here."""
        raise NotImplementedError

    def _disable_advertising(self) -> None:
        """Subclasses disable their advertising here."""
        raise NotImplementedError

    def close(self) -> None:
        """Disable advertising and close HCI socket."""
        if self._sock:
            try:
                self._disable_advertising()
            except OSError:
                pass
            self._sock.close()
            self._sock = None
            logger.info("BLE backend: closed HCI socket")


# ── BLE 4 Legacy backend ──────────────────────────────────────────────────────

class BleLegacyBackend(_BleBase):
    """BLE 4 Legacy Advertising transport for ASTM F3411-19/22 RID.

    Sends one ASTM message per BLE advertisement, rotating through
    message types (2x Location + 2x rotating Statics per cycle).
    Used for hardware that does not support BLE 5 Extended Advertising.
    Works on any BLE 4+ adapter.

    Multi-drone constraint: BLE has one radio, so drones are
    time-multiplexed. Each cycle emits 3x Location plus one rotating
    static message (BasicID, Self-ID, System, OperatorID), i.e. 4 ads
    per drone. At 200ms per ad and a 1s interval, two drones fit per
    cycle; reduce advertising_interval_ms (e.g. 100) to fit more.
    """

    _ADV_ENABLE_OPCODES = (HCI_CMD_LE_SET_ADV_ENABLE,)

    def __init__(self, adapter: str = "hci0", advertising_interval_ms: int = 200,
                 protocol_version: int = 2):
        self._adv_enabled: bool = False
        super().__init__(adapter, advertising_interval_ms, protocol_version)

    def _init_advertising(self) -> None:
        """No-op — legacy params are set each cycle in send_messages."""
        pass

    def _disable_advertising(self) -> None:
        self._set_advertising_enable(False)

    def _set_advertising_enable(self, enable: bool) -> None:
        """Enable or disable BLE advertising. No-op when already in that state."""
        if enable == self._adv_enabled:
            return
        self._send_hci_command(HCI_CMD_LE_SET_ADV_ENABLE, bytes([int(enable)]))
        self._adv_enabled = enable

    def _set_random_address(self, mac: str) -> None:
        """Set the random advertising address."""
        addr_bytes = _mac_to_bytes(mac)
        self._warn_if_bad_random_address(mac, addr_bytes)
        self._send_hci_command(HCI_CMD_LE_SET_RANDOM_ADDR, addr_bytes)

    def _set_advertising_params(self) -> None:
        """Set advertising parameters for ADV_NONCONN_IND."""
        # Interval is in units of 0.625 ms
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
        """Set the advertising data payload (31 bytes max)."""
        ad_data = self._build_legacy_ad(message, counter)
        # HCI LE Set Advertising Data: length(1) + data(31)
        hci_data = bytes([len(ad_data)]) + ad_data + b'\x00' * (31 - len(ad_data))
        self._send_hci_command(HCI_CMD_LE_SET_ADV_DATA, hci_data)

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


# ── BLE 5 Extended Advertising backend ─────────────────────────────────────────

class BleExtendedBackend(_BleBase):
    """BLE 5 Extended Advertising transport for ASTM F3411-22 RID.

    Uses BLE 5 Extended Advertising with two simultaneous handles:
      Handle 0: Legacy PDU (1M PHY) — BLE 4 compatible single-message rotation.
                Used for backward compatibility with standard RID scanners.
      Handle 1: Extended PDU (LE Coded PHY) — Full ODID Message Pack.
                Maximizes range and ensures all messages are received at once.

    Timing Model:
      The handles are decoupled. The Legacy PDU rotates through the message
      sequence with a fast 'legacy_interval_ms', while the Extended PDU pulses
      in the background at a slower 'extended_interval_ms'.
    """

    _ADV_ENABLE_OPCODES = (HCI_CMD_LE_SET_EXT_ADV_ENABLE,)

    def __init__(self, adapter: str = "hci0",
                 legacy_interval_ms: int = 100,
                 extended_interval_ms: int = 200,
                 protocol_version: int = 2):
        super().__init__(adapter, extended_interval_ms, protocol_version)
        self.legacy_interval_ms = legacy_interval_ms

    def _init_advertising(self) -> None:
        """Initialize extended advertising sets."""
        self._set_advertising_enable(False, [0x00, 0x01])
        # Handle 0: legacy PDU, 1M PHY — SID 0
        self._set_advertising_params(0x00, 0x0010, 0x01, 0x01, 0x00)
        # Handle 1: extended PDU, LE Coded PHY — SID 1
        self._set_advertising_params(0x01, 0x0000, 0x03, 0x03, 0x01)

    def _disable_advertising(self) -> None:
        self._set_advertising_enable(False, [])

    def _set_advertising_params(self, handle: int, properties: int,
                                 primary_phy: int, secondary_phy: int, sid: int,
                                 interval_ms: Optional[int] = None) -> None:
        """Set Extended Advertising Parameters for the given handle."""
        # Use provided override or the backend's default interval
        ival = interval_ms if interval_ms is not None else self.advertising_interval_ms
        # Interval is in units of 0.625 ms
        interval = int(ival / 0.625)
        interval_bytes = interval.to_bytes(3, byteorder='little')
        params = struct.pack("<BH", handle, properties)
        params += interval_bytes  # Min interval (24-bit)
        params += interval_bytes  # Max interval (24-bit)
        params += bytes([
            0x07,  # Primary Channel Map (37, 38, 39)
            0x01,  # Own address type (Random)
            0x00,  # Peer address type
        ])
        params += b'\x00' * 6  # Peer address
        params += bytes([
            0x00,  # Filter policy
            0x7F,  # Tx power (Host has no preference)
            primary_phy,
            0x00,  # Secondary Max Skip
            secondary_phy,
            sid & 0x0F,  # Advertising SID (must be unique for sets sharing an address)
            0x00,  # Scan Request Notification Enable
        ])
        self._send_hci_command(HCI_CMD_LE_SET_EXT_ADV_PARAMS, params)

    def _set_random_address(self, handle: int, mac: str) -> None:
        """Set the random MAC address for the given advertising handle."""
        addr_bytes = _mac_to_bytes(mac)
        self._warn_if_bad_random_address(mac, addr_bytes)
        payload = struct.pack("<B", handle) + addr_bytes
        self._send_hci_command(HCI_CMD_LE_SET_EXT_RANDOM_ADDR, payload)

    def _set_advertising_data(self, handle: int, ad_payload: bytes) -> None:
        """Set Extended Advertising Data for the given handle."""
        # Handle(1), Op=0x03(Complete), Frag=0x01(No Frag), Length(1), Data
        header = struct.pack("<BBBB", handle, 0x03, 0x01, len(ad_payload))
        self._send_hci_command(HCI_CMD_LE_SET_EXT_ADV_DATA, header + ad_payload)

    def _set_advertising_enable(self, enable: bool, handles: List[int]) -> None:
        """Enable or disable Extended Advertising for the given handles."""
        if enable:
            payload = struct.pack("<BB", 0x01, len(handles))
            for h in handles:
                payload += struct.pack("<BHB", h, 0x0000, 0x00)
        else:
            # Explicitly disable specific handles if provided, otherwise try global disable
            num_sets = len(handles)
            payload = struct.pack("<BB", 0x00, num_sets)
            for h in handles:
                payload += struct.pack("<BHB", h, 0x0000, 0x00)
        self._send_hci_command(HCI_CMD_LE_SET_EXT_ADV_ENABLE, payload)

    def _build_message_pack_ad(self, messages: List[bytes], counter: int) -> bytes:
        """Build a Service Data AD element containing an ODID Message Pack.

        Layout: [AD Len][0x16][UUID][AppCode][Counter][PackHdr][MsgSize][N][msg0...msgN]
        """
        msg_count = len(messages) & 0xFF
        service_data = (
            ASTM_UUID
            + bytes([ASTM_APP_CODE, counter & 0xFF])
            + self.pack_header_prefix
            + bytes([msg_count])
            + b''.join(messages)
        )
        ad_length = 1 + len(service_data)  # AD Type byte + data
        return bytes([ad_length, AD_TYPE_SERVICE_DATA_16]) + service_data

    def send_messages(self, drone: DroneState, messages: List[bytes]) -> None:
        """Send ASTM messages via BLE Extended Advertising.

        Handle 0: legacy PDU — single message rotation (3x Location + 1 static).
        Handle 1: extended PDU — full ODID Message Pack on LE Coded PHY.
        """
        if not self._sock:
            logger.error("BLE socket not open")
            return

        drone_key = drone.serial
        counter = self._counters.get(drone_key, 0)

        # 1. Disable broadcasting before altering sets
        self._set_advertising_enable(False, [0x00, 0x01])
        time.sleep(0.01)

        # 2. Re-apply Params and Address
        # Use a faster dwell for Legacy rotation; use standard interval for Extended pack.
        self._set_advertising_params(0x00, 0x0010, 0x01, 0x01, 0x00, interval_ms=self.legacy_interval_ms)
        self._set_advertising_params(0x01, 0x0000, 0x03, 0x03, 0x01, interval_ms=self.advertising_interval_ms)
        self._set_random_address(0x00, drone.ble_address)
        self._set_random_address(0x01, drone.ble_address)

        # BLE4 rotation sequence for handle 0
        send_sequence = self._build_send_sequence(drone_key, messages)
        
        # 3. Upload and start the Message Pack (Handle 1)
        pack_ad = self._build_message_pack_ad(messages, counter)
        self._set_advertising_data(0x01, pack_ad)
        self._set_advertising_enable(True, [0x01])

        # 4. Manually cycle through Legacy messages (Handle 0)
        for msg in send_sequence:
            legacy_ad = self._build_legacy_ad(msg, counter)
            self._set_advertising_data(0x00, legacy_ad)
            self._set_advertising_enable(True, [0x00])

            # Wait for the legacy dwell time
            time.sleep(self.legacy_interval_ms / 1000.0)

            self._set_advertising_enable(False, [0x00])
            counter = (counter + 1) & 0xFF

        # 5. Stop Handle 1
        self._set_advertising_enable(False, [0x01])
        self._counters[drone_key] = counter
