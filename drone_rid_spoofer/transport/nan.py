"""NAN (Wi-Fi Aware) transport backend using a TCP bridge to an Android App."""

import base64
import json
import logging
import socket
import threading
from typing import List

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.messages import MsgType
from drone_rid_spoofer.transport.base import TransportBackend


class NanBackend(TransportBackend):
    """NAN (Wi-Fi Aware) transport for ASTM F3411-22 RID.
    
    Connects to a bridge Android App over a TCP connection (via ADB port forwarding)
    and sends JSON commands to manage Wi-Fi Aware publish sessions.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, protocol_version: int = 2, update_interval: float = 1.0):
        self.host = host
        self.port = port
        self.protocol_version = protocol_version
        self.update_interval = update_interval
        self.sock = None
        self.lock = threading.Lock()
        self._configured_drones = set()
        self._counters = {}
        self._stop_event = threading.Event()
        self._listener_thread = None
        self._drones = []
        self._packet_builder = None
        self._transmit_thread = None
        self._connect()

    def start(self, drones: List[DroneState], packet_builder) -> None:
        self._drones = drones
        self._packet_builder = packet_builder
        self._transmit_thread = threading.Thread(target=self._transmit_loop, daemon=True)
        self._transmit_thread.start()
        logging.info(f"NAN backend background thread started with {self.update_interval}s interval")

    def _listen(self, sock):
        """Listen for incoming messages from the Android bridge."""
        sock.settimeout(1.0)
        try:
            # makefile makes reading lines easy
            with sock.makefile('r', encoding='utf-8') as f:
                while not self._stop_event.is_set():
                    try:
                        line = f.readline()
                        if not line:
                            break
                        msg = json.loads(line)
                        if msg.get("type") == "ERROR":
                            logging.error(f"NAN Bridge Error for drone {msg.get('drone_id')}: {msg.get('reason')}")
                    except socket.timeout:
                        continue
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

    def _connect(self):
        """Establish TCP connection to the Android App."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect((self.host, self.port))
            logging.info(f"Connected to NAN bridge at {self.host}:{self.port}")
            self._listener_thread = threading.Thread(target=self._listen, args=(self.sock,), daemon=True)
            self._listener_thread.start()
        except Exception as e:
            logging.error(f"Failed to connect to NAN bridge at {self.host}:{self.port}: {e}")
            self.sock = None

    def _send_command(self, cmd: dict):
        """Send JSON command over TCP."""
        with self.lock:
            if not self.sock:
                # Attempt to reconnect
                self._connect()
                if not self.sock:
                    return

            try:
                data = json.dumps(cmd) + "\n"
                self.sock.sendall(data.encode('utf-8'))
            except Exception as e:
                logging.error(f"Error sending command to NAN bridge: {e}")
                self.sock.close()
                self.sock = None

    def send_raw(self, drone_key: str, payload: bytes) -> None:
        """Send a raw byte payload via NAN."""
        if drone_key not in self._configured_drones:
            config_cmd = {
                "type": "CONFIG",
                "drone_id": drone_key
            }
            self._send_command(config_cmd)
            self._configured_drones.add(drone_key)

        if len(payload) > 255:
            logging.warning(f"NAN Raw Payload too large ({len(payload)} bytes). Truncating to 255.")
            payload = payload[:255]

        payload_b64 = base64.b64encode(payload).decode('ascii')
        payload_cmd = {
            "type": "PAYLOAD",
            "drone_id": drone_key,
            "payload": payload_b64
        }
        self._send_command(payload_cmd)

    def _transmit_loop(self) -> None:
        import time
        # Wait until drones are populated
        while not self._stop_event.is_set() and not self._drones:
            time.sleep(0.01)
            
        next_tick = time.time()
        while not self._stop_event.is_set():
            for drone in self._drones:
                if not getattr(drone, 'active', True):
                    continue
                
                # Initialize the drone on the Android bridge if not already done
                if drone.mac_address not in self._configured_drones:
                    config_cmd = {
                        "type": "CONFIG",
                        "drone_id": drone.mac_address
                    }
                    self._send_command(config_cmd)
                    self._configured_drones.add(drone.mac_address)

                messages = self._packet_builder(drone)
                drone_key = drone.mac_address
                
                if hasattr(drone, 'counter_override') and drone.counter_override is not None:
                    counter = drone.counter_override
                else:
                    counter = self._counters.get(drone_key, 0)
                    self._counters[drone_key] = (counter + 1) & 0xFF
                
                msg_count = len(messages) & 0xFF
                pack_header = bytes([counter, (MsgType.PACK << 4) | self.protocol_version, 0x19, msg_count])

                payload = pack_header + b''.join(messages)
                if len(payload) > 255:
                    logging.warning(f"NAN Payload too large ({len(payload)} bytes). Truncating to 255.")
                    payload = payload[:255]

                payload_b64 = base64.b64encode(payload).decode('ascii')
                payload_cmd = {
                    "type": "PAYLOAD",
                    "drone_id": drone.mac_address,
                    "payload": payload_b64
                }
                self._send_command(payload_cmd)
                
            next_tick += self.update_interval
            now = time.time()
            if next_tick < now:
                next_tick = now
                
            sleep_time = next_tick - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

    def remove_drone(self, drone: DroneState) -> None:
        """Stop publishing and remove state for an expired drone."""
        if drone.mac_address in self._configured_drones:
            stop_cmd = {
                "type": "STOP",
                "drone_id": drone.mac_address
            }
            self._send_command(stop_cmd)
            self._configured_drones.discard(drone.mac_address)
        self._counters.pop(drone.mac_address, None)

    def close(self) -> None:
        """Close the connection to the Android bridge."""
        self._stop_event.set()
        if self.sock:
            with self.lock:
                # Tell Android to stop all publishing
                try:
                    cmd = {"type": "STOP_ALL"}
                    data = json.dumps(cmd) + "\n"
                    self.sock.sendall(data.encode('utf-8'))
                except Exception:
                    pass
                self._configured_drones.clear()
                
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
            logging.info("Disconnected from NAN bridge.")
        if self._listener_thread:
            self._listener_thread.join(timeout=2.0)
        if self._transmit_thread:
            self._transmit_thread.join(timeout=2.0)

    def reset(self) -> None:
        """Perform a full system reset of the Android NAN subsystem."""
        if self.sock:
            with self.lock:
                try:
                    cmd = {"type": "RESET"}
                    data = json.dumps(cmd) + "\n"
                    self.sock.sendall(data.encode('utf-8'))
                except Exception as e:
                    logging.error(f"Failed to send RESET command: {e}")
                self._configured_drones.clear()
            logging.info("Sent RESET command to NAN bridge.")

