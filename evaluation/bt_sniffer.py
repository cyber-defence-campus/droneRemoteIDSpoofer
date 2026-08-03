import argparse
import time
import base64
import json
import struct
import socket
import select
from sniffparser import ASTM_F3411_SpecParser

REMOTE_ID_UUID = b"\xfa\xff" # 16-bit UUID in little-endian

# Globals for Replay output
START_TIME = None
REPLAY_FILE = None
MAC_TO_SERIAL = {}

def parse_ad_structures(data: bytes):
    """Parse LTV structures from raw AD payload and return service data dict for 16-bit UUIDs."""
    service_data = {}
    i = 0
    while i < len(data):
        length = data[i]
        if length == 0:
            break
        if i + 1 + length > len(data):
            break
        ad_type = data[i+1]
        ad_value = data[i+2 : i+1+length]
        
        if ad_type == 0x16 and len(ad_value) >= 2: # Service Data - 16-bit UUID
            uuid16 = ad_value[:2]
            service_data[uuid16] = ad_value[2:]
            
        i += 1 + length
    return service_data

def handle_payload(mac: str, rssi: int, service_data_payload: bytes):
    print(f"🚁 Drone Detected! MAC: {mac} | RSSI: {rssi} dBm")
    print(f"  Raw Remote ID Payload (Hex): {service_data_payload.hex().upper()}")
    try:
        # Extract counter
        counter = service_data_payload[1] if len(service_data_payload) >= 2 and service_data_payload[0] == 0x0D else 0
        # Strip Application Code (0x0D) and Counter if present
        astm_data = service_data_payload[2:] if len(service_data_payload) >= 2 and service_data_payload[0] == 0x0D else service_data_payload
        
        # Distinguish between BLE 4 (Legacy) and BLE 5 (Extended)
        msg_type = (astm_data[0] >> 4) if len(astm_data) > 0 else None
        is_bt5 = len(astm_data) > 25 or msg_type == 0xF
        transport = "bt5" if is_bt5 else "bt4"
        
        if is_bt5:
            print("  [Protocol] BLE 5 Extended Advertising (Message Pack / Multi-Message)")
        else:
            print("  [Protocol] BLE 4 Legacy Advertising (Single Message)")
            
        parser = ASTM_F3411_SpecParser(astm_data)
        parsed_data = parser.parse_payload()
        
        serial = None
        if parsed_data:
            for entry in parsed_data:
                print(f"    - {entry}")
                if entry.get("type") == "Basic ID" and entry.get("id"):
                    serial = entry["id"]
                    MAC_TO_SERIAL[mac] = serial
        else:
            print(f"    - (Parser returned no data. astm_data length: {len(astm_data)}, type: {msg_type})")
            
        # Optionally write to replay JSONL
        if REPLAY_FILE is not None:
            msgs_b64 = []
            if msg_type == 0xF and len(astm_data) >= 3:
                msg_count = astm_data[2]
                for i in range(msg_count):
                    offset = 3 + (i * 25)
                    if offset + 25 <= len(astm_data):
                        msg = astm_data[offset:offset+25]
                        msgs_b64.append(base64.b64encode(msg).decode('ascii'))
            else:
                if len(astm_data) >= 25:
                    msg = astm_data[0:25]
                    msgs_b64.append(base64.b64encode(msg).decode('ascii'))
                    
            if msgs_b64:
                event = {
                    "time_offset_ms": int((time.time() - START_TIME) * 1000),
                    "transport": transport,
                    "counter": counter,
                    "messages_b64": msgs_b64,
                    "mac": mac
                }
                if serial:
                    event["serial"] = serial
                elif mac in MAC_TO_SERIAL:
                    event["serial"] = MAC_TO_SERIAL[mac]
                    
                REPLAY_FILE.write(json.dumps(event) + "\n")
                REPLAY_FILE.flush()
            
    except Exception as e:
        import traceback
        print(f"    - Error parsing payload: {type(e).__name__}: {e}")
        traceback.print_exc()
    print("-" * 50)

class RawHciSniffer:
    def __init__(self, adapter="hci0"):
        self.adapter = adapter
        self.dev_id = int(adapter.replace("hci", "")) if adapter.startswith("hci") else 0
        self.sock = None
        
    def _build_hci_command(self, opcode: int, data: bytes) -> bytes:
        return struct.pack('<BHB', 0x01, opcode, len(data)) + data

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
            self.sock.bind((self.dev_id,))
        except Exception as e:
            raise RuntimeError(f"Failed to open HCI socket on {self.adapter}. Did you use sudo? Error: {e}")

        # Set HCI Filter to receive LE Meta Events (0x3E)
        type_mask = 1 << 4 # HCI_EVENT_PKT
        event_mask_lo = 0xFFFFFFFF
        event_mask_hi = 0xFFFFFFFF
        filter_bytes = struct.pack("<IIIH", type_mask, event_mask_lo, event_mask_hi, 0) + b'\x00\x00'
        self.sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, filter_bytes)

        try:
            # Disable Extended Scan (in case it was running)
            self.sock.send(self._build_hci_command(0x2042, struct.pack("<BB", 0x00, 0x00)))
            
            # Set Extended Scan Parameters (Active, 10ms Window/Interval for LE 1M & LE Coded)
            # Own_Addr_Type=0, Filter_Policy=0, Scanning_PHYs=0x05 (Bit 0: 1M, Bit 2: Coded)
            # For each PHY: Scan_Type=0x01 (Active), Interval=0x0010 (10ms), Window=0x0010 (10ms)
            params = struct.pack("<BBB BHH BHH", 0x01, 0x00, 0x05, 0x01, 0x0010, 0x0010, 0x01, 0x0010, 0x0010)
            self.sock.send(self._build_hci_command(0x2041, params))
            
            # Enable Extended Scan
            self.sock.send(self._build_hci_command(0x2042, struct.pack("<BBHH", 0x01, 0x00, 0x0000, 0x0000)))
        except OSError as e:
            if e.errno == 97: # Address family not supported by protocol -> usually meaning controller doesn't support Extended commands
                print(f"[!] Warning: Adapter {self.adapter} rejected Extended Scanning commands (BT 4.0 adapter?). Falling back to Legacy Scanning...")
                # Try Legacy Set Scan Parameters (0x200B) and Enable (0x200C)
                self.sock.send(self._build_hci_command(0x200B, struct.pack("<BHHBB", 0x01, 0x0010, 0x0010, 0x00, 0x00)))
                self.sock.send(self._build_hci_command(0x200C, struct.pack("<BB", 0x01, 0x00)))
            else:
                raise

        print(f"[*] Raw HCI Scanner started on {self.adapter} (100% duty cycle)")

    def stop(self):
        if self.sock:
            try:
                self.sock.send(self._build_hci_command(0x2042, struct.pack("<BB", 0x00, 0x00)))
                self.sock.send(self._build_hci_command(0x200C, struct.pack("<BB", 0x00, 0x00)))
            except Exception:
                pass
            self.sock.close()

    def process_events(self):
        while True:
            ready, _, _ = select.select([self.sock], [], [], 1.0)
            if not ready:
                continue
            
            try:
                pkt = self.sock.recv(258)
            except OSError:
                break

            if len(pkt) < 3 or pkt[0] != 0x04:
                continue
                
            event_code = pkt[1]
            if event_code == 0x3E: # LE Meta Event
                subevent = pkt[3]
                if subevent == 0x0D: # LE Extended Advertising Report
                    num_reports = pkt[4]
                    offset = 5
                    for _ in range(num_reports):
                        if offset + 24 > len(pkt): break
                        # Header is 24 bytes up to data_length
                        # evt_type(2), addr_type(1), addr(6), p_phy(1), s_phy(1), sid(1), tx_pwr(1), rssi(1, int8), p_int(2), d_addr_type(1), d_addr(6), d_len(1)
                        evt_type, addr_type, addr, p_phy, s_phy, sid, tx_pwr, rssi, p_int, d_addr_type, d_addr, d_len = struct.unpack("<HB6sBBBbbHB6sB", pkt[offset:offset+24])
                        offset += 24
                        data = pkt[offset:offset+d_len]
                        offset += d_len
                        
                        self._process_ad_data(addr, rssi, data)

                elif subevent == 0x02: # LE Advertising Report (Legacy fallback)
                    num_reports = pkt[4]
                    offset = 5
                    for _ in range(num_reports):
                        if offset + 9 > len(pkt): break
                        evt_type, addr_type, addr, d_len = struct.unpack("<BB6sB", pkt[offset:offset+9])
                        offset += 9
                        data = pkt[offset:offset+d_len]
                        offset += d_len
                        rssi = 0
                        if offset < len(pkt):
                            rssi = struct.unpack("<b", pkt[offset:offset+1])[0]
                            offset += 1
                            
                        self._process_ad_data(addr, rssi, data)

    def _process_ad_data(self, addr_bytes: bytes, rssi: int, data: bytes):
        ad_structures = parse_ad_structures(data)
        if REMOTE_ID_UUID in ad_structures:
            mac = ':'.join(f'{b:02X}' for b in reversed(addr_bytes))
            handle_payload(mac, rssi, ad_structures[REMOTE_ID_UUID])

def main():
    parser = argparse.ArgumentParser(description="Raw HCI BT5 Drone Remote ID Sniffer")
    parser.add_argument("--replay-out", help="Optional output JSONL file for use with replay_drones.py", default=None)
    parser.add_argument("--adapter", help="Bluetooth adapter to use (e.g. hci0)", default="hci0")
    args = parser.parse_args()
    
    global START_TIME, REPLAY_FILE
    START_TIME = time.time()
    
    if args.replay_out:
        REPLAY_FILE = open(args.replay_out, 'a')
        print(f"[*] Replay events will be saved to {args.replay_out}")
        
    sniffer = RawHciSniffer(args.adapter)
    try:
        sniffer.start()
        sniffer.process_events()
    except KeyboardInterrupt:
        print("\nScanning stopped.")
    finally:
        sniffer.stop()
        if REPLAY_FILE:
            REPLAY_FILE.close()

if __name__ == "__main__":
    main()
