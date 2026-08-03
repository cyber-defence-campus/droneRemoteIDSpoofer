import struct
from scapy.all import sniff, Dot11Beacon, Dot11Elt

# --- Your Fixed Parser Class ---
class ASTM_F3411_SpecParser:
    def __init__(self, raw_bytes):
        self.data = raw_bytes
        self.results = []

    def parse_payload(self):
        i = 0
        while i < len(self.data):
            msg_type = (self.data[i]) >> 4
            if msg_type == 0xF:
                i += 1
                msg_size = self.data[i]
                i += 1
                msg_count = self.data[i]
                i += 1
                for _ in range(msg_count):
                    if i + 25 <= len(self.data):
                        self._process_message(self.data[i:i+25])
                        i += 25
            else:
                if i + 25 <= len(self.data):
                    self._process_message(self.data[i:i+25])
                    i += 25
                else:
                    break
        return self.results

    def _process_message(self, block):
        msg_type = (block[0]) >> 4
        if msg_type not in [0x0, 0x1, 0x2, 0x3, 0x4, 0x5]:
            return # Skip or handle error

        if msg_type == 0x0: self._decode_basic_id(block)
        elif msg_type == 0x1: self._decode_location(block)
        elif msg_type == 0x3: self._decode_self_id(block)
        elif msg_type == 0x4: self._decode_system(block)
        elif msg_type == 0x5: self._decode_operator_id(block)

    def _decode_location(self, b):
        lat = struct.unpack('<i', b[5:9])[0] / 1e7
        lon = struct.unpack('<i', b[9:13])[0] / 1e7
        alt_enc = struct.unpack('<H', b[15:17])[0]
        alt_m = (alt_enc * 0.5) - 1000
        self.results.append({"type": "Location", "lat": lat, "lon": lon, "alt": alt_m})

    def _decode_basic_id(self, b):
        uas_id = b[2:22].decode('ascii', errors='ignore').strip('\x00')
        self.results.append({"type": "Basic ID", "id": uas_id})

    def _decode_operator_id(self, b):
        op_id = b[2:22].decode('ascii', errors='ignore').strip('\x00')
        self.results.append({"type": "Operator ID", "id": op_id})

    def _decode_self_id(self, b):
        desc = b[2:25].decode('ascii', errors='ignore').strip('\x00')
        self.results.append({"type": "Self-ID", "desc": desc})

    def _decode_system(self, b):
        op_lat = struct.unpack('<i', b[2:6])[0] / 1e7
        op_lon = struct.unpack('<i', b[6:10])[0] / 1e7
        self.results.append({"type": "System", "pilot_lat": op_lat, "pilot_lon": op_lon})

# --- Scapy Sniffer Logic ---

def packet_callback(pkt):
    if pkt.haslayer(Dot11Beacon):
        # Scan through Information Elements (IEs)
        elt = pkt.getlayer(Dot11Elt)
        while isinstance(elt, Dot11Elt):
            # ID 221 (0xDD) is Vendor Specific
            if elt.ID == 221:
                # Check for ASTM/OpenDroneID OUI: FA:0B:BC
                # Payload format: OUI (3 bytes) + Type (1 byte) + ASTM Payload
                if elt.info.startswith(b'\xfa\x0b\xbc'):
                    # The actual ASTM payload starts after the 3-byte OUI and 1-byte type indicator
                    astm_payload = elt.info[5:]
                    
                    try:
                        parser = ASTM_F3411_SpecParser(astm_payload)
                        data = parser.parse_payload()
                        
                        if data:
                            chan_info = ""
                            if pkt.haslayer("RadioTap"):
                                try:
                                    freq = pkt.getlayer("RadioTap").ChannelFrequency
                                    if freq == 2484: chan = 14
                                    elif freq < 2484: chan = (freq - 2407) // 5
                                    elif freq > 5000: chan = (freq - 5000) // 5
                                    else: chan = freq
                                    chan_info = f", Ch: {chan}"
                                except Exception:
                                    pass
                            
                            print(f"\n[+] Remote ID Detected from {pkt.addr2} (RSSI: {pkt.dBm_AntSignal}dBm{chan_info})")
                            for entry in data:
                                print(f"    - {entry}")
                    except Exception as e:
                        pass # Handle parsing noise
            elt = elt.payload

if __name__ == "__main__":
    interface = "wlx40ae30abad23" # Change to your monitor-mode interface
    print(f"[*] Starting Remote ID Scanner on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)