#!/usr/bin/env python3
"""
Unit tests for combined_rid_listener.py:
1. Channel hopping sequence & timing calculations
2. ASTM F3411 payload decoding (Basic ID, Location, System, Operator ID, Self-ID)
3. SharedChannelState concurrency
"""

import unittest
import struct
import time
from scanner.combined_rid_listener import (
    SharedChannelState,
    decode_astm_message,
    parse_astm_payload,
    SOCIAL_CHANNEL_2G,
    NON_SOCIAL_CHANNELS_2G,
    SOCIAL_CHANNEL_5G,
    NON_SOCIAL_CHANNELS_5G,
    get_band_for_channel,
    get_freq_for_channel,
)

class TestCombinedRIDListener(unittest.TestCase):

    def test_channel_helpers(self):
        self.assertEqual(get_band_for_channel(6), "2.4GHz")
        self.assertEqual(get_band_for_channel(1), "2.4GHz")
        self.assertEqual(get_band_for_channel(149), "5.8GHz")
        self.assertEqual(get_band_for_channel(157), "5.8GHz")
        self.assertEqual(get_freq_for_channel(6), 2437)
        self.assertEqual(get_freq_for_channel(149), 5745)

    def test_shared_channel_state(self):
        state = SharedChannelState(initial_channel=6)
        ch, band, freq, ts = state.get()
        self.assertEqual(ch, 6)
        self.assertEqual(band, "2.4GHz")
        self.assertEqual(freq, 2437)

        state.update(149)
        ch, band, freq, ts = state.get()
        self.assertEqual(ch, 149)
        self.assertEqual(band, "5.8GHz")
        self.assertEqual(freq, 5745)

    def test_decode_basic_id(self):
        # Header: (MsgType 0 << 4) | proto 2 = 0x02
        # ID Type: Serial number (1) << 4 | UA Type Helicopter (2) = 0x12
        # UAS ID: 20 bytes ASCII
        serial = b"15967200000000000001"
        block = bytes([0x02, 0x12]) + serial + b'\x00\x00\x00'
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["type"], "Basic ID")
        self.assertEqual(decoded["id"], "15967200000000000001")
        self.assertEqual(decoded["id_type"], 1)
        self.assertEqual(decoded["ua_type"], 2)

    def test_decode_location(self):
        # Header: (MsgType 1 << 4) | proto 2 = 0x12
        # Status flags: 0x00
        # Track dir: 180 deg
        # Speed: 20 * 0.25 = 5.0 m/s (speed_mult=0)
        # VSpeed: 2 * 0.5 = 1.0 m/s
        # Lat: 47.3769 * 1e7 = 473769000
        # Lon: 8.5417 * 1e7 = 85417000
        # Alt: (450 + 1000) * 2 = 2900 (0x0B54)
        # GAlt: (460 + 1000) * 2 = 2920 (0x0B68)
        # Height: (50 + 1000) * 2 = 2100 (0x0834)
        lat_i = 473769000
        lon_i = 85417000
        block = struct.pack(
            '<BBBBBiiHHH6s',
            0x12, 0x00, 180, 20, 2,
            lat_i, lon_i,
            2900, 2920, 2100,
            b'\x00' * 6
        )
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["type"], "Location")
        self.assertAlmostEqual(decoded["lat"], 47.3769, places=4)
        self.assertAlmostEqual(decoded["lon"], 8.5417, places=4)
        self.assertEqual(decoded["speed_mps"], 5.0)
        self.assertEqual(decoded["direction_deg"], 180)
        self.assertEqual(decoded["pressure_altitude_m"], 450.0)
        self.assertEqual(decoded["geodetic_altitude_m"], 460.0)
        self.assertEqual(decoded["height_m"], 50.0)

    def test_decode_message_pack(self):
        # Build 2-message pack: Basic ID + Location
        serial = b"TESTDRONE00000000001"
        b_id = bytes([0x02, 0x12]) + serial + b'\x00\x00\x00'
        loc = struct.pack(
            '<BBBBBiiHHH6s',
            0x12, 0x00, 90, 40, 0,
            470000000, 80000000,
            2500, 2500, 2100,
            b'\x00' * 6
        )
        # Pack header: 0xF2 (MsgType 0xF, ver 2), size=25 (0x19), count=2
        pack_payload = bytes([0xF2, 0x19, 0x02]) + b_id + loc
        parsed, raw_b64 = parse_astm_payload(pack_payload)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(len(raw_b64), 2)
        self.assertEqual(parsed[0]["type"], "Basic ID")
        self.assertEqual(parsed[0]["id"], "TESTDRONE00000000001")
        self.assertEqual(parsed[1]["type"], "Location")
        self.assertEqual(parsed[1]["direction_deg"], 90)

    def test_decode_auth_page_zero(self):
        # Header: (MsgType 2 << 4) | proto 2 = 0x22
        # AuthType: UAS ID Signature (1) << 4 | DataPage 0 = 0x10
        # LastPageIndex: 2
        # Length: 55
        # Timestamp: 3600 (seconds since 2019-01-01) -> Epoch: 1546300800 + 3600 = 1546304400
        # 17 bytes auth data
        auth_data = b"0123456789ABCDEFG"
        block = struct.pack('<BBBB I 17s', 0x22, 0x10, 2, 55, 3600, auth_data)
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["type"], "Auth")
        self.assertEqual(decoded["auth_type"], 1)
        self.assertEqual(decoded["auth_type_name"], "UAS ID Signature")
        self.assertEqual(decoded["page_number"], 0)
        self.assertEqual(decoded["last_page_index"], 2)
        self.assertEqual(decoded["auth_data_length"], 55)
        self.assertEqual(decoded["auth_timestamp_epoch"], 1546304400)
        self.assertEqual(decoded["auth_data_hex"], auth_data.hex().upper())

    def test_decode_auth_continuation_page(self):
        # Page 1
        auth_data = b"CONTINUATION_PAGE_1_23B"
        block = bytes([0x22, 0x11]) + auth_data
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["type"], "Auth")
        self.assertEqual(decoded["page_number"], 1)
        self.assertEqual(decoded["auth_data_hex"], auth_data.hex().upper())

    def test_decode_self_id(self):
        # Header: 0x32 (Type 3, Proto 2)
        # DescType: 1 (Emergency Status v2)
        # Desc: "Motor failure landing"
        desc = b"Motor failure landing\x00\x00"
        block = bytes([0x32, 0x01]) + desc
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["type"], "Self-ID")
        self.assertEqual(decoded["desc_type"], 1)
        self.assertEqual(decoded["desc_type_name"], "Emergency Status (v2)")
        self.assertEqual(decoded["description"], "Motor failure landing")

    def test_decode_system(self):
        # Header: 0x42 (Type 4, Proto 2)
        # Flags: OperatorLocationType Live GNSS (1), ClassificationType EU (1) -> (1 << 2) | 1 = 0x05
        # Pilot Lat: 47.3769 * 1e7 = 473769000
        # Pilot Lon: 8.5417 * 1e7 = 85417000
        # AreaCount: 1
        # AreaRadius: 5 (50m)
        # AreaCeiling: (150 + 1000) * 2 = 2300
        # AreaFloor: (0 + 1000) * 2 = 2000
        # Byte 17: EU Category Open (1) << 4 | Class C1 (2) = 0x12
        # Pilot Alt: (430 + 1000) * 2 = 2860
        # Timestamp: 7200 -> Epoch: 1546300800 + 7200 = 1546308000
        block = struct.pack(
            '<BBiiH B HH B H I B',
            0x42, 0x05,
            473769000, 85417000,
            1, 5,
            2300, 2000,
            0x12,
            2860,
            7200,
            0x00
        )
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["type"], "System")
        self.assertEqual(decoded["operator_location_type_name"], "Live GNSS (Dynamic Pilot / GCS)")
        self.assertEqual(decoded["classification_type_name"], "European Union (EU)")
        self.assertAlmostEqual(decoded["pilot_lat"], 47.3769, places=4)
        self.assertAlmostEqual(decoded["pilot_lon"], 8.5417, places=4)
        self.assertEqual(decoded["area_radius_m"], 50)
        self.assertEqual(decoded["area_ceiling_m"], 150.0)
        self.assertEqual(decoded["area_floor_m"], 0.0)
        self.assertEqual(decoded["category_eu_name"], "Open")
        self.assertEqual(decoded["class_eu_name"], "Class 1")
        self.assertEqual(decoded["pilot_alt_m"], 430.0)
        self.assertEqual(decoded["system_timestamp_epoch"], 1546308000)

    def test_decode_operator_id(self):
        # Header: 0x52 (Type 5, Proto 2)
        # OpIdType: 0 (Operator ID)
        # OperatorId: "CHE-123456789abc-xyz"
        op_id = b"CHE-123456789abc-xyz"
        block = bytes([0x52, 0x00]) + op_id + b'\x00\x00\x00'
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["type"], "Operator ID")
        self.assertEqual(decoded["operator_id"], "CHE-123456789abc-xyz")
        self.assertEqual(decoded["operator_id_type_name"], "Operator ID")

    def test_decode_location_accuracies_and_speeds(self):
        # Test high speed multiplier (speed_mult = 1) and accuracies
        # Byte 1: Status Airborne (2) << 4 | HeightType AGL (1) << 2 | EW Dir West (1) << 1 | SpeedMult (1) = 0x27
        # Dir: 45 (+180 = 225 deg)
        # Speed: 50 -> 63.75 + (50 * 0.75) = 101.25 m/s
        # VSpeed: -10 * 0.5 = -5.0 m/s (signed int8: -10 = 246 / 0xF6)
        # Accuracy B19: VertAcc <10m (5) << 4 | HorizAcc <3m (11) = 0x5B
        # Accuracy B20: BaroAcc <25m (4) << 4 | SpeedAcc <1m/s (3) = 0x43
        # TimeStamp: 1234 (123.4s)
        # Accuracy B23: TSAcc <0.2s (2) = 0x02
        block = struct.pack(
            '<BBBBb ii HHH BB H B B',
            0x12, 0x27, 45, 50, -10,
            470000000, 80000000,
            2000, 2000, 2000,
            0x5B, 0x43,
            1234, 0x02, 0x00
        )
        self.assertEqual(len(block), 25)
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["status_name"], "Airborne")
        self.assertEqual(decoded["direction_deg"], 225)
        self.assertAlmostEqual(decoded["speed_mps"], 101.25)
        self.assertEqual(decoded["vertical_speed_mps"], -5.0)
        self.assertEqual(decoded["height_type_name"], "Above Ground Level (AGL)")
        self.assertEqual(decoded["horizontal_accuracy_name"], "< 3 m")
        self.assertEqual(decoded["vertical_accuracy_name"], "< 10 m")
        self.assertEqual(decoded["baro_accuracy_name"], "< 25 m")
        self.assertEqual(decoded["speed_accuracy_name"], "< 1 m/s")
        self.assertEqual(decoded["timestamp_s"], 123.4)
        self.assertEqual(decoded["timestamp_accuracy_name"], "< 0.2 s")

    def test_security_malformed_message_packs(self):
        # 1. Zero msg_count in message pack (DA-01)
        zero_pack = bytes([0xF2, 0x19, 0x00])
        parsed, raw_b64 = parse_astm_payload(zero_pack)
        self.assertEqual(len(parsed), 0)

        # 2. Invalid msg_size != 25 (e.g. msg_size = 50)
        invalid_size_pack = bytes([0xF2, 50, 0x01]) + (b"\x00" * 50)
        parsed, raw_b64 = parse_astm_payload(invalid_size_pack)
        self.assertEqual(len(parsed), 0)

        # 3. Excessive msg_count > 9 (e.g. msg_count = 20)
        excess_pack = bytes([0xF2, 0x19, 20]) + (b"\x00" * 500)
        parsed, raw_b64 = parse_astm_payload(excess_pack)
        self.assertEqual(len(parsed), 0)

        # 4. Truncated pack (header says count=2, but buffer only has 1 message)
        truncated_pack = bytes([0xF2, 0x19, 0x02]) + (b"\x00" * 25)
        parsed, raw_b64 = parse_astm_payload(truncated_pack)
        self.assertEqual(len(parsed), 0)

    def test_security_terminal_ansi_escape_sanitization(self):
        # DA-03: String containing ANSI escape sequences (\x1b[2J) and non-printable control chars (\x07)
        malicious_serial = b"\x1b[2J\x1b[HATTACKER_ID\x07\x00"
        block = bytes([0x02, 0x12]) + malicious_serial.ljust(20, b'\x00') + b'\x00\x00\x00'
        decoded = decode_astm_message(block)
        self.assertIsNotNone(decoded)
        # Verify ANSI control chars were neutralized
        self.assertNotIn("\x1b", decoded["id"])
        self.assertNotIn("\x07", decoded["id"])
        self.assertIn("ATTACKER_ID", decoded["id"])

    def test_security_csv_formula_injection(self):
        # ANDR-01 / RDBP-03: Cell starting with formula operator
        from scanner.query_rid_db import sanitize_csv_cell
        self.assertEqual(sanitize_csv_cell("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(sanitize_csv_cell("+12345"), "'+12345")
        self.assertEqual(sanitize_csv_cell("-12345"), "'-12345")
        self.assertEqual(sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("NORMAL_TEXT"), "NORMAL_TEXT")

    def test_ble_sniffer_json_event_processing(self):
        import queue
        import json
        event_queue = queue.Queue()
        # Simulated JSON record from nrf_bt_sniffer_json.py for BLE 5 Extended Remote ID
        raw_json_line = json.dumps({
            "timestamp": 1725448000.123,
            "mac": "FE:FB:89:DF:4A:3D",
            "rssi_dbm": -75,
            "pdu_type": "ADV_EXT_IND/AUX_ADV_IND",
            "remote_id": {
                "transport": "ble5_extended",
                "counter": 42,
                "parsed_messages": [
                    {"type": "Basic ID", "id": "Spoofed_Serial_12345", "raw_hex": "021253706f6f6665645f53657269616c5f3132333435000000"},
                    {"type": "Location", "lat": 47.3769, "lon": 8.5417, "alt": 450.0, "speed": 12.5, "heading": 180, "raw_hex": "1200b432021c3d18e8051759080b540b680834000017700000"}
                ]
            }
        })
        
        record = json.loads(raw_json_line)
        rid_info = record["remote_id"]
        parsed_msgs = rid_info.get("parsed_messages", [])
        transport_type = str(rid_info.get("transport", "bt5")).lower()
        pdu_type = str(record.get("pdu_type", "")).upper()
        transport = "bt5" if ("5" in transport_type or "ext" in transport_type or "AUX" in pdu_type) else "bt4"
        
        self.assertEqual(transport, "bt5")
        self.assertEqual(len(parsed_msgs), 2)
        self.assertEqual(parsed_msgs[0]["id"], "Spoofed_Serial_12345")
        self.assertEqual(parsed_msgs[1]["lat"], 47.3769)

    def test_schedule_coverage(self):
        # Verify that with k=1 (2 in 2.4G, 1 in 5.8G), 6 cycles cover all 12 2.4G non-social and all 6 5.8G non-social channels
        k = 1
        n_2g = 2 * k
        n_5g = k

        visited_2g = []
        visited_5g = []

        idx_2g = 0
        idx_5g = 0

        for cycle in range(6):
            for _ in range(n_2g):
                visited_2g.append(NON_SOCIAL_CHANNELS_2G[idx_2g % len(NON_SOCIAL_CHANNELS_2G)])
                idx_2g += 1
            for _ in range(n_5g):
                visited_5g.append(NON_SOCIAL_CHANNELS_5G[idx_5g % len(NON_SOCIAL_CHANNELS_5G)])
                idx_5g += 1

        self.assertEqual(len(visited_2g), 12)
        self.assertEqual(len(visited_5g), 6)
        self.assertEqual(set(visited_2g), set(NON_SOCIAL_CHANNELS_2G))
        self.assertEqual(set(visited_5g), set(NON_SOCIAL_CHANNELS_5G))

    def test_nordic_ble_packet_metadata_and_rssi(self):
        from evaluation.nrf_bt_sniffer_json import parse_packet_metadata
        # Build realistic nRF Sniffer v2 DLT_NORDIC_BLE header (17 bytes)
        # Board(1) + Len(2, e.g. 164 = 0x00A4) + Ver(1) + Cnt(2) + Type(1=0x06) + HdrLen(1=10) + Flags(1=0x01) + Ch(1=37) + RSSI(1=55 -> -55dBm) + EvtCnt(2) + DeltaTime(4)
        # Followed by BLE_ADV_ACCESS_ADDR (4 bytes) + PDU Header (2 bytes) + AdvA MAC (6 bytes)
        board = b'\x00'
        pkt_len = struct.pack('<H', 164) # 0xA4, 0x00
        ver = b'\x02'
        cnt = struct.pack('<H', 123)
        pkt_type = b'\x06' # event_packet
        hdr_len = b'\x0A' # 10
        flags = b'\x01' # CRC OK
        rf_ch = bytes([37])
        rssi_magnitude = bytes([55]) # -55 dBm
        evt_cnt = struct.pack('<H', 1)
        delta_t = struct.pack('<I', 1000)
        
        nordic_hdr = board + pkt_len + ver + cnt + pkt_type + hdr_len + flags + rf_ch + rssi_magnitude + evt_cnt + delta_t
        self.assertEqual(len(nordic_hdr), 17)
        
        # Access Address: 0x8E89BED6
        access_addr = b'\xd6\xbe\x89\x8e'
        # PDU Header: ADV_EXT_IND (0x07)
        pdu_hdr = b'\x07\x10'
        # Extended Header with AdvA MAC: CD:57:9B:8E:EB:AB
        mac_bytes_le = bytes.fromhex("ABEB8E9B57CD")
        ext_hdr = b'\x08\x09\x09' + mac_bytes_le
        
        full_packet = nordic_hdr + access_addr + pdu_hdr + ext_hdr
        
        pdu_type_str, mac_addr, rssi_dbm, ch = parse_packet_metadata(full_packet)
        self.assertEqual(pdu_type_str, "ADV_EXT_IND/AUX_ADV_IND")
        self.assertEqual(mac_addr, "CD:57:9B:8E:EB:AB")
        self.assertEqual(rssi_dbm, -55) # Verified NOT misidentified as -92 from length 0xA4
        self.assertEqual(ch, 37)

    def test_wifi_sniffer_frame_processing(self):
        # Construct realistic Wi-Fi 802.11 Beacon frame with Radiotap header
        # Radiotap header (18 bytes)
        rt_hdr = b'\x00\x00\x12\x00\x2e\x48\x00\x00\x10\x02\x85\x09\xa0\x00\xa0\x00\x00\x00'
        # 802.11 MAC Header: FrameControl (Beacon = 0x8000), Duration (0x0000), Addr1 (FF:FF:FF:FF:FF:FF), Addr2 (6 bytes), Addr3 (6 bytes), Seq (0x0000)
        mac_addr_bytes = bytes.fromhex("00C0CA9910EA")
        bssid_bytes = mac_addr_bytes
        mac_hdr = b'\x80\x00\x00\x00' + (b'\xff' * 6) + mac_addr_bytes + bssid_bytes + b'\x00\x00'
        # Beacon fixed parameters: Timestamp(8) + Interval(2) + Cap(2) = 12 bytes
        beacon_fixed = b'\x00' * 12
        # SSID IE: ID=0, Len=4, "RID1"
        ie_ssid = b'\x00\x04RID1'
        
        # Build 1 ASTM Basic ID message (25 bytes)
        serial = b"WIFI_TEST_DRONE_0001"
        basic_id_msg = bytes([0x02, 0x12]) + serial + b'\x00\x00\x00'
        # Pack header: 0xF2 (MsgType 0xF, ver 2), size=25 (0x19), count=1
        astm_pack = bytes([0xF2, 0x19, 0x01]) + basic_id_msg
        
        # Vendor Specific IE: 0xDD (Tag), Len, OUI(FA:0B:BC) + AppCode(0x0D) + Counter(42) + astm_pack
        vendor_payload = bytes([0x0D, 42]) + astm_pack
        oui_and_payload = b'\xfa\x0b\xbc' + vendor_payload
        ie_vendor = b'\xdd' + bytes([len(oui_and_payload)]) + oui_and_payload
        
        full_frame = rt_hdr + mac_hdr + beacon_fixed + ie_ssid + ie_vendor
        
        # Test simulated parsing logic from WifiSnifferThread
        vendor_ie_idx = -1
        search_offset = 0
        while True:
            idx = full_frame.find(b'\xfa\x0b\xbc', search_offset)
            if idx == -1: break
            if idx >= 2 and full_frame[idx - 2] == 0xDD:
                vendor_ie_idx = idx
                break
            search_offset = idx + 1
            
        self.assertNotEqual(vendor_ie_idx, -1)
        ie_len = full_frame[vendor_ie_idx - 1]
        vendor_data = full_frame[vendor_ie_idx + 3 : vendor_ie_idx + ie_len]
        self.assertEqual(vendor_data[0], 0x0D)
        counter = vendor_data[1]
        self.assertEqual(counter, 42)
        astm_payload = vendor_data[2:]
        
        parsed_msgs, b64_blocks = parse_astm_payload(astm_payload)
        self.assertEqual(len(parsed_msgs), 1)
        self.assertEqual(parsed_msgs[0]["type"], "Basic ID")
        self.assertEqual(parsed_msgs[0]["id"], "WIFI_TEST_DRONE_0001")

if __name__ == "__main__":
    unittest.main()
