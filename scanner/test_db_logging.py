#!/usr/bin/env python3
"""
Unit tests for persistent SQLite Encounter Logging, Replay JSONL format,
and query_rid_db.py search & GeoJSON export utility.
"""

import os
import json
import sqlite3
import tempfile
import time
import unittest
from scanner.combined_rid_listener import (
    EncounterTracker,
    UnifiedTelemetryLogger,
    decode_astm_message,
    parse_astm_payload,
)
from scanner.query_rid_db import (
    format_duration,
    get_db_connection,
)


class TestDatabaseAndReplayLogging(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_rid.db")
        self.jsonl_path = os.path.join(self.temp_dir.name, "test_replay.jsonl")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_duration_formatter(self):
        self.assertEqual(format_duration(45), "45s")
        self.assertEqual(format_duration(125), "2m 05s")
        self.assertEqual(format_duration(3665), "1h 01m")

    def test_encounter_lifecycle_and_timeout(self):
        # Initialize tracker with short 1.0s timeout for testing
        tracker = EncounterTracker(db_path=self.db_path, timeout_s=1.0)

        t0 = 1756129000.0
        pkt1 = {
            "timestamp": t0,
            "mac": "60:60:1F:AA:BB:CC",
            "serial_number": "TEST_SERIAL_1",
            "transport": "bt5",
            "channel": "Adv",
            "rssi_dbm": -65,
            "messages": [
                {"type": "Basic ID", "id": "TEST_SERIAL_1", "id_type": 1},
                {"type": "Location", "lat": 47.3769, "lon": 8.5417, "geodetic_altitude_m": 450.0, "speed_mps": 10.0, "direction_deg": 180},
                {"type": "System", "pilot_lat": 47.3760, "pilot_lon": 8.5410, "pilot_alt_m": 410.0},
                {"type": "Operator ID", "operator_id": "CHE-12345"},
            ]
        }

        # 1. First packet creates encounter
        enc_id1 = tracker.update_with_packet(pkt1)
        self.assertTrue(enc_id1.startswith("ENC-"))

        # Verify encounter stored in DB as active
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM encounters WHERE encounter_id = ?", (enc_id1,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["mac"], "60:60:1F:AA:BB:CC")
            self.assertEqual(row["serial_number"], "TEST_SERIAL_1")
            self.assertEqual(row["packet_count"], 1)
            self.assertEqual(row["operator_id"], "CHE-12345")
            self.assertEqual(row["is_active"], 1)

        # 2. Second packet 0.5s later updates same encounter
        pkt2 = {
            "timestamp": t0 + 0.5,
            "mac": "60:60:1F:AA:BB:CC",
            "serial_number": "TEST_SERIAL_1",
            "transport": "wifi",
            "channel": 6,
            "rssi_dbm": -55,
            "messages": [
                {"type": "Location", "lat": 47.3775, "lon": 8.5420, "geodetic_altitude_m": 460.0, "speed_mps": 12.5, "direction_deg": 185}
            ]
        }
        enc_id2 = tracker.update_with_packet(pkt2)
        self.assertEqual(enc_id1, enc_id2)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM encounters WHERE encounter_id = ?", (enc_id1,)).fetchone()
            self.assertEqual(row["packet_count"], 2)
            self.assertEqual(row["min_rssi_dbm"], -65)
            self.assertEqual(row["max_rssi_dbm"], -55)
            self.assertEqual(row["max_alt_m"], 460.0)
            self.assertEqual(row["max_speed_mps"], 12.5)
            traj = json.loads(row["trajectory_json"])
            self.assertEqual(len(traj), 2)

        # 3. Simulate timeout check 2.0s later (> 1.0s timeout)
        closed = tracker.check_timeouts(now=t0 + 2.0)
        self.assertIn(enc_id1, closed)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT is_active FROM encounters WHERE encounter_id = ?", (enc_id1,)).fetchone()
            self.assertEqual(row["is_active"], 0)

        # 4. Third packet after timeout starts a NEW encounter
        pkt3 = {
            "timestamp": t0 + 5.0,
            "mac": "60:60:1F:AA:BB:CC",
            "serial_number": "TEST_SERIAL_1",
            "transport": "bt5",
            "channel": "Adv",
            "rssi_dbm": -70,
            "messages": [
                {"type": "Basic ID", "id": "TEST_SERIAL_1", "id_type": 1},
                {"type": "Location", "lat": 47.3800, "lon": 8.5500, "geodetic_altitude_m": 500.0, "speed_mps": 5.0, "direction_deg": 0}
            ]
        }
        enc_id3 = tracker.update_with_packet(pkt3)
        self.assertNotEqual(enc_id1, enc_id3)

        with sqlite3.connect(self.db_path) as conn:
            total_enc = conn.execute("SELECT COUNT(*) FROM encounters").fetchone()[0]
            self.assertEqual(total_enc, 2)

    def test_replay_jsonl_output_format(self):
        logger = UnifiedTelemetryLogger(
            log_jsonl_path=self.jsonl_path,
            db_path=self.db_path,
            encounter_timeout_s=300.0
        )

        t0 = time.time()
        pkt = {
            "timestamp": t0,
            "timestamp_iso": "2026-08-25T14:15:10.000Z",
            "transport": "bt5",
            "channel": "Adv",
            "counter": 42,
            "mac": "AA:BB:CC:DD:EE:FF",
            "rssi_dbm": -60,
            "serial_number": "TESTDRONE123",
            "messages": [
                {"type": "Basic ID", "id": "TESTDRONE123", "raw_hex": "02125445535444524F4E4531323300000000000000"}
            ],
            "messages_b64": [
                "AhJTcG9vZmVkX1NlcmlhbF80ODkyMQAAAA=="
            ]
        }

        logger.process_event(pkt)
        logger.close()

        # Verify JSONL lines can be loaded and have exact keys required by replay_drones.py
        with open(self.jsonl_path, "r") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])

            # Keys required by replay_drones.py
            self.assertIn("time_offset_ms", rec)
            self.assertIn("transport", rec)
            self.assertIn("counter", rec)
            self.assertIn("messages_b64", rec)
            self.assertIn("mac", rec)
            self.assertEqual(rec["transport"], "bt5")
            self.assertEqual(rec["counter"], 42)
            self.assertEqual(rec["mac"], "AA:BB:CC:DD:EE:FF")
            self.assertEqual(len(rec["messages_b64"]), 1)

    def test_geojson_export_structure(self):
        tracker = EncounterTracker(db_path=self.db_path, timeout_s=300.0)
        pkt = {
            "timestamp": 1756129000.0,
            "mac": "11:22:33:44:55:66",
            "serial_number": "GEOJSON_DRONE",
            "transport": "wifi",
            "channel": 6,
            "rssi_dbm": -50,
            "messages": [
                {"type": "Location", "lat": 47.3769, "lon": 8.5417, "geodetic_altitude_m": 450.0, "speed_mps": 10.0, "direction_deg": 180},
                {"type": "System", "pilot_lat": 47.3760, "pilot_lon": 8.5410, "pilot_alt_m": 410.0},
                {"type": "Operator ID", "operator_id": "CHE-999"},
            ]
        }
        enc_id = tracker.update_with_packet(pkt)
        tracker.finalize_all()

        # Run query_rid_db export logic
        from scanner.query_rid_db import get_db_connection
        conn = get_db_connection(self.db_path)
        row = conn.execute("SELECT * FROM encounters WHERE encounter_id = ?", (enc_id,)).fetchone()
        traj = json.loads(row["trajectory_json"])

        line_coords = [[pt[1], pt[0], pt[2] if pt[2] is not None else 0.0] for pt in traj]
        self.assertEqual(line_coords[0], [8.5417, 47.3769, 450.0])


if __name__ == "__main__":
    unittest.main()
