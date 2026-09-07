#!/usr/bin/env python3
import base64
import json
import os
import sys
import argparse

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.messages import build_all_messages, build_self_id
from drone_rid_spoofer.helpers import generate_ble_mac

def main():
    parser = argparse.ArgumentParser(description="Generate a NAN restart scenario.")
    parser.add_argument("--gap", type=int, default=10, help="Gap duration in seconds")
    args = parser.parse_args()

    mac_address = generate_ble_mac()
    serial = b"RESTART_TEST_01"
    
    # Drone starts at a specific location
    lat = 473769000
    lng = 85417000
    pilot_loc = (lat, lng)
    
    drone = DroneState(serial, pilot_loc, lat, lng, mac_address, mac_address)
    events = []
    
    fps = 2  # 2 Hz broadcast
    counter = 0
    time_ms = 0
    
    print("Generating Phase 1: Drone transmits normally...")
    for _ in range(15 * fps): # 15 seconds
        drone.lat += 10
        drone.lng += 10
        drone.drift_kinematics()
        drone.timestamp_offset = time_ms / 60000.0
        
        msgs = build_all_messages(drone, omit_self_id=True)
        msgs.insert(2, build_self_id(b"Drone (Phase 1)"))
        msgs_b64 = [base64.b64encode(m).decode('ascii') for m in msgs]
        
        events.append({
            "time_offset_ms": time_ms,
            "transport": "nan",
            "mac": mac_address,
            "session_id": "drone_1",
            "counter": counter % 256,
            "messages_b64": msgs_b64
        })
        
        counter += 1
        time_ms += (1000 // fps)
        
    print(f"Generating Gap: Changing payload to garbage for {args.gap} seconds...")
    events.append({
        "time_offset_ms": time_ms,
        "transport": "nan",
        "mac": mac_address,
        "session_id": "drone_1",
        "raw_payload_b64": base64.b64encode(b"NOT_A_RID_MESSAGE_JUST_GARBAGE_DATA").decode('ascii')
    })
    
    time_ms += args.gap * 1000 # Configurable seconds of silence
    
    print("Generating Phase 2: Drone restarts publishing...")
    for _ in range(15 * fps): # 15 seconds
        drone.lat += 10
        drone.lng += 10
        drone.drift_kinematics()
        drone.timestamp_offset = time_ms / 60000.0
        
        msgs = build_all_messages(drone, omit_self_id=True)
        msgs.insert(2, build_self_id(b"Drone (Phase 2)"))
        msgs_b64 = [base64.b64encode(m).decode('ascii') for m in msgs]
        
        events.append({
            "time_offset_ms": time_ms,
            "transport": "nan",
            "mac": mac_address,
            "session_id": "drone_1",
            "counter": counter % 256,
            "messages_b64": msgs_b64
        })
        
        counter += 1
        time_ms += (1000 // fps)
        
    out_file = os.path.join(os.path.dirname(__file__), "nan_restart.jsonl")
    with open(out_file, 'w') as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
            
    print(f"Generated {len(events)} events in {out_file}")
    print("You can now run this scenario using:")
    print(f"sudo .venv/bin/python3 experiments/replay_drones.py experiments/nan_restart.jsonl --transport nan")

if __name__ == "__main__":
    main()
