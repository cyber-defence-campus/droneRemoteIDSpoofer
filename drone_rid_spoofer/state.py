from dataclasses import dataclass
from datetime import datetime
from typing import Tuple, List, Optional

from drone_rid_spoofer.helpers import drift, random_location


@dataclass
class DroneState:
    """Represents the state of a single drone."""
    serial: bytes
    pilot_location: Tuple[int, int]
    lat: int
    lng: int
    mac_address: str       # Wi-Fi unicast LAA
    ble_address: str        # BLE Static Random
    direction: int = 0
    mode: str = "random"
    end_time: Optional[datetime] = None
    active: bool = True
    waypoints: Optional[List[Tuple[int, int, int]]] = None
    waypoint_index: int = 0
    next_waypoint_time: Optional[datetime] = None
    transport: Optional[str] = None  # per-drone transport override
    timestamp_offset: float = 0.0  # minutes to shift ASTM timestamp (negative = past)
    speed: float = 0.0              # horizontal speed (m/s)
    vertical_speed: float = 0.0     # vertical speed (m/s, + = climbing)
    pressure_altitude: float = 0.0  # meters MSL
    geodetic_altitude: float = 0.0  # meters MSL
    height: float = 0.0             # meters above takeoff/ground

    def update_location(self, step: int) -> None:
        """Update drone location randomly within step range."""
        self.lat, self.lng = random_location(self.lat, self.lng, step)

    def drift_kinematics(self) -> None:
        """Drift speed/vertical speed/altitudes/height by realistic small steps."""
        self.speed = drift(self.speed, 1.5, 0.0, 60.0)
        self.vertical_speed = drift(self.vertical_speed, 0.8, -10.0, 10.0)
        self.geodetic_altitude = drift(self.geodetic_altitude, 5.0, 0.0, 500.0)
        # Pressure altitude tracks geodetic with a small offset
        self.pressure_altitude = drift(self.pressure_altitude, 5.0, 0.0, 500.0)
        self.height = drift(self.height, 5.0, 0.0, 200.0)

    def move(self, direction: str, step: int) -> None:
        """Move drone in specified direction and update rotation."""
        direction_map = {
            'north': (step, 0, 0),
            'south': (-step, 0, 180),
            'east': (0, step, 90),
            'west': (0, -step, 270)
        }

        if direction in direction_map:
            lat_delta, lng_delta, rotation = direction_map[direction]
            self.lat += lat_delta
            self.lng += lng_delta
            self.direction = rotation
