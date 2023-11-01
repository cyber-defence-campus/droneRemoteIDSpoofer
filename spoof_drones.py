import argparse
import logging
import select
import struct
import sys
import termios
import tty
import random
from datetime import datetime, timedelta

import scapy.layers.dot11 as scapy
from scapy.sendrecv import sendp

logging.basicConfig(level=logging.NOTSET, format='%(asctime)s %(levelname)s %(message)s')


DEFAULT_LAT: int = 473763399
DEFAULT_LNG: int = 85312562


class ParseLocationAction(argparse.Action):
    """Parse location values during argument parsing"""

    def __call__(self, parser, namespace, values, option_string=None):
        paths = self.parse_location(values[0], values[1])
        setattr(namespace, self.dest, paths)

    def parse_location(self, latitude: str, longitude: str) -> tuple[int, int]:
        """
        Parses the values for argument location of argparse. The values represent the latitude and longitude of a
        location. Accordingly, the values are required to be between a certain value. Latitude: [-90, 90],
        Longitude: [-180, 180]. Both exclusive. If no value is passed as an argument, it defaults to Kasernenareal,
        Zürich.

        Args:
            latitude: Latitude of drone. Value between -90 and 90, exclusive.
            longitude: Longitude of drone. Value between -180 and 180, exclusive.

        Returns:
            tuple[int, int]: Starting location [latitude, longitude].
        """
        lat_ = float(latitude)
        lng_ = float(longitude)
        if -90 >= lat_ or lat_ >= 90:
            raise argparse.ArgumentTypeError(f"LATITUDE value must be between -90 and 90, exclusive. was: {lat_}")
        if -180 >= lng_ or lng_ >= 180:
            raise argparse.ArgumentTypeError(f"LONGITUDE value must be between -180 and 180, exclusive. was: {lng_}")
        return int(lat_ * 10 ** 7), int(lng_ * 10 ** 7)


def parse_args() -> argparse.Namespace:
    description = "Spoofes drone remote id (RID) packets with scapy. The format of the packets are compliant with " \
                  "ASTM regulation. The packets are sent to an interface which defaults to wlx801f02f1e3c9 but can " \
                  "be defined with the -i argument. This script can be used to test the drone monitoring system by " \
                  "spoofing drones.\n\nREQUIREMENT: to use the script scapy has to be installed."

    # user-friendly command-line interface
    argparser = argparse.ArgumentParser(prog="Drone Spoofer",
                                        formatter_class=argparse.RawTextHelpFormatter,
                                        description=description)
    argparser.add_argument("-i", "--interface", help="interface name")
    argparser.add_argument("-m", "--manual", help="manual mode, to control drone movement", action="store_true")
    argparser.add_argument("-r", "--random", type=int, default=1,
                           help="random mode, spoof multiple random drones without motion")
    argparser.add_argument("-s", "--serial", type=lambda x: x if 20 >= len(x) > 0 else False,
                           help="set drones serial number. (incompatible with multiple drones)")
    argparser.add_argument("-n", "--interval", type=float, default=3,
                           help="interval in seconds, time between sending packets")
    argparser.add_argument("-l", "--location", nargs=2, metavar=("LATITUDE", "LONGITUDE"), action=ParseLocationAction,
                           help="start location, to customise the starting point")
    return argparser.parse_args()


# ==== Create minimal Wi-Fi Beacon Paket ====
dest_addr = 'ff:ff:ff:ff:ff:ff'  # address 1
src_addr = '90:3a:e6:5b:c8:a8'  # address 2

# IE: SSID
drone_ssid = 'AnafiThermal-Spoofed'
ie_ssid = scapy.Dot11Elt(ID='SSID', len=len(drone_ssid), info=drone_ssid)

# Captured from Parrot Anafi Thermal
header = b'\x0d\x5d\xf0\x19\x04'  # oui: fa:0b:bc (ASD-STAN)
msg_type_5 = b'\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def is_data() -> bool:
    """
    I do not know what this method does exactly, but it is needed to ensure that the packets are regularly sent after
    the passing of 3 seconds.

    Returns:
        bool: True if idk... else False.
    """
    return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])


def get_random_serial_number() -> bytes:
    """
    Method to create a random (but not unique) serial number for a drone.

    Returns:
        bytes: Randomly generated serial number.
    """
    integer_val = random.randint(1, 99999)
    serial_byte = "Spoofed_Serial_" + str(integer_val)
    return serial_byte.encode()


def get_random_pilot_location(lat_: int, lng_: int) -> tuple[int, int]:
    """
    Calculates a random pilot location withing a specific range and based on the starting location of the drone.

    Args:
        lat_ (int): Latitude of drone.
        lng_ (int): Longitude of drone.

    Returns:
        tuple[int, int]: Pilot location (latitude, longitude).
    """
    return lat_ + random.randint(-10000, 10000), lng_ + random.randint(-10000, 10000)


def transform_rotation(rot: int) -> tuple[int, int]:
    """
    Method to transform the rotation value of the drone to be sent. It checks the rotation and transforms the value
    accordingly. The transmitted value must be within 0 - 179. Depending on if the original rotation value was higher
    than 180 or lower, an additional value of 32 or 34 is appended. The additional value is an int value for simplicity
    reasons. It sets a specific bit (E/W direction Segment Bit) when transformed to byte. For more information see the
    ASTM F3411 - 19 regulation.

    Args:
        rot (int): Rotation of the drone. In degrees (0-359).

    Returns:
        tuple[int, int]: Transformed rotation value, value to set E/W direction segment bit.
    """
    if rot < 0 or rot > 359:
        return 0, 32
    elif rot < 90:
        return rot, 32
    elif rot < 180:
        return rot, 32
    elif rot < 270:
        return rot - 180, 34
    return rot - 180, 34


def create_packet(lat_: int, lng_: int, serial: bytes, pilot_loc: tuple[int, int], rotation: int = 0) -> scapy.RadioTap:
    """
    Creates the message types 0, 1 and 4 according to the ASTM F3411-19 - Standard Specification for Remote ID and
    Tracking and composes then a full Wi-Fi Beacon Frame containing the message types 0, 1, 4 and 5.

    Args:
        lat_ (int): Latitude of drone.
        lng_ (int): Longitude of drone.
        serial (bytes): Serial number of drone in bytes.
        pilot_loc (tuple[int, int]): Location (latitude, longitude) of drone pilot.
        rotation (int): Drone rotation (0 - 359°).

    Returns:
        scapy.RadioTap: Wi-Fi Beacon Frame containing Remote ID information
    """
    serial_byte = struct.pack("<20s", serial)
    msg_type_0 = b''.join([b'\x00\x12', serial_byte, b'\x00\x00\x00'])

    direction, ew_dir = transform_rotation(rotation)
    ew_dir_byte = struct.pack("<B", ew_dir)
    direction_byte = struct.pack("<B", direction)
    lat_byte = struct.pack("<i", lat_)
    lng_byte = struct.pack("<i", lng_)
    now = datetime.now()
    tenth_seconds_byte = struct.pack("<H", now.minute*600 + now.second*10)
    msg_type_1 = b''.join(
        [b'\x10', ew_dir_byte, direction_byte, b'\x00\x00', lat_byte, lng_byte, b'\x00\x00\x00\x00\xd0\x07\x00\x00',
         tenth_seconds_byte, b'\x00\x00'])

    pilot_lat_byte = struct.pack("<i", pilot_loc[0])
    pilot_lng_byte = struct.pack("<i", pilot_loc[1])
    msg_type_4 = b''.join([b'\x40\x05', pilot_lat_byte, pilot_lng_byte,
                           b'\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00'])

    vendor_spec_data = b''.join([header, msg_type_0, msg_type_1, msg_type_4, msg_type_5])
    ie_vendor_parrot = scapy.Dot11EltVendorSpecific(ID=221, len=len(vendor_spec_data), oui=16387004,
                                                    info=vendor_spec_data)

    return scapy.RadioTap() / scapy.Dot11(type=0, subtype=8, addr1=dest_addr, addr2=src_addr,
                                          addr3=src_addr) / scapy.Dot11Beacon() / ie_ssid / ie_vendor_parrot


def spoof_controlled_drone(args: argparse.Namespace) -> None:
    """
    Sends regularly (defaults to every 3 seconds) another Wi-Fi Beacon frame (static information) according to ASTM
    F3411-19 - Standard Specification for Remote ID and Tracking until the script is interrupted. The location of the
    drone can be manually adjusted by pressing the following keys: w (north), s (south), a (west) and d (east).

    Args:
        args (argparse.Namespace): Object containing command arguments.
    """
    seconds: int = args.interval
    step = 1000
    lat_, lng_ = args.location

    send_next = datetime.now() + timedelta(seconds=seconds)
    stdin = sys.stdin.fileno()
    tattr = termios.tcgetattr(stdin)

    serial = args.serial.encode() if args.serial else get_random_serial_number()
    lat_, lng_ = random_location(lat_, lng_, step*10) # so if we spoof consectutively they dont appear too close
    direction = 0
    pilot_loc = get_random_pilot_location(lat_, lng_)
    logging.info(f"Drone with SERIAL NUMBER {serial} and LOCATION [LAT LNG] {lat_}, {lng_} created.")
    logging.info(f"Starting spoofing....\nUse W, A, S, D to move the drone.\nW (North)\nA (West)\nS (South)\nD (East)")

    s = conf.L2socket(iface=args.interface)
    try:
        tty.setcbreak(sys.stdin.fileno())
        while True:
            if is_data():
                c = sys.stdin.read(1)
                if c == '\x61':
                    logging.info(f"move WEST")
                    direction = 270
                    lng_ -= step
                elif c == '\x64':
                    logging.info(f"move EAST")
                    direction = 90
                    lng_ += step
                elif c == '\x77':
                    logging.info(f"move NORTH")
                    direction = 0
                    lat_ += step
                elif c == '\x73':
                    logging.info(f"move SOUTH")
                    direction = 180
                    lat_ -= step

            if send_next < datetime.now():  # only send packets every 3 seconds
                packet = create_packet(lat_, lng_, serial, pilot_loc, direction)
                s.send(packet)
                logging.info(f"Sent {serial}")
                send_next = datetime.now() + timedelta(seconds=seconds)

        s.close()
    except KeyboardInterrupt:
        logging.info("Script interrupted. Shutting down..")
    finally:
        termios.tcsetattr(stdin, termios.TCSANOW, tattr)


def spoof_automatic_drones(args: argparse.Namespace) -> None:
    """
    Sends regularly (defaults to every 3 seconds) another Wi-Fi Beacon frame (static information) according to ASTM
    F3411-19 - Standard Specification for Remote ID and Tracking until the script is interrupted. The location of the
    drone changes randomly. The number of drones to spoof can be customised via command line argument manual. It
    defaults to 1.

    Args:
        args (argparse.Namespace): Object containing command arguments.
    """
    seconds: int = args.interval
    lat_, lng_ = args.location
    step = 10000

    logging.info(f"Starting in RANDOM MODE - spoofing {args.random} drones.")
    drone_list = []
    send_next = datetime.now() + timedelta(seconds=seconds)

    
    n_drones = args.random
    for i in range(n_drones):
        serial = get_random_serial_number()
        pilot_loc = get_random_pilot_location(lat_, lng_)
        drone_list.append((serial, pilot_loc, lat_, lng_))
        logging.info(f"Drone with SERIAL NUMBER {serial} created.")

    try:
        
        packet_list = []
        for i, tup in enumerate(drone_list):
            serial_i, pilot_loc_i, lat_prev, lng_prev = tup
            lat_i, lng_i = random_location(lat_prev, lng_prev, step)
            drone_list[i] = serial_i, pilot_loc_i, lat_i, lng_i
            packet = create_packet(lat_i, lng_i, serial_i, pilot_loc_i)
            packet_list.append(packet)

        s = conf.L2socket(iface=args.interface)
        counter = 0
        while True:
            if send_next < datetime.now():  # only send packets every 3 seconds
                i = 0
                for p in packet_list:
                    s.send(p)
                    logging.info(f"Sent {drone_list[i][0]}")
                    i +=1
                    counter += 1
                print("Packets sent: %i " % counter)

                send_next = datetime.now() + timedelta(seconds=seconds)
        s.close()
    except KeyboardInterrupt:
        s.close()
        sys.exit(0)
        logging.info("Script interrupted. Shutting down..")


def random_location(lat_: int, lng_: int, distance: int = 100000) -> tuple[int, int]:
    """
    Generate a pair of coordinates randomly around a given location.

    Args:
        lat_ (int): Latitude of drone.
        lng_ (int): Longitude of drone.
        distance (int): Max distance to original point.

    Returns:
        tuple[int, int]: New random location [latitude, longitude].
    """
    lat_new = lat_ + random.randint(-distance, distance)
    lng_new = lng_ + random.randint(-distance, distance)

    return int(lat_new), int(lng_new)


def main() -> None:
    args = parse_args()
    logging.info("########## STARTING DRONE SPOOFER ##########")
    #  Setup interface
    if not args.interface:
        logging.info("No interface detected. Using default value.")
        args.interface = "wlan1"
    logging.info(f"Setting interface to: {args.interface}")

    #  Setup location, defaults to Kasernenareal
    if not args.location:
        logging.info("No location input detected. Using DEFAULT values.")
        args.location = DEFAULT_LAT, DEFAULT_LNG
    logging.info(f"Setting location to {args.location}.")

    # Choose mode
    if args.manual:
        logging.info("Starting in MANUAL MODE - spoofing one user controlled drone.")
        spoof_controlled_drone(args)
    else:
        if args.random <1:
            print("When using random mode (-r) the minimum value is 1")
            sys.exit(0)

        spoof_automatic_drones(args)


if __name__ == '__main__':
    main()
