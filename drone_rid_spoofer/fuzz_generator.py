"""
Core Fuzzing Generators and Mutators for ASTM F3411 Remote ID.

Contains specialized mutation classes for evaluating receiver memory resilience,
parser buffer safety, reassembly state machines, and sanitization pipelines.
"""
import random
import struct
import time
from typing import List, Dict, Any, Tuple
from drone_rid_spoofer.messages import (
    MsgType,
    build_basic_id,
    build_location_vector,
    build_system,
    build_self_id,
    build_operator_id,
    build_all_messages,
    _encode_speed,
    _encode_vertical_speed,
    _encode_altitude,
    _transform_rotation,
)
from drone_rid_spoofer.state import DroneState


def build_auth_page_0(auth_type: int = 2, page_count: int = 1, length: int = 38,
                      timestamp: int = 0, auth_data: bytes = b'\x00' * 16,
                      protocol_version: int = 2) -> bytes:
    """Build ASTM F3411 Type 0x02 Authentication Message Page 0 (25 bytes).
    
    Layout: [MsgType/Ver(1)][Page=0(1)][AuthType(1)][PageCount(1)][Len(1)][Time(4)][Data(16)]
    """
    header = bytes([
        ((MsgType.AUTH << 4) | (protocol_version & 0x0F)) & 0xFF,
        0x00,  # Page Number 0
        auth_type & 0xFF,
        page_count & 0xFF,
        length & 0xFF
    ]) + struct.pack("<I", timestamp & 0xFFFFFFFF)
    
    body = (auth_data + b'\x00' * 16)[:16]
    return header + body


def build_auth_page_n(page_num: int, auth_data: bytes = b'\x00' * 23,
                      protocol_version: int = 2) -> bytes:
    """Build ASTM F3411 Type 0x02 Authentication Message Page N (25 bytes).
    
    Layout: [MsgType/Ver(1)][PageN(1)][Data(23)]
    """
    header = bytes([
        ((MsgType.AUTH << 4) | (protocol_version & 0x0F)) & 0xFF,
        page_num & 0xFF
    ])
    body = (auth_data + b'\x00' * 23)[:23]
    return header + body


class FuzzCategory:
    PACK_HEADER = "pack_header"
    NESTED_PACKS = "nested_packs"
    AUTH_PAGINATION = "auth_pages"
    STRING_INJECTION = "string_inject"
    KINEMATICS = "kinematics"
    PROTOCOL_VERSION = "protocol"
    ALL = "all"

    @classmethod
    def all_choices(cls) -> list:
        return [cls.PACK_HEADER, cls.NESTED_PACKS, cls.AUTH_PAGINATION, cls.STRING_INJECTION, cls.KINEMATICS, cls.PROTOCOL_VERSION, cls.ALL]


class RidFuzzer:
    """Master controller for generating fuzzed ASTM F3411 payloads and configs."""

    def __init__(self, category: str = FuzzCategory.ALL):
        self.category = category
        self._iteration = 0

        self.string_payloads = [
            # Missing null terminators (full length non-null strings)
            (b"ABCDEFGHIJKLMNOPQRST", b"12345678901234567890123"),
            # Format string vulnerabilities (ANSI C printf exploits)
            (b"%s%s%s%s%p%n%x%d%u%X", b"%x.%x.%x.%x.%s.%n.%p"),
            # OS Command Injection (targeted at shell telemetry pipelines - persistent PoC)
            (b";touch /poc;#       ", b"$(touch /poc); #       "),
            # DOM XSS Injection (targeted at web administrative monitoring frontends)
            (b"<script>c()</script>", b"<img src=x onerror=c()>"),
            # Extreme ASCII / binary junk
            (bytes([0xFF, 0xFE, 0xFD, 0x80] * 5), bytes([0x7F, 0x00, 0xFF] * 7 + [0x00, 0x00])),
        ]

        self.pack_configs = [
            {"pack_msg_size": 0x00},  # Zero size -> tests for infinite loop iteration
            {"pack_msg_size": 0xFF},  # Max byte size -> tests for buffer overread / heap leak
            {"pack_msg_size": 0x30},  # Misaligned message size
            {"pack_msg_count": 0x00}, # Claim 0 messages when messages exist
            {"pack_msg_count": 0xFF}, # Claim 255 messages when only a few exist -> out-of-bounds loop
            {"pack_msg_count": 0x0F, "disable_pack_limit": True}, # Bypass limits
        ]

        self.kinematic_edge_cases = [
            # Out of bounds coordinates (Lat ±91°, Lng ±181°, INT32_MAX, INT32_MIN)
            {"lat": 910000000, "lng": 1810000000, "dir": 361, "alt": 0xFFFF},
            {"lat": -910000000, "lng": -1810000000, "dir": 999, "alt": 0x0000},
            {"lat": 0x7FFFFFFF, "lng": 0x7FFFFFFF, "dir": 255, "alt": 0x7FFF},
            {"lat": -0x80000000, "lng": -0x80000000, "dir": 359, "alt": 0xFFFF},
        ]

    def get_next_fuzz_payload(self, drone: DroneState) -> Tuple[List[bytes], Dict[str, Any], str]:
        """Generate fuzzed message payload list, backend fuzz config, and attack description.
        
        Returns:
            Tuple of (messages_list, fuzz_config_dict, description_string)
        """
        self._iteration += 1
        
        active_cat = self.category
        if active_cat == FuzzCategory.ALL:
            categories = [
                FuzzCategory.PACK_HEADER,
                FuzzCategory.NESTED_PACKS,
                FuzzCategory.AUTH_PAGINATION,
                FuzzCategory.STRING_INJECTION,
                FuzzCategory.KINEMATICS,
                FuzzCategory.PROTOCOL_VERSION,
            ]
            active_cat = categories[self._iteration % len(categories)]

        if active_cat == FuzzCategory.PACK_HEADER:
            cfg = self.pack_configs[self._iteration % len(self.pack_configs)]
            msgs = build_all_messages(drone)
            desc = f"Message Pack Header Fuzzing -> Config Overrides: {cfg}"
            return msgs, cfg, desc

        elif active_cat == FuzzCategory.NESTED_PACKS:
            mode = self._iteration % 3
            if mode == 0:
                # Direct recursive nesting: internal message is itself an advertised pack header
                nested_header = bytes([(MsgType.PACK << 4) | 0x02, 0x19, 0x05]) + b"\xFA\x0B\xBC" * 7 + b"\x00"
                msgs = [
                    build_basic_id(drone.serial),
                    nested_header[:25],
                    build_location_vector(drone.lat, drone.lng, drone.direction, speed=drone.speed),
                ]
                desc = "Nested Message Packs -> Recursive Trigger: Injecting Type 0xF Pack header inside pack payload"
            elif mode == 1:
                # Zero-length nested pack (tests for zero-length recursion loops)
                zero_nested = bytes([(MsgType.PACK << 4) | 0x02, 0x00, 0xFF]) + b"\xFF" * 22
                msgs = [zero_nested[:25], build_basic_id(drone.serial)]
                desc = "Nested Message Packs -> Zero-Length Recursion: Nested pack with msg_size=0x00 and count=0xFF"
            else:
                # Deep nesting chain: multiple consecutive nested pack headers
                p1 = bytes([(MsgType.PACK << 4) | 0x02, 0x19, 0x02]) + b"\x11" * 22
                p2 = bytes([(MsgType.PACK << 4) | 0x02, 0x19, 0x01]) + b"\x22" * 22
                msgs = [build_basic_id(drone.serial), p1[:25], p2[:25]]
                desc = "Nested Message Packs -> Deep Nesting Chain: Multiple sequential Type 0xF headers in payload"
            return msgs, {}, desc

        elif active_cat == FuzzCategory.AUTH_PAGINATION:
            mode = self._iteration % 3
            if mode == 0:
                # Page count overflow: claim 255 pages and send illegal high page indexes
                msgs = [
                    build_basic_id(drone.serial),
                    build_auth_page_0(auth_type=2, page_count=255, length=255, timestamp=int(time.time())),
                    build_auth_page_n(page_num=18, auth_data=b"\xDE\xAD\xBE\xEF" * 5),
                    build_auth_page_n(page_num=254, auth_data=b"\xCA\xFE\xBA\xBE" * 5),
                ]
                desc = "Authentication Pagination -> Overflow: Claiming 255 total pages with illegal indexes (18, 254)"
            elif mode == 1:
                # Out-of-order and duplicate pages
                msgs = [
                    build_basic_id(drone.serial),
                    build_auth_page_0(auth_type=1, page_count=3, length=70),
                    build_auth_page_n(page_num=3, auth_data=b"\x11" * 23),
                    build_auth_page_n(page_num=2, auth_data=b"\x22" * 23),
                    build_auth_page_n(page_num=2, auth_data=b"\x33" * 23),  # Duplicate page 2 with conflicting bytes
                    build_auth_page_n(page_num=1, auth_data=b"\x44" * 23),
                ]
                desc = "Authentication Pagination -> Reassembly Corruption: Out-of-order & duplicate pages with conflicting data"
            else:
                # Unsupported authentication type & zero length
                msgs = [
                    build_basic_id(drone.serial),
                    build_auth_page_0(auth_type=0xFF, page_count=1, length=0),
                    build_auth_page_n(page_num=1, auth_data=b"\xFF" * 23),
                ]
                desc = "Authentication Pagination -> Edge Cases: Illegal AuthType 0xFF with Length 0"
            return msgs, {}, desc

        elif active_cat == FuzzCategory.STRING_INJECTION:
            basic_payload, self_payload = self.string_payloads[self._iteration % len(self.string_payloads)]
            
            # Custom basic ID without standard termination/padding rules
            header_basic = bytes([(MsgType.BASIC_ID << 4) | 0x02, 0x12])
            custom_basic = (header_basic + basic_payload.ljust(23, b'\x41'))[:25]
            
            header_self = bytes([(MsgType.SELF_ID << 4) | 0x02, 0x00])
            custom_self = (header_self + self_payload.ljust(23, b'\x42'))[:25]

            msgs = [
                custom_basic,
                build_location_vector(drone.lat, drone.lng, drone.direction, speed=drone.speed),
                custom_self,
                build_system(drone.pilot_location[0], drone.pilot_location[1]),
            ]
            desc = f"String & Injection Safety -> BasicID: {basic_payload[:15]!r} | SelfID: {self_payload[:15]!r}"
            return msgs, {}, desc

        elif active_cat == FuzzCategory.KINEMATICS:
            edge = self.kinematic_edge_cases[self._iteration % len(self.kinematic_edge_cases)]
            
            # Construct raw location message with forced illegal coordinates and angles
            dir_val, ew_dir = _transform_rotation(edge["dir"])
            raw_loc = b''.join([
                struct.pack("<B", (MsgType.LOCATION << 4) | 0x02),
                struct.pack("<B", ew_dir & 0xFF),
                struct.pack("<B", dir_val & 0xFF),
                struct.pack("<B", 255),
                struct.pack("<b", -127),
                struct.pack("<i", edge["lat"]),
                struct.pack("<i", edge["lng"]),
                struct.pack("<H", edge["alt"]),
                struct.pack("<H", edge["alt"]),
                struct.pack("<H", edge["alt"]),
                b'\x00\x00\x00\x00\x00\x00',
            ])[:25]

            msgs = [
                build_basic_id(drone.serial),
                raw_loc,
                build_system(edge["lat"], edge["lng"]),
            ]
            desc = f"Kinematic Edge-Cases -> Lat: {edge['lat']}, Lng: {edge['lng']}, Dir: {edge['dir']}, Alt: {edge['alt']}"
            return msgs, {}, desc

        elif active_cat == FuzzCategory.PROTOCOL_VERSION:
            ver_override = (self._iteration % 15) + 1
            msgs = []
            for m in build_all_messages(drone):
                new_byte0 = ((m[0] & 0xF0) | ver_override) & 0xFF
                msgs.append(bytes([new_byte0]) + m[1:])
                
            cfg = {"pack_type_ver": (MsgType.PACK << 4) | ver_override}
            desc = f"Protocol Version Fuzzing -> Forcing version nibble to 0x{ver_override:X}"
            return msgs, cfg, desc

        else:
            return build_all_messages(drone), {}, "Baseline valid ASTM messages"
