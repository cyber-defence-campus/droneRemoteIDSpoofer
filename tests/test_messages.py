"""Tests for the ASTM F3411 message builders.

These cover the fixed 25-byte size, the message-type/version header nibbles, the
scalar field encoders, and a build->decode round trip through the parser for the
identity and location fields.
"""
from drone_rid_spoofer import messages
from drone_rid_spoofer.messages import MsgType
from drone_rid_spoofer.parser import decode_astm_message
from drone_rid_spoofer.state import DroneState

PROTO = 2


def _drone(serial: bytes = b"TESTSERIAL1") -> DroneState:
    return DroneState(
        serial=serial,
        pilot_location=(473000000, 85000000),
        lat=473763399, lng=85312562,
        mac_address="02:00:00:00:00:01",
        ble_address="c0:00:00:00:00:01",
    )


def test_every_builder_emits_25_bytes():
    assert len(messages.build_basic_id(b"SERIAL123")) == 25
    assert len(messages.build_location_vector(0, 0, 0)) == 25
    assert len(messages.build_system(0, 0)) == 25
    assert len(messages.build_self_id()) == 25
    assert len(messages.build_operator_id("OP-1")) == 25


def test_header_type_and_version_nibbles():
    assert messages.build_basic_id(b"x")[0] == (MsgType.BASIC_ID << 4) | PROTO
    assert messages.build_location_vector(0, 0, 0)[0] == (MsgType.LOCATION << 4) | PROTO
    assert messages.build_self_id()[0] == (MsgType.SELF_ID << 4) | PROTO
    assert messages.build_system(0, 0)[0] == (MsgType.SYSTEM << 4) | PROTO
    assert messages.build_operator_id()[0] == (MsgType.OPERATOR_ID << 4) | PROTO


def test_encode_speed_units_and_clamp():
    assert messages._encode_speed(0.0) == 0
    assert messages._encode_speed(0.25) == 1      # 0.25 m/s unit
    assert messages._encode_speed(1.0) == 4
    assert messages._encode_speed(10_000.0) == 255  # clamped to uint8


def test_encode_vertical_speed_signed_units_and_clamp():
    assert messages._encode_vertical_speed(0.0) == 0
    assert messages._encode_vertical_speed(0.5) == 1    # 0.5 m/s unit
    assert messages._encode_vertical_speed(-0.5) == -1
    assert messages._encode_vertical_speed(1000.0) == 127
    assert messages._encode_vertical_speed(-1000.0) == -127


def test_encode_altitude_offset_and_clamp():
    assert messages._encode_altitude(0.0) == 2000       # (0 + 1000) * 2
    assert messages._encode_altitude(-1000.0) == 0      # clamped low
    assert messages._encode_altitude(1e9) == 0xFFFF     # clamped high


def test_basic_id_serial_round_trips():
    decoded = decode_astm_message(messages.build_basic_id(b"ABC123"))
    assert decoded["msg_type"] == 0x0
    assert decoded["id"] == "ABC123"


def test_location_lat_lng_round_trips():
    msg = messages.build_location_vector(473763399, 85312562, 90, speed=4.0)
    decoded = decode_astm_message(msg)
    assert decoded["msg_type"] == 0x1
    assert abs(decoded["lat"] - 47.3763399) < 1e-6
    assert abs(decoded["lon"] - 8.5312562) < 1e-6
    assert decoded["speed"] == 4.0


def test_build_all_messages_default_set():
    msgs = messages.build_all_messages(_drone())
    # Basic ID, Location, Self-ID, System, Operator ID.
    assert len(msgs) == 5
    assert all(len(m) == 25 for m in msgs)


def test_build_all_messages_omit_flags():
    d = _drone()
    assert len(messages.build_all_messages(d, omit_self_id=True)) == 4
    assert len(messages.build_all_messages(d, omit_operator_id=True)) == 4
    assert len(messages.build_all_messages(d, omit_self_id=True, omit_operator_id=True)) == 3
