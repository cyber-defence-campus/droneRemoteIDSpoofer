"""Tests for MAC generation, coordinate parsing, and kinematic helpers."""
import re

import pytest

from drone_rid_spoofer import helpers

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _first_byte(mac: str) -> int:
    return int(mac.split(":")[0], 16)


def test_wifi_mac_is_unicast_locally_administered():
    # byte[0] must be xxxxxx10: multicast bit clear, LAA bit set. Checked over
    # many samples so the invariant holds regardless of the random draw.
    for _ in range(500):
        mac = helpers.generate_wifi_mac()
        assert MAC_RE.match(mac), mac
        b0 = _first_byte(mac)
        assert b0 & 0x01 == 0x00, f"multicast bit set: {mac}"
        assert b0 & 0x02 == 0x02, f"LAA bit clear: {mac}"


def test_ble_mac_is_static_random():
    # byte[0] must be 11xxxxxx for a BLE Static Random Address.
    for _ in range(500):
        mac = helpers.generate_ble_mac()
        assert MAC_RE.match(mac), mac
        assert _first_byte(mac) & 0xC0 == 0xC0, f"top two bits not set: {mac}"


def test_parse_location_valid_fixed_point():
    lat, lng = helpers.parse_location("47.3763399", "8.5312562")
    assert lat == 473763399
    assert lng == 85312562


@pytest.mark.parametrize("lat,lng", [
    ("91", "0"), ("-91", "0"), ("0", "181"), ("0", "-181"),
])
def test_parse_location_rejects_out_of_range(lat, lng):
    with pytest.raises(Exception):
        helpers.parse_location(lat, lng)


def test_parse_location_rejects_non_numeric():
    with pytest.raises(Exception):
        helpers.parse_location("abc", "1.0")


def test_drift_stays_within_bounds():
    for _ in range(500):
        v = helpers.drift(5.0, 2.0, 0.0, 10.0)
        assert 0.0 <= v <= 10.0


def test_drift_clamps_at_edges():
    # A large step from the boundary cannot escape the clamp range.
    assert helpers.drift(10.0, 100.0, 0.0, 10.0) <= 10.0
    assert helpers.drift(0.0, 100.0, 0.0, 10.0) >= 0.0
