"""Tests for SpooferConfig source-merging precedence.

Precedence is CLI argument > scenario `global` block > built-in default. The
helper builds an argparse.Namespace in which every flag is unset (None), i.e.
the state after argparse when nothing is passed on the command line.
"""
import argparse

from drone_rid_spoofer.config import DEFAULT_LAT, DEFAULT_LNG, SpooferConfig


def _ns(**overrides) -> argparse.Namespace:
    base = dict(
        interface=None, manual=False, random=None, serial=None, interval=None,
        location=None, transport=None, verbose=False, no_self_id=None,
        no_operator_id=None, ble_adapter=None, ble_interval=None,
        ble_extended_interval=None, ble_mode=None, wifi_ess=None,
        wifi_channel=None, wifi_beacon_interval=None, nan_port=None,
        nan_mode=None, nan_cluster_id=None, nan_instance_id=None,
        mac=None, ble_mac=None, operator_id=None, description=None,
        lifespan=None, static=None, pilot_location=None, timestamp_offset=None,
        speed=None, vertical_speed=None, geodetic_altitude=None,
        pressure_altitude=None, height=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_built_in_defaults():
    cfg = SpooferConfig.from_sources(_ns(), {})
    assert cfg.transport == "wifi"
    assert cfg.interval == 1.0
    assert cfg.location == (DEFAULT_LAT, DEFAULT_LNG)
    assert cfg.wifi_channel == 6
    assert cfg.ble_mode == "extended"
    assert cfg.random == 1


def test_scenario_overrides_default():
    cfg = SpooferConfig.from_sources(
        _ns(), {"global": {"transport": "ble", "interval": 2.0}})
    assert cfg.transport == "ble"
    assert cfg.interval == 2.0


def test_cli_overrides_scenario():
    cfg = SpooferConfig.from_sources(
        _ns(transport="nan", interval=0.5),
        {"global": {"transport": "ble", "interval": 2.0}})
    assert cfg.transport == "nan"
    assert cfg.interval == 0.5


def test_cli_can_negate_a_scenario_boolean():
    # Scenario enables the ESS bit; the CLI clears it (tri-state boolean).
    cfg = SpooferConfig.from_sources(
        _ns(wifi_ess=False), {"global": {"wifi": {"ess": True}}})
    assert cfg.wifi_ess is False


def test_ble_mode_defaults_to_dual_for_mixed_drones():
    drones = [{"ble_mode": "ext-legacy"}, {"ble_mode": "extended"}]
    cfg = SpooferConfig.from_sources(_ns(), {"drones": drones})
    assert cfg.ble_mode == "dual"


def test_ble_mode_normalizes_underscore_to_hyphen():
    cfg = SpooferConfig.from_sources(_ns(ble_mode="ext_legacy"), {})
    assert cfg.ble_mode == "ext-legacy"
