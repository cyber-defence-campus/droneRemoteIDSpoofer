"""Tests for the TransportBackend two-phase lifecycle and packet cache.

A concrete backend is exercised here without any radio or socket, which is the
property the architecture relies on: construction is pure, resources are only
acquired in open(), and the generation-gated cache rebuilds payloads only when
the controller advances the generation.
"""
from typing import List, Optional

from drone_rid_spoofer.generation_lock import GenerationLock
from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.transport.base import TransportBackend


class FakeBackend(TransportBackend):
    """Minimal in-memory backend that acquires no OS resources."""

    def __init__(self):
        super().__init__()
        self.acquire_calls = 0
        self.cleaned_up: List[DroneState] = []

    def _acquire(self) -> None:
        self.acquire_calls += 1

    def _cleanup_drone(self, drone: DroneState) -> None:
        self.cleaned_up.append(drone)

    def start(self, drones, packet_builder, gen_lock: Optional[GenerationLock] = None):
        self._bind(drones, packet_builder, gen_lock)
        self.open()

    def close(self) -> None:
        pass


def _drone(serial: bytes = b"S1") -> DroneState:
    return DroneState(
        serial=serial, pilot_location=(1, 2), lat=1, lng=2,
        mac_address="02:00:00:00:00:01", ble_address="c0:00:00:00:00:01",
    )


def test_construction_acquires_nothing():
    b = FakeBackend()
    assert b._opened is False
    assert b.acquire_calls == 0


def test_open_acquires_once_and_is_idempotent():
    b = FakeBackend()
    b.open()
    b.open()
    assert b.acquire_calls == 1
    assert b._opened is True


def test_packet_cache_rebuilds_only_on_new_generation():
    builds = {"n": 0}

    def builder(drone: DroneState) -> List[bytes]:
        builds["n"] += 1
        return [b"payload"]

    gl = GenerationLock()
    b = FakeBackend()
    b._bind([_drone()], builder, gl)

    b._active_packets()
    after_first = builds["n"]
    assert after_first == 1          # built once for the one active drone

    b._active_packets()
    assert builds["n"] == after_first  # cache hit: same generation, no rebuild

    with gl.write():
        pass                          # controller commits a new generation
    b._active_packets()
    assert builds["n"] == after_first + 1  # rebuilt after the generation advanced


def test_cache_rebuilds_every_call_without_a_generation_lock():
    builds = {"n": 0}

    def builder(drone: DroneState) -> List[bytes]:
        builds["n"] += 1
        return [b"payload"]

    b = FakeBackend()
    b._bind([_drone()], builder, None)  # standalone/PoC path: no coordinator

    b._active_packets()
    b._active_packets()
    assert builds["n"] == 2             # no gating, rebuilt each call


def test_removals_are_deferred_then_drained():
    b = FakeBackend()
    drone = _drone()
    b.remove_drone(drone)                 # controller thread only enqueues
    assert len(b._pending_removals) == 1
    assert b.cleaned_up == []

    b._drain_removals()                   # transmit thread performs cleanup
    assert len(b._pending_removals) == 0
    assert b.cleaned_up == [drone]
