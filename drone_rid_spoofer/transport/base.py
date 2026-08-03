from abc import ABC, abstractmethod
from typing import List

from drone_rid_spoofer.state import DroneState


class TransportBackend(ABC):
    """Abstract base class for RID transport backends."""

    def __init__(self, fuzz_config: dict = None):
        self.fuzz_config = fuzz_config or {}

    @abstractmethod
    def start(self, drones: List[DroneState], packet_builder) -> None:
        """Start the backend transmission thread.

        Args:
            drones: Shared list of drone states to transmit.
            packet_builder: A callable `f(drone)` that generates ASTM messages on the fly.
        """

    @abstractmethod
    def close(self) -> None:
        """Release transport resources."""

    def remove_drone(self, drone: DroneState) -> None:
        """Remove and cleanup resources for an expired drone."""
        pass
