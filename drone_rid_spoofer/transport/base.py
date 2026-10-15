from abc import ABC, abstractmethod
from collections import deque
from typing import Callable, Deque, List, Optional, Tuple

from drone_rid_spoofer.generation_lock import GenerationLock
from drone_rid_spoofer.state import DroneState

# The one contract every backend expects from a packet builder: a plain callable
# that maps a drone's current state to its list of ASTM message payloads. Kept as
# a named alias so the backends and their callers can't silently drift apart.
PacketBuilder = Callable[[DroneState], List[bytes]]


class TransportBackend(ABC):
    """Abstract base class for RID transport backends."""

    def __init__(self, fuzz_config: dict = None):
        self.fuzz_config = fuzz_config or {}
        self._drones: List[DroneState] = []
        self._packet_builder: Optional[PacketBuilder] = None
        self._gen_lock: Optional[GenerationLock] = None
        # Per-generation packet cache: rebuilt only when the controller commits
        # a new drone-state generation, so the hot transmit path does an int
        # compare instead of re-encoding every ASTM message each tick.
        self._pkt_cache_gen: int = -1
        self._pkt_cache_list: List[Tuple[DroneState, List[bytes]]] = []
        # Drones the controller has asked to remove. The controller thread only
        # appends here; the transmit thread drains it via `_drain_removals` and
        # performs the actual per-backend cleanup. This keeps every bookkeeping
        # dict mutated by exactly one thread (deque append/popleft are atomic in
        # CPython), instead of the controller and transmit threads racing on it.
        self._pending_removals: "Deque[DroneState]" = deque()

    @abstractmethod
    def start(self, drones: List[DroneState], packet_builder: PacketBuilder,
              gen_lock: Optional[GenerationLock] = None) -> None:
        """Start the backend transmission thread.

        Args:
            drones: Shared list of drone states to transmit.
            packet_builder: A callable `f(drone) -> list[bytes]` that generates
                the ASTM message payloads for a drone on the fly.
            gen_lock: Optional coordinator shared with the controller. When given,
                reads of drone state are serialized against the controller's
                writes and the packet cache is generation-gated. When omitted
                (e.g. standalone PoC callers), the cache rebuilds every tick with
                no cross-thread guarantees — the pre-coordinator behavior.
        """

    @abstractmethod
    def close(self) -> None:
        """Release transport resources."""

    def _bind(self, drones: List[DroneState], packet_builder: PacketBuilder,
              gen_lock: Optional[GenerationLock]) -> None:
        """Store the shared state handed to :meth:`start`. Call from subclasses."""
        self._drones = drones
        self._packet_builder = packet_builder
        self._gen_lock = gen_lock

    def _refresh_packets(self) -> None:
        """Rebuild the packet cache iff the controller advanced the generation.

        With a GenerationLock, the (fast) rebuild runs under its lock so it never
        races the controller's mutations; the common cache-hit path just reads
        the generation. Without one, there is nothing to gate on, so the cache is
        rebuilt every call to preserve the legacy behavior.
        """
        builder = self._packet_builder
        if builder is None:
            return

        gen_lock = self._gen_lock
        if gen_lock is None:
            active = [d for d in self._drones if getattr(d, "active", True)]
            self._pkt_cache_list = [(d, builder(d)) for d in active]
            return

        with gen_lock.lock:
            if gen_lock.generation == self._pkt_cache_gen:
                return
            active = [d for d in self._drones if getattr(d, "active", True)]
            self._pkt_cache_list = [(d, builder(d)) for d in active]
            self._pkt_cache_gen = gen_lock.generation

    def _active_packets(self) -> List[Tuple[DroneState, List[bytes]]]:
        """Active drones paired with their freshly-cached ASTM message payloads."""
        self._refresh_packets()
        return self._pkt_cache_list

    def remove_drone(self, drone: DroneState) -> None:
        """Request cleanup of an expired drone. Safe to call from any thread.

        Called by the controller thread. The actual cleanup is deferred to the
        transmit thread (see :meth:`_drain_removals`) so per-backend bookkeeping
        is only ever mutated by the thread that also builds and sends packets.
        """
        self._pending_removals.append(drone)

    def _drain_removals(self) -> None:
        """Perform any pending drone cleanups. Call from the transmit thread.

        Must be invoked at the top of each transmit cycle so bookkeeping for
        removed drones is reclaimed on the same thread that reads it.
        """
        while True:
            try:
                drone = self._pending_removals.popleft()
            except IndexError:
                break
            self._cleanup_drone(drone)

    def _cleanup_drone(self, drone: DroneState) -> None:
        """Backend-specific cleanup for one removed drone (transmit thread).

        Subclasses override this to release per-drone bookkeeping (counters,
        rotation indices, external publish sessions). The default is a no-op.
        """
        pass
