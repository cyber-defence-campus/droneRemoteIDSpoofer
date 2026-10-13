"""Synchronization primitive shared by the spoofing controller and the backends.

The controller thread is the sole writer of drone state (position, kinematics,
active flag); each transport backend runs its own transmit thread that only
reads that state. `GenerationLock` is the lock those threads share, paired with
a monotonic generation counter that lets readers cheaply detect when the state
has changed. It holds no drone data of its own -- the drone list is shared
directly between controller and backends.

  * The controller mutates drones only inside ``with gen_lock.write():`` which
    holds the lock and bumps the generation counter on exit.
  * Each backend reads under the same lock and caches the packets it built,
    rebuilding only when the generation advances (see
    ``TransportBackend._refresh_packets``).

Before this, backends read mutable ``DroneState`` objects while the controller
mutated them, with no synchronization -- correct only by accident of the GIL.
"""
import threading
from contextlib import contextmanager
from typing import Iterator


class GenerationLock:
    """A lock paired with a monotonic generation counter.

    Writers take the lock and bump the generation; readers take the lock and
    compare the generation against the one their cache was built at.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self._generation = 0

    @property
    def generation(self) -> int:
        """Monotonic counter; advances once per committed write batch."""
        return self._generation

    @contextmanager
    def write(self) -> Iterator[None]:
        """Hold the lock for a batch of drone-state mutations.

        On clean exit the generation counter is bumped so reader threads know
        to rebuild their packet caches.
        """
        with self.lock:
            yield
            self._generation += 1
