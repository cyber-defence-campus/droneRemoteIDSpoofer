"""Tests for the controller/backend synchronization primitive."""
from drone_rid_spoofer.generation_lock import GenerationLock


def test_generation_advances_once_per_write():
    gl = GenerationLock()
    start = gl.generation
    with gl.write():
        pass
    assert gl.generation == start + 1
    with gl.write():
        pass
    assert gl.generation == start + 2


def test_lock_is_held_inside_write_and_released_after():
    gl = GenerationLock()
    assert not gl.lock.locked()
    with gl.write():
        assert gl.lock.locked()
    assert not gl.lock.locked()


def test_generation_still_advances_on_exception():
    # The counter is bumped on clean exit of the context body; an exception
    # should still release the lock (so the backends are not deadlocked).
    gl = GenerationLock()
    try:
        with gl.write():
            raise ValueError("boom")
    except ValueError:
        pass
    assert not gl.lock.locked()
