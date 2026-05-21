import queue
import threading
from typing import List


class PacketQueue:
    """
    Fan-out queue: one producer (capture engine), multiple consumers (detectors).
    Each subscriber gets its own Queue and receives every packet independently.
    """

    def __init__(self, maxsize: int = 1000):
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()
        self._maxsize = maxsize

    def subscribe(self) -> queue.Queue:
        """Register a new consumer. Returns a Queue that will receive all future packets."""
        q = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._subscribers.append(q)
        return q

    def put(self, packet: dict) -> None:
        """Distribute a packet to all registered subscribers."""
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(packet)
            except queue.Full:
                pass  # slow consumer - drop packet rather than block

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)
