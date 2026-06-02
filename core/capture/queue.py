import queue
import threading
from typing import List


class PacketQueue:
    """
    Fan-out queue architecture for packet distribution.
    Ensures thread-safe delivery of network packets from a single producer 
    (Capture Engine) to multiple isolated consumer queues (Detectors).
    """

    def __init__(self, maxsize: int = 1000):
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()
        self._maxsize = maxsize

    def subscribe(self) -> queue.Queue:
        """
        Registers a new consumer and provisions a dedicated queue.
        Returns the queue instance to be polled by the consumer thread.
        """
        q = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._subscribers.append(q)
        return q

    def put(self, packet: dict) -> None:
        """
        Distributes a parsed packet to all registered subscribers.
        Drops the packet for a specific consumer if its queue is full, 
        preventing a slow consumer from blocking the main capture engine.
        """
        with self._lock:
            subscribers = list(self._subscribers)
            
        for q in subscribers:
            try:
                q.put_nowait(packet)
            except queue.Full:
                pass

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)