import queue                                            # Python's built-in thread-safe queue module
import threading                                        # provides Lock to prevent race conditions between threads
from typing import List                                 # allows us to write List[queue.Queue] as a type hint


class PacketQueue:
    """
    Fan-out queue: one producer (capture engine), multiple consumers (detectors).
    Each subscriber gets its own Queue and receives every packet independently.
    """

    def __init__(self, maxsize: int = 1000):            # constructor – runs once when PacketQueue() is created
        self._subscribers: List[queue.Queue] = []       # holds one Queue object per registered detector
        self._lock = threading.Lock()                   # mutex – only one thread can modify _subscribers at a time
        self._maxsize = maxsize                         # max packets a subscriber queue holds before dropping begins

    def subscribe(self) -> queue.Queue:                 # each detector calls this once at startup to register itself
        """Register a new consumer. Returns a Queue that will receive all future packets."""
        q = queue.Queue(maxsize=self._maxsize)          # create a private, isolated queue for this subscriber
        with self._lock:                                # acquire the lock – no other thread can touch _subscribers now
            self._subscribers.append(q)                 # add this detector's queue to the shared list
        return q                                        # hand the queue back – the detector will poll it for packets

    def put(self, packet: dict) -> None:               # capture engine calls this once for every incoming packet
        """Distribute a packet to all registered subscribers."""
        with self._lock:                                # acquire lock before reading the shared list
            subscribers = list(self._subscribers)       # snapshot the list so the lock can be released immediately
        for q in subscribers:                           # loop over every detector's personal queue
            try:
                q.put_nowait(packet)                    # insert the packet without waiting – raises Full if no space
            except queue.Full:
                pass                                    # slow consumer - drop packet rather than block the engine

    @property
    def subscriber_count(self) -> int:                 # read-only property – useful for logging and health checks
        with self._lock:                                # lock needed – another thread might be adding a subscriber
            return len(self._subscribers)              # number of detectors currently registered
