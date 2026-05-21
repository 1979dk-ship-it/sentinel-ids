import queue
import threading
from typing import List


class PacketQueue:
    """
    Fan-out queue: producer אחד (capture engine), צרכנים מרובים (detectors).
    כל subscriber מקבל queue נפרד ורואה כל packet באופן עצמאי.
    """

    def __init__(self, maxsize: int = 1000):
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()
        self._maxsize = maxsize

    def subscribe(self) -> queue.Queue:
        """רושם צרכן חדש. מחזיר Queue שיקבל את כל ה-Packets מעכשיו."""
        q = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._subscribers.append(q)
        return q

    def put(self, packet: dict) -> None:
        """מפיץ packet לכל ה-subscribers הרשומים."""
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(packet)
            except queue.Full:
                pass  # צרכן איטי מדי – packet נזנח במקום לחסום

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)
