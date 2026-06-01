import threading                                        # Thread for non-blocking capture loop
from scapy.sendrecv import sniff                        # captures packets live from a network interface
from scapy.utils import rdpcap                          # reads a .pcap file and returns a list of packets

from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue


class PacketCapture:
    """
    Drives packet ingestion from a live interface or a PCAP file.
    Runs Scapy's sniff() on a dedicated daemon thread so the rest of
    the application (UI, detectors) is never blocked.
    """

    def __init__(self, interface: str, parser: PacketParser, queue: PacketQueue):
        self._interface = interface                     # NIC name e.g. "Ethernet" or "\\Device\\NPF_{GUID}"
        self._parser = parser                           # converts raw Scapy packets to flat dicts
        self._queue = queue                             # fan-out queue – distributes packets to all detectors
        self._thread: threading.Thread | None = None   # reference to capture thread; None before start()
        self._stop_event = threading.Event()            # signals the capture loop to exit cleanly

    def start(self) -> None:
        """Start live capture on the configured interface."""
        if self._thread and self._thread.is_alive():   # prevent double-start
            return
        self._stop_event.clear()                        # reset flag in case start() is called after stop()
        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,                                # daemon thread exits automatically when main thread ends
            name="packet-capture"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the capture loop to stop and wait for the thread to finish."""
        self._stop_event.set()                          # tell stop_filter to return True on the next packet
        if self._thread:
            self._thread.join(timeout=3)                # wait up to 3s – avoids hanging on quiet interfaces

    @property
    def is_running(self) -> bool:                       # read-only – used by health checks and the TUI
        return self._thread is not None and self._thread.is_alive()

    def replay_pcap(self, path: str) -> None:
        """Feed a .pcap file through the full pipeline synchronously (dev / testing mode)."""
        packets = rdpcap(path)                          # load all packets from file into memory
        for pkt in packets:
            self._handle_packet(pkt)                    # reuse the same handler as live capture

    # ------------------------------------------------------------------
    # private
    # ------------------------------------------------------------------

    def _capture_loop(self) -> None:                    # runs on the dedicated capture thread
        sniff(
            iface=self._interface,
            prn=self._handle_packet,                    # callback invoked once per captured packet
            store=False,                                # do not accumulate packets in RAM
            stop_filter=lambda _: self._stop_event.is_set()  # stop after next packet once stop() is called
        )

    def _handle_packet(self, raw_packet) -> None:       # called by both sniff() and replay_pcap()
        parsed = self._parser.parse(raw_packet)         # convert raw Scapy packet → flat dict
        if parsed:
            self._queue.put(parsed)                     # distribute to all registered detectors
