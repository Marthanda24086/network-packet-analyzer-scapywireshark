"""
Capture Manager Module for NetScope.
Orchestrates interface discovery and packet capture sessions (live and demo mode).
"""

import time
import logging
from typing import List, Optional, Callable
from PySide6.QtCore import QObject, Signal

from app.capture.interfaces import InterfaceManager, NetworkInterface
from app.workers.capture_worker import CaptureWorker
from app.analysis.filters import FilterEngine

logger = logging.getLogger(__name__)


class CaptureManager(QObject):
    """
    High-level manager coordinating network interface selection and
    packet capture worker execution.
    """

    # Forwarded Qt Signals
    packet_captured = Signal(object, object)  # (PacketRecord, raw Scapy Packet)
    capture_started = Signal(str)             # Interface name
    capture_finished = Signal(int)            # Total packets captured
    capture_error = Signal(str)               # Error message

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[CaptureWorker] = None
        self._current_interface: str = "DEMO_MODE"
        self._is_capturing: bool = False
        self._start_time: float = 0.0

    @property
    def is_capturing(self) -> bool:
        """Returns True if a capture session is currently active."""
        return self._is_capturing and self._worker is not None and self._worker.isRunning()

    @property
    def current_interface(self) -> str:
        """Returns the name of the currently selected capture interface."""
        return self._current_interface

    @staticmethod
    def get_available_interfaces() -> List[NetworkInterface]:
        """Discovers and returns list of physical and synthetic interfaces."""
        return InterfaceManager.get_interfaces()

    def start_capture(
        self,
        interface: str = "DEMO_MODE",
        bpf_filter: str = "",
        count_limit: int = 0,
        duration_limit: int = 0
    ) -> bool:
        """
        Starts a background packet capture session on the specified interface.

        Args:
            interface: Interface name (or 'DEMO_MODE')
            bpf_filter: Optional BPF filter string
            count_limit: Maximum packets to capture (0 = unlimited)
            duration_limit: Maximum duration in seconds (0 = unlimited)

        Returns:
            True if worker was successfully launched, False otherwise.
        """
        if self.is_capturing:
            logger.warning("Capture session already in progress.")
            return False

        # Validate BPF filter syntax if provided
        if bpf_filter.strip() and not FilterEngine.validate_bpf_filter(bpf_filter):
            self.capture_error.emit(f"Invalid BPF capture filter syntax: '{bpf_filter}'")
            return False

        self._current_interface = interface
        self._start_time = time.time()
        self._is_capturing = True

        self._worker = CaptureWorker(
            interface=interface,
            bpf_filter=bpf_filter,
            count_limit=count_limit,
            duration_limit=duration_limit
        )

        self._worker.packet_captured.connect(self._on_worker_packet)
        self._worker.capture_finished.connect(self._on_worker_finished)
        self._worker.capture_error.connect(self._on_worker_error)

        logger.info(f"Starting capture on interface: {interface}")
        self.capture_started.emit(interface)
        self._worker.start()
        return True

    def stop_capture(self, wait_timeout_ms: int = 2000):
        """Stops the active capture session gracefully."""
        if not self.is_capturing or not self._worker:
            return

        logger.info("Stopping capture session...")
        self._worker.stop()
        self._worker.wait(wait_timeout_ms)
        self._is_capturing = False

    def get_elapsed_seconds(self) -> float:
        """Returns the elapsed duration of the current/last capture session."""
        if self._start_time <= 0.0:
            return 0.0
        return max(0.0, time.time() - self._start_time)

    def _on_worker_packet(self, record, raw_packet):
        self.packet_captured.emit(record, raw_packet)

    def _on_worker_finished(self, total_count: int):
        self._is_capturing = False
        logger.info(f"Capture session finished. Total packets: {total_count}")
        self.capture_finished.emit(total_count)

    def _on_worker_error(self, err_msg: str):
        self._is_capturing = False
        logger.error(f"Capture error reported: {err_msg}")
        self.capture_error.emit(err_msg)
