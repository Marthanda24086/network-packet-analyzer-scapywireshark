"""
Unit tests for InterfaceManager and CaptureManager.
"""

import time
import pytest
from app.capture.interfaces import InterfaceManager, NetworkInterface
from app.capture.capture_manager import CaptureManager


def test_interface_discovery():
    ifaces = InterfaceManager.get_interfaces()
    assert len(ifaces) > 0

    demo_iface = next((i for i in ifaces if i.name == "DEMO_MODE"), None)
    assert demo_iface is not None
    assert demo_iface.status == "Ready (Synthetic)"
    assert demo_iface.ip == "192.168.1.100"


def test_capture_manager_initial_state():
    mgr = CaptureManager()
    assert mgr.is_capturing is False
    assert mgr.current_interface == "DEMO_MODE"
    assert mgr.get_elapsed_seconds() == 0.0

    ifaces = mgr.get_available_interfaces()
    assert len(ifaces) > 0


def test_capture_manager_invalid_bpf():
    mgr = CaptureManager()
    errors = []
    mgr.capture_error.connect(lambda err: errors.append(err))

    res = mgr.start_capture(interface="DEMO_MODE", bpf_filter="invalid!!bpf??syntax")
    assert res is False
    assert len(errors) == 1
    assert "Invalid BPF" in errors[0]


def test_capture_manager_demo_session():
    from PySide6.QtCore import QCoreApplication
    app = QCoreApplication.instance() or QCoreApplication([])

    mgr = CaptureManager()
    captured_records = []
    finished_counts = []

    mgr.packet_captured.connect(lambda rec, raw: captured_records.append(rec))
    mgr.capture_finished.connect(lambda count: finished_counts.append(count))

    # Run for 2 packets limit
    res = mgr.start_capture(interface="DEMO_MODE", count_limit=2)
    assert res is True
    assert mgr.is_capturing is True

    # Cannot start another session while capturing
    res_second = mgr.start_capture(interface="DEMO_MODE")
    assert res_second is False

    # Wait for completion (2 synthetic packets take ~0.4s) and process Qt events
    timeout = time.time() + 4.0
    while mgr.is_capturing and time.time() < timeout:
        app.processEvents()
        time.sleep(0.05)

    # Process remaining signals
    for _ in range(5):
        app.processEvents()
        time.sleep(0.05)

    assert len(captured_records) == 2
    assert len(finished_counts) == 1
    assert finished_counts[0] == 2
    assert mgr.is_capturing is False
    assert mgr.get_elapsed_seconds() > 0.0
