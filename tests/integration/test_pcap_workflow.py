"""
Integration test for full PCAP loading, parsing, filtering, statistics, and report exporter workflow.
"""

import os
import tempfile
import pytest
from app.pcap.pcap_manager import PcapManager
from app.pcap.exporters import Exporter
from app.analysis.filters import FilterEngine
from app.analysis.statistics import StatisticsEngine


def test_pcap_end_to_end_workflow():
    sample_pcap = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sample_data", "sample_traffic.pcap")
    assert os.path.exists(sample_pcap), "sample_traffic.pcap must exist for integration test"

    # 1. Load PCAP
    records, raw_pkts, err = PcapManager.load_pcap(sample_pcap)
    assert err is None
    assert len(records) > 0
    assert len(raw_pkts) == len(records)

    # 2. Filter Packets
    dns_records = FilterEngine.filter_packets(records, protocol="DNS")
    assert len(dns_records) > 0

    # 3. Calculate Statistics
    stats = StatisticsEngine.calculate_summary(records)
    assert stats["total_packets"] == len(records)

    # 4. Test Exports
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "test.csv")
        json_path = os.path.join(tmpdir, "test.json")
        md_path = os.path.join(tmpdir, "test.md")
        html_path = os.path.join(tmpdir, "test.html")

        ok, err_csv = Exporter.export_csv(csv_path, records)
        assert ok is True and os.path.exists(csv_path)

        ok, err_json = Exporter.export_json(json_path, records)
        assert ok is True and os.path.exists(json_path)

        ok, err_md = Exporter.export_markdown_report(md_path, records)
        assert ok is True and os.path.exists(md_path)

        ok, err_html = Exporter.export_html_report(html_path, records)
        assert ok is True and os.path.exists(html_path)


def test_pcap_invalid_path():
    records, raw_pkts, err = PcapManager.load_pcap("non_existent_file.pcap")
    assert records == []
    assert raw_pkts == []
    assert err is not None
    assert "not found" in err.lower()


def test_pcap_empty_or_corrupt_file():
    import gc
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        # 1. Empty file test
        empty_file = os.path.join(tmpdir, "empty.pcap")
        with open(empty_file, "wb") as f:
            f.write(b"")

        records, raw_pkts, err = PcapManager.load_pcap(empty_file)
        assert records == []
        assert raw_pkts == []
        assert err is not None
        assert "empty" in err.lower()

        # 2. Corrupt file content
        corrupt_file = os.path.join(tmpdir, "corrupt.pcap")
        with open(corrupt_file, "wb") as f:
            f.write(b"NOT_A_VALID_PCAP_HEADER_DATA_1234567890")

        records, raw_pkts, err = PcapManager.load_pcap(corrupt_file)
        assert err is not None
        assert "corrupted" in err.lower() or "unsupported" in err.lower()

        # Cleanly trigger gc for any open reader handles
        gc.collect()


def test_pcap_save_empty():
    ok, err = PcapManager.save_pcap("should_fail.pcap", [])
    assert ok is False
    assert "no packets" in err.lower()
