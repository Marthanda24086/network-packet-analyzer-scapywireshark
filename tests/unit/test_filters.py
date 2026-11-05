"""
Unit tests for FilterEngine.
"""

import pytest
from app.analysis.packet_models import PacketRecord
from app.analysis.filters import FilterEngine


@pytest.fixture
def sample_records():
    return [
        PacketRecord(packet_num=1, timestamp=100.0, formatted_time="12:00:00.000", length=64, src_ip="192.168.1.10", dst_ip="8.8.8.8", protocol="DNS", transport_protocol="UDP", src_port=54321, dst_port=53, info="DNS Query example.com"),
        PacketRecord(packet_num=2, timestamp=101.0, formatted_time="12:00:01.000", length=128, src_ip="192.168.1.10", dst_ip="93.184.216.34", protocol="TCP", transport_protocol="TCP", src_port=50123, dst_port=80, info="HTTP GET /index.html"),
        PacketRecord(packet_num=3, timestamp=102.0, formatted_time="12:00:02.000", length=42, src_ip="192.168.1.10", dst_ip="192.168.1.1", protocol="ARP", transport_protocol="N/A", info="ARP Request Who has 192.168.1.1"),
    ]


def test_protocol_filter(sample_records):
    dns_res = FilterEngine.filter_packets(sample_records, protocol="DNS")
    assert len(dns_res) == 1
    assert dns_res[0].packet_num == 1

    tcp_res = FilterEngine.filter_packets(sample_records, protocol="TCP")
    assert len(tcp_res) == 1
    assert tcp_res[0].packet_num == 2


def test_ip_filter(sample_records):
    res = FilterEngine.filter_packets(sample_records, ip_addr="8.8.8.8")
    assert len(res) == 1
    assert res[0].packet_num == 1


def test_port_filter(sample_records):
    res = FilterEngine.filter_packets(sample_records, port=80)
    assert len(res) == 1
    assert res[0].packet_num == 2


def test_text_search_filter(sample_records):
    res = FilterEngine.filter_packets(sample_records, search_text="example.com")
    assert len(res) == 1
    assert res[0].packet_num == 1


def test_bpf_validation():
    assert FilterEngine.validate_bpf_filter("tcp port 80") is True
    assert FilterEngine.validate_bpf_filter("ip and src host 192.168.1.1") is True
    assert FilterEngine.validate_bpf_filter("invalid$$bpf!!syntax") is False
