"""
Unit tests for StatisticsEngine.
"""

import pytest
from app.analysis.packet_models import PacketRecord
from app.analysis.statistics import StatisticsEngine


def test_statistics_summary():
    records = [
        PacketRecord(packet_num=1, timestamp=100.0, formatted_time="12:00:00.000", length=100, src_ip="192.168.1.10", dst_ip="8.8.8.8", protocol="DNS", transport_protocol="UDP", src_port=5000, dst_port=53),
        PacketRecord(packet_num=2, timestamp=102.0, formatted_time="12:00:02.000", length=200, src_ip="192.168.1.10", dst_ip="8.8.8.8", protocol="TCP", transport_protocol="TCP", src_port=5001, dst_port=443),
    ]

    stats = StatisticsEngine.calculate_summary(records)

    assert stats["total_packets"] == 2
    assert stats["total_bytes"] == 300
    assert stats["avg_packet_size"] == 150.0
    assert stats["min_packet_size"] == 100
    assert stats["max_packet_size"] == 200
    assert stats["unique_sources"] == 1
    assert stats["unique_destinations"] == 1
    assert stats["protocol_counts"]["DNS"] == 1
    assert stats["protocol_counts"]["TCP"] == 1


def test_empty_statistics():
    stats = StatisticsEngine.calculate_summary([])
    assert stats["total_packets"] == 0
    assert stats["total_bytes"] == 0
    assert stats["avg_packet_size"] == 0
