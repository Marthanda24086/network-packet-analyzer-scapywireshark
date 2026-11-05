"""
Visualization Tab Widget for NetScope.
Embeds interactive Matplotlib charts rendering real-time protocol breakdowns,
packet rates over time, top talkers, and transport protocol splits.
"""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PySide6.QtCore import Qt
from typing import List

import matplotlib
matplotlib.use('QtAgg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from app.analysis.packet_models import PacketRecord
from app.analysis.statistics import StatisticsEngine


class VisualizationTabWidget(QWidget):
    """Visual Analytics Tab housing 4 quadrant Matplotlib charts."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        # Matplotlib Figure and Canvas
        self.figure = Figure(figsize=(10, 8), facecolor='#1e293b')
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        # Draw empty state initially
        self.plot_empty_state()

    def plot_empty_state(self):
        """Renders placeholder when no packet data is loaded."""
        self.figure.clear()
        ax = self.figure.add_subplot(111, facecolor='#1e293b')
        ax.text(
            0.5, 0.5,
            "No Traffic Data Available\n\nStart a Live Capture or Load a PCAP to View Visual Analytics",
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes,
            color='#94a3b8',
            fontsize=14,
            fontweight='bold'
        )
        ax.axis('off')
        self.canvas.draw()

    def update_charts(self, records: List[PacketRecord]):
        """Re-renders all 4 charts based on provided packet records."""
        if not records:
            self.plot_empty_state()
            return

        stats = StatisticsEngine.calculate_summary(records)

        self.figure.clear()

        # Custom Dark Palette
        colors = ['#38bdf8', '#818cf8', '#34d399', '#f43f5e', '#fbbf24', '#a78bfa', '#fb923c']

        # Chart 1: Protocol Distribution (Pie)
        ax1 = self.figure.add_subplot(221, facecolor='#1e293b')
        proto_data = stats["protocol_counts"]
        if proto_data:
            labels = list(proto_data.keys())
            values = list(proto_data.values())
            ax1.pie(
                values, labels=labels, autopct='%1.1f%%',
                colors=colors[:len(values)], textprops={'color': '#f8fafc', 'fontsize': 9}
            )
        ax1.set_title("Protocol Breakdown", color='#38bdf8', fontsize=11, fontweight='bold')

        # Chart 2: Timeline (Packets over Time)
        ax2 = self.figure.add_subplot(222, facecolor='#1e293b')
        tx, ty = stats["timeline_series"]
        if tx and ty:
            ax2.plot(tx, ty, color='#38bdf8', linewidth=2, marker='o', markersize=3)
            ax2.fill_between(tx, ty, color='#38bdf8', alpha=0.2)
        ax2.set_title("Packets per Second Timeline", color='#38bdf8', fontsize=11, fontweight='bold')
        ax2.set_xlabel("Time Offset (sec)", color='#94a3b8', fontsize=8)
        ax2.set_ylabel("Packets", color='#94a3b8', fontsize=8)
        ax2.tick_params(colors='#94a3b8', labelsize=8)
        for spine in ax2.spines.values():
            spine.set_color('#334155')

        # Chart 3: Top Sources (Bar)
        ax3 = self.figure.add_subplot(223, facecolor='#1e293b')
        top_src = stats["top_sources"]
        if top_src:
            src_ips = [item[0] for item in top_src]
            counts = [item[1] for item in top_src]
            ax3.barh(src_ips, counts, color='#34d399')
            ax3.invert_yaxis()  # top talker at top
        ax3.set_title("Top Source IP Endpoints", color='#38bdf8', fontsize=11, fontweight='bold')
        ax3.tick_params(colors='#94a3b8', labelsize=8)
        for spine in ax3.spines.values():
            spine.set_color('#334155')

        # Chart 4: Transport Layer Breakdown (Bar)
        ax4 = self.figure.add_subplot(224, facecolor='#1e293b')
        t_split = stats["transport_split"]
        categories = list(t_split.keys())
        t_counts = list(t_split.values())
        ax4.bar(categories, t_counts, color='#fbbf24')
        ax4.set_title("Transport Protocol Split", color='#38bdf8', fontsize=11, fontweight='bold')
        ax4.tick_params(colors='#94a3b8', labelsize=8)
        for spine in ax4.spines.values():
            spine.set_color('#334155')

        self.figure.tight_layout(pad=2.0)
        self.canvas.draw()
