#!/usr/bin/env python3
"""
FastPort GUI - Professional graphical interface for port scanning
"""

import sys
import asyncio
import json
from datetime import datetime
from typing import List, Optional

# Try PyQt6 first, fall back to PyQt5
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
        QTableWidget, QTableWidgetItem, QGroupBox, QSpinBox,
        QCheckBox, QFileDialog, QMessageBox, QSplitter, QTabWidget
    )
    from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer
    from PyQt6.QtGui import QFont, QColor, QPalette, QIcon
    PYQT_VERSION = 6
except ImportError:
    try:
        from PyQt5.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
            QTableWidget, QTableWidgetItem, QGroupBox, QSpinBox,
            QCheckBox, QFileDialog, QMessageBox, QSplitter, QTabWidget
        )
        from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
        from PyQt5.QtGui import QFont, QColor, QPalette, QIcon
        PYQT_VERSION = 5
    except ImportError:
        print("Error: PyQt6 or PyQt5 required. Install with: pip install PyQt6")
        sys.exit(1)

try:
    import fastport_core
    RUST_CORE_AVAILABLE = True
except ImportError:
    RUST_CORE_AVAILABLE = False

from scanner import AsyncPortScanner, parse_ports


class ScanWorker(QThread):
    """Background thread for scanning"""
    progress = pyqtSignal(int, int)  # current, total
    result = pyqtSignal(dict)  # scan result
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target: str, ports: List[int], workers: int, timeout: int):
        super().__init__()
        self.target = target
        self.ports = ports
        self.workers = workers
        self.timeout = timeout
        self._is_running = True

    def run(self):
        """Run scan in background thread"""
        try:
            asyncio.run(self._async_scan())
        except Exception as e:
            self.error.emit(str(e))

    async def _async_scan(self):
        """Async scan implementation"""
        scanner = AsyncPortScanner(
            self.target,
            self.ports,
            max_workers=self.workers,
            timeout=self.timeout
        )

        results = await scanner.scan()

        for idx, result in enumerate(results, 1):
            if not self._is_running:
                break

            self.result.emit(result)
            self.progress.emit(idx, len(results))

        self.finished.emit()

    def stop(self):
        """Stop the scan"""
        self._is_running = False


class FastPortGUI(QMainWindow):
    """Main GUI window"""

    def __init__(self):
        super().__init__()
        self.scan_worker: Optional[ScanWorker] = None
        self.results = []
        self.start_time = None

        self.init_ui()
        self.load_system_info()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("FastPort - Professional Port Scanner")
        self.setGeometry(100, 100, 1200, 800)

        # Apply dark theme
        self.set_dark_theme()

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)

        # Add components
        main_layout.addWidget(self.create_header())
        main_layout.addWidget(self.create_input_panel())

        # Splitter for results and info
        splitter = QSplitter(Qt.Orientation.Horizontal if PYQT_VERSION == 6 else Qt.Horizontal)
        splitter.addWidget(self.create_results_panel())
        splitter.addWidget(self.create_info_panel())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter)

        # Status bar
        main_layout.addWidget(self.create_status_panel())

    def set_dark_theme(self):
        """Apply dark theme to the application"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window if PYQT_VERSION == 6 else QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.WindowText if PYQT_VERSION == 6 else QPalette.WindowText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Base if PYQT_VERSION == 6 else QPalette.Base, QColor(35, 35, 35))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase if PYQT_VERSION == 6 else QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase if PYQT_VERSION == 6 else QPalette.ToolTipBase, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ColorRole.ToolTipText if PYQT_VERSION == 6 else QPalette.ToolTipText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Text if PYQT_VERSION == 6 else QPalette.Text, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Button if PYQT_VERSION == 6 else QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ButtonText if PYQT_VERSION == 6 else QPalette.ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Link if PYQT_VERSION == 6 else QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.Highlight if PYQT_VERSION == 6 else QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText if PYQT_VERSION == 6 else QPalette.HighlightedText, QColor(0, 0, 0))

        self.setPalette(dark_palette)

    def create_header(self) -> QWidget:
        """Create header with title"""
        header = QGroupBox()
        layout = QVBoxLayout()

        title = QLabel("⚡ FastPort Professional")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold if PYQT_VERSION == 6 else QFont.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter if PYQT_VERSION == 6 else Qt.AlignCenter)

        subtitle = QLabel("High-Performance Async Port Scanner with AVX-512 Acceleration")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter if PYQT_VERSION == 6 else Qt.AlignCenter)
        subtitle.setStyleSheet("color: #2A82DA;")

        layout.addWidget(title)
        layout.addWidget(subtitle)
        header.setLayout(layout)
        header.setMaximumHeight(100)

        return header

    def create_input_panel(self) -> QWidget:
        """Create input panel for scan configuration"""
        panel = QGroupBox("Scan Configuration")
        layout = QHBoxLayout()

        # Target input
        target_layout = QVBoxLayout()
        target_layout.addWidget(QLabel("Target Host:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com or 192.168.1.1")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)

        # Ports input
        ports_layout = QVBoxLayout()
        ports_layout.addWidget(QLabel("Ports:"))
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("80,443,8000-9000")
        self.ports_input.setText("22,80,443,3306,6379,8080,8443")
        ports_layout.addWidget(self.ports_input)
        layout.addLayout(ports_layout)

        # Workers input
        workers_layout = QVBoxLayout()
        workers_layout.addWidget(QLabel("Workers:"))
        self.workers_input = QSpinBox()
        self.workers_input.setRange(1, 1000)
        self.workers_input.setValue(200)
        workers_layout.addWidget(self.workers_input)
        layout.addLayout(workers_layout)

        # Timeout input
        timeout_layout = QVBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (s):"))
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 30)
        self.timeout_input.setValue(2)
        timeout_layout.addWidget(self.timeout_input)
        layout.addLayout(timeout_layout)

        # Scan button
        button_layout = QVBoxLayout()
        button_layout.addWidget(QLabel(""))  # Spacer
        self.scan_button = QPushButton("🚀 Start Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #2A82DA;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1E5FA3;
            }
            QPushButton:disabled {
                background-color: #555555;
            }
        """)
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        layout.addLayout(button_layout)

        # Stop button
        stop_layout = QVBoxLayout()
        stop_layout.addWidget(QLabel(""))  # Spacer
        self.stop_button = QPushButton("⏹ Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #DA2A2A;
                color: white;
                font-weight: bold;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #A31E1E;
            }
            QPushButton:disabled {
                background-color: #555555;
            }
        """)
        self.stop_button.clicked.connect(self.stop_scan)
        stop_layout.addWidget(self.stop_button)
        layout.addLayout(stop_layout)

        panel.setLayout(layout)
        return panel

    def create_results_panel(self) -> QWidget:
        """Create results table panel"""
        panel = QGroupBox("Scan Results")
        layout = QVBoxLayout()

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Host", "Port", "State", "Service", "Version", "Response Time"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setAlternatingRowColors(True)

        layout.addWidget(self.results_table)

        # Export button
        export_button = QPushButton("💾 Export Results")
        export_button.clicked.connect(self.export_results)
        layout.addWidget(export_button)

        panel.setLayout(layout)
        return panel

    def create_info_panel(self) -> QWidget:
        """Create info panel with tabs"""
        tabs = QTabWidget()

        # Statistics tab
        stats_widget = QWidget()
        stats_layout = QVBoxLayout()

        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setStyleSheet("font-family: 'Courier New'; background-color: #252525;")

        stats_layout.addWidget(self.stats_text)
        stats_widget.setLayout(stats_layout)

        tabs.addTab(stats_widget, "📊 Statistics")

        # System info tab
        sys_widget = QWidget()
        sys_layout = QVBoxLayout()

        self.system_text = QTextEdit()
        self.system_text.setReadOnly(True)
        self.system_text.setStyleSheet("font-family: 'Courier New'; background-color: #252525;")

        sys_layout.addWidget(self.system_text)
        sys_widget.setLayout(sys_layout)

        tabs.addTab(sys_widget, "🖥 System")

        return tabs

    def create_status_panel(self) -> QWidget:
        """Create status bar panel"""
        panel = QWidget()
        layout = QVBoxLayout()

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("padding: 5px;")
        layout.addWidget(self.status_label)

        panel.setLayout(layout)
        return panel

    def load_system_info(self):
        """Load and display system information"""
        info_lines = ["FastPort System Information", "=" * 50, ""]

        if RUST_CORE_AVAILABLE:
            try:
                scanner = fastport_core.FastPortScanner(workers=None)
                info_lines.append(f"🚀 Rust Core: ENABLED")
                info_lines.append(f"⚡ SIMD Variant: {scanner.get_simd_variant()}")
                info_lines.append(f"🧵 Workers: {scanner.get_worker_count()}")
                info_lines.append("")
                info_lines.append(fastport_core.get_cpu_features())
                info_lines.append("")
                info_lines.append("Performance Benchmark:")
                info_lines.append(fastport_core.benchmark_simd())
            except Exception as e:
                info_lines.append(f"⚠️  Rust Core Error: {e}")
        else:
            info_lines.append("⚠️  Rust Core: NOT AVAILABLE")
            info_lines.append("Running in Python-only mode")
            info_lines.append("")
            info_lines.append("For maximum performance:")
            info_lines.append("cd fastport-core && maturin develop --release")

        self.system_text.setText("\n".join(info_lines))

    def update_statistics(self):
        """Update statistics display"""
        if not self.start_time:
            return

        elapsed = (datetime.now() - self.start_time).total_seconds()
        ports_open = sum(1 for r in self.results if r.get('is_open', False))
        ports_closed = len(self.results) - ports_open

        pps = len(self.results) / elapsed if elapsed > 0 else 0

        stats_lines = [
            "Scan Statistics",
            "=" * 50,
            "",
            f"⏱  Elapsed Time: {elapsed:.1f}s",
            f"🎯 Target: {self.target_input.text()}",
            f"🔍 Ports Scanned: {len(self.results):,}",
            f"✅ Ports Open: {ports_open}",
            f"❌ Ports Closed: {ports_closed}",
            f"⚡ Speed: {pps:,.0f} ports/sec",
        ]

        self.stats_text.setText("\n".join(stats_lines))

    def start_scan(self):
        """Start the port scan"""
        # Validate inputs
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target host")
            return

        ports_str = self.ports_input.text().strip()
        if not ports_str:
            QMessageBox.warning(self, "Error", "Please enter ports to scan")
            return

        try:
            ports = parse_ports(ports_str)
        except ValueError as e:
            QMessageBox.warning(self, "Error", f"Invalid port specification: {e}")
            return

        # Clear previous results
        self.results = []
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)

        # Disable inputs during scan
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.ports_input.setEnabled(False)

        # Start scan
        self.start_time = datetime.now()
        self.status_label.setText(f"🔍 Scanning {target}...")

        self.scan_worker = ScanWorker(
            target,
            ports,
            self.workers_input.value(),
            self.timeout_input.value()
        )
        self.scan_worker.progress.connect(self.on_progress)
        self.scan_worker.result.connect(self.on_result)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.error.connect(self.on_error)
        self.scan_worker.start()

    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_worker:
            self.scan_worker.stop()
            self.status_label.setText("⏹ Stopping scan...")

    def on_progress(self, current: int, total: int):
        """Handle progress update"""
        progress = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(progress)
        self.update_statistics()

    def on_result(self, result: dict):
        """Handle scan result"""
        self.results.append(result)

        # Add to table if port is open
        if result.get('is_open', False):
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)

            self.results_table.setItem(row, 0, QTableWidgetItem(result['hostname']))
            self.results_table.setItem(row, 1, QTableWidgetItem(str(result['port'])))
            self.results_table.setItem(row, 2, QTableWidgetItem("OPEN"))
            self.results_table.setItem(row, 3, QTableWidgetItem(result.get('service', '-')))
            self.results_table.setItem(row, 4, QTableWidgetItem(result.get('version', '-')))
            self.results_table.setItem(row, 5, QTableWidgetItem(f"{result.get('response_time_ms', 0)}ms"))

            # Color code the state
            state_item = self.results_table.item(row, 2)
            state_item.setForeground(QColor(0, 255, 0))

    def on_scan_finished(self):
        """Handle scan completion"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.ports_input.setEnabled(True)

        ports_open = sum(1 for r in self.results if r.get('is_open', False))
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0

        self.status_label.setText(
            f"✅ Scan complete! Found {ports_open} open ports in {elapsed:.1f}s"
        )
        self.progress_bar.setValue(100)

        QMessageBox.information(
            self,
            "Scan Complete",
            f"Scan finished successfully!\n\n"
            f"Ports scanned: {len(self.results):,}\n"
            f"Ports open: {ports_open}\n"
            f"Time: {elapsed:.1f}s"
        )

    def on_error(self, error_msg: str):
        """Handle scan error"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.ports_input.setEnabled(True)

        self.status_label.setText(f"❌ Error: {error_msg}")

        QMessageBox.critical(self, "Scan Error", f"An error occurred:\n\n{error_msg}")

    def export_results(self):
        """Export results to JSON file"""
        if not self.results:
            QMessageBox.warning(self, "No Results", "No scan results to export")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "fastport_results.json",
            "JSON Files (*.json)"
        )

        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=2, default=str)
                QMessageBox.information(self, "Success", f"Results exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export:\n{e}")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for better cross-platform look

    window = FastPortGUI()
    window.show()

    sys.exit(app.exec() if PYQT_VERSION == 6 else app.exec_())


if __name__ == "__main__":
    main()
