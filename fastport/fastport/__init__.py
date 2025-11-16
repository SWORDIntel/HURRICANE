"""
FastPort - High-Performance Async Port Scanner with CVE Integration

A modern, blazing-fast port scanner built with asyncio that rivals NMAP in performance
while providing enhanced features like automatic CVE detection, version fingerprinting,
and beautiful interactive TUI dashboards.

Key Features:
- Async/await architecture for maximum performance
- Automatic service version detection
- Integrated CVE vulnerability scanning with NVD database
- Live TUI dashboards with real-time feedback
- RCE vulnerability highlighting
- Multiple scanning modes (async, masscan-style)
- JSON export for automation
- Color-coded severity ratings

Modules:
- scanner: Core async port scanning engine
- scanner_tui: Interactive TUI for port scanning
- cve_scanner: Automatic CVE analysis for discovered services
- cve_scanner_tui: Interactive TUI for CVE scanning
- cve_lookup: CVE database integration with NVD API
"""

__version__ = "1.0.0"
__author__ = "HDAIS Project"

from .scanner import AsyncPortScanner, MasscanScanner
from .cve_lookup import CVELookup, CVERecord, ServiceVulnerability
from .cve_scanner import AutoCVEScanner, ServiceWithCVEs

__all__ = [
    'AsyncPortScanner',
    'MasscanScanner',
    'CVELookup',
    'CVERecord',
    'ServiceVulnerability',
    'AutoCVEScanner',
    'ServiceWithCVEs',
]
