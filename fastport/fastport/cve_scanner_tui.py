#!/usr/bin/env python3
"""
Interactive TUI for Automatic CVE Scanner
Beautiful terminal interface with live progress, color-coded results, and real-time feedback
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich import box
from rich.style import Style

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.cve_lookup import CVELookup, ServiceVulnerability
from scanners.auto_cve_scanner import AutoCVEScanner, HostVulnerabilityReport


class CVEScannerTUI:
    """Interactive TUI for CVE scanning with live feedback"""

    def __init__(self):
        self.console = Console()
        self.scanner = None
        self.port_scan_file = None
        self.api_key = None
        self.rce_only = False
        self.output_file = None

        # Statistics for live display
        self.stats = {
            'hosts_scanned': 0,
            'services_analyzed': 0,
            'cves_found': 0,
            'rce_found': 0,
            'critical_found': 0,
            'high_found': 0,
            'current_host': '',
            'current_service': ''
        }

    def show_banner(self):
        """Display welcome banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║      🛡️  HDAIS Automatic CVE Scanner with RCE Detection     ║
║                                                               ║
║      Real-time Vulnerability Analysis & Reporting            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
        self.console.print(banner, style="bold cyan")
        self.console.print("\nAutomatically scans for vulnerabilities in detected services")
        self.console.print("with special focus on RCE (Remote Code Execution) CVEs\n")

    def configure_scanner(self):
        """Interactive configuration"""
        self.console.print("\n[bold cyan]═══ Configuration ═══[/bold cyan]\n")

        # Port scan file
        while True:
            port_scan_file = Prompt.ask(
                "[cyan]Port scan results file[/cyan]",
                default="port_scan_results.json"
            )

            if Path(port_scan_file).exists():
                self.port_scan_file = port_scan_file
                break
            else:
                self.console.print(f"[red]✗[/red] File not found: {port_scan_file}")
                if not Confirm.ask("Try another file?", default=True):
                    sys.exit(0)

        # API key
        self.console.print("\n[yellow]NVD API Key (optional but recommended)[/yellow]")
        self.console.print("  Without key: ~10 requests/minute")
        self.console.print("  With key: ~100 requests/minute")
        self.console.print("  Get free key: https://nvd.nist.gov/developers/request-an-api-key\n")

        api_key = Prompt.ask(
            "[cyan]API Key[/cyan] (press Enter to skip)",
            default="",
            show_default=False
        )
        self.api_key = api_key if api_key else None

        # RCE-only mode
        self.rce_only = Confirm.ask(
            "\n[cyan]RCE-only mode?[/cyan] (show only Remote Code Execution vulnerabilities)",
            default=False
        )

        # Output file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_output = f"cve_scan_report_{timestamp}.json"
        self.output_file = Prompt.ask(
            "\n[cyan]Output file[/cyan]",
            default=default_output
        )

        # Confirmation
        self.console.print("\n[bold cyan]═══ Configuration Summary ═══[/bold cyan]")

        config_table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
        config_table.add_column(style="cyan")
        config_table.add_column()

        config_table.add_row("Input File:", self.port_scan_file)
        config_table.add_row("API Key:", "✓ Provided" if self.api_key else "✗ Not provided (slower)")
        config_table.add_row("RCE-Only Mode:", "✓ Enabled" if self.rce_only else "✗ Disabled")
        config_table.add_row("Output File:", self.output_file)

        self.console.print(config_table)
        self.console.print()

        if not Confirm.ask("[cyan]Start scanning?[/cyan]", default=True):
            sys.exit(0)

    def create_stats_panel(self) -> Panel:
        """Create live statistics panel"""
        stats_table = Table.grid(padding=(0, 2))
        stats_table.add_column(style="cyan", justify="right")
        stats_table.add_column()

        stats_table.add_row("Hosts Scanned:", f"[bold white]{self.stats['hosts_scanned']}[/bold white]")
        stats_table.add_row("Services Analyzed:", f"[bold white]{self.stats['services_analyzed']}[/bold white]")
        stats_table.add_row("CVEs Found:", f"[bold yellow]{self.stats['cves_found']}[/bold yellow]")

        # RCE with red if found
        rce_style = "bold red" if self.stats['rce_found'] > 0 else "white"
        stats_table.add_row("RCE CVEs:", f"[{rce_style}]{self.stats['rce_found']}[/{rce_style}]")

        # Critical with red if found
        crit_style = "bold red" if self.stats['critical_found'] > 0 else "white"
        stats_table.add_row("Critical:", f"[{crit_style}]{self.stats['critical_found']}[/{crit_style}]")

        # High with orange if found
        high_style = "bold orange3" if self.stats['high_found'] > 0 else "white"
        stats_table.add_row("High Severity:", f"[{high_style}]{self.stats['high_found']}[/{high_style}]")

        return Panel(stats_table, title="[bold cyan]Scan Statistics[/bold cyan]", border_style="cyan")

    def create_current_activity_panel(self) -> Panel:
        """Create current activity panel"""
        activity_text = Text()

        if self.stats['current_host']:
            activity_text.append("🎯 Host: ", style="cyan")
            activity_text.append(f"{self.stats['current_host']}\n", style="bold white")

        if self.stats['current_service']:
            activity_text.append("🔍 Service: ", style="cyan")
            activity_text.append(self.stats['current_service'], style="bold yellow")

        if not self.stats['current_host'] and not self.stats['current_service']:
            activity_text.append("Initializing...", style="dim")

        return Panel(activity_text, title="[bold cyan]Current Activity[/bold cyan]", border_style="cyan")

    def create_results_table(self, results: List[Dict]) -> Table:
        """Create results table with color-coded severity"""
        table = Table(title="Recent Findings", box=box.ROUNDED, show_lines=True)

        table.add_column("Host", style="cyan", no_wrap=True)
        table.add_column("Service", style="yellow")
        table.add_column("CVEs", justify="right")
        table.add_column("RCE", justify="center")
        table.add_column("Critical", justify="center")
        table.add_column("High", justify="center")

        # Show last 10 results
        for result in results[-10:]:
            # Color-code RCE
            rce_text = str(result['rce'])
            if result['rce'] > 0:
                rce_text = f"[bold red]{rce_text}[/bold red]"

            # Color-code Critical
            crit_text = str(result['critical'])
            if result['critical'] > 0:
                crit_text = f"[bold red]{crit_text}[/bold red]"

            # Color-code High
            high_text = str(result['high'])
            if result['high'] > 0:
                high_text = f"[bold orange3]{high_text}[/bold orange3]"

            table.add_row(
                result['host'][:30],
                result['service'][:25],
                str(result['total_cves']),
                rce_text,
                crit_text,
                high_text
            )

        return table

    def create_dashboard(self, results: List[Dict]) -> Layout:
        """Create live dashboard layout"""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )

        layout["body"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=2)
        )

        # Header
        header_text = Text("🛡️ HDAIS CVE Scanner", style="bold cyan", justify="center")
        layout["header"].update(Panel(header_text, border_style="cyan"))

        # Left: Stats and activity
        layout["left"].split_column(
            Layout(self.create_stats_panel(), size=10),
            Layout(self.create_current_activity_panel())
        )

        # Right: Results table
        layout["right"].update(self.create_results_table(results))

        # Footer
        mode_text = "[RCE-ONLY MODE]" if self.rce_only else "[FULL SCAN]"
        footer_text = Text(f"Scanning... {mode_text}", style="dim", justify="center")
        layout["footer"].update(Panel(footer_text, border_style="dim"))

        return layout

    def scan_with_live_ui(self):
        """Run scan with live updating UI"""
        self.console.print("\n[bold green]▶ Starting scan...[/bold green]\n")

        # Initialize scanner
        self.scanner = AutoCVEScanner(
            self.port_scan_file,
            api_key=self.api_key,
            rce_only=self.rce_only
        )

        # Load hosts
        hosts = self.scanner.load_port_scan_data()
        if not hosts:
            self.console.print("[red]✗ No hosts found in port scan output[/red]")
            return

        total_hosts = len(hosts)
        results = []

        # Live dashboard
        with Live(self.create_dashboard(results), refresh_per_second=4, console=self.console) as live:
            for i, host_data in enumerate(hosts, 1):
                hostname = host_data.get('hostname', 'unknown')
                self.stats['current_host'] = hostname
                self.stats['hosts_scanned'] = i

                detected_services = host_data.get('detected_services', [])

                for service in detected_services:
                    service_name = service.get('service_name', 'Unknown')
                    version = service.get('version')
                    port = service.get('port')

                    if not version:
                        continue

                    self.stats['current_service'] = f"{service_name} {version} (port {port})"
                    self.stats['services_analyzed'] += 1

                    # Update display
                    live.update(self.create_dashboard(results))

                    # Perform CVE lookup
                    vuln = self.scanner.cve_lookup.lookup_service_with_version(service_name, version)

                    # Filter RCE if needed
                    if self.rce_only and vuln.rce_count > 0:
                        rce_cves = self.scanner.cve_lookup.get_rce_only(vuln)
                        vuln.cves = rce_cves
                        vuln.total_cves = len(rce_cves)
                        vuln.critical_count = sum(1 for c in rce_cves if c.severity == 'CRITICAL')
                        vuln.high_count = sum(1 for c in rce_cves if c.severity == 'HIGH')

                    # Update statistics
                    if vuln.total_cves > 0:
                        self.stats['cves_found'] += vuln.total_cves
                        self.stats['rce_found'] += vuln.rce_count
                        self.stats['critical_found'] += vuln.critical_count
                        self.stats['high_found'] += vuln.high_count

                        # Add to results
                        results.append({
                            'host': hostname,
                            'service': f"{service_name} {version}",
                            'total_cves': vuln.total_cves,
                            'rce': vuln.rce_count,
                            'critical': vuln.critical_count,
                            'high': vuln.high_count
                        })

                    # Update display
                    live.update(self.create_dashboard(results))

                # Clear current service after host is done
                self.stats['current_service'] = ''
                live.update(self.create_dashboard(results))

        # Scan complete
        self.stats['current_host'] = ''
        self.stats['current_service'] = ''

        # Now actually run the full scanner to generate reports
        self.console.print("\n[bold cyan]Generating detailed reports...[/bold cyan]\n")

        with self.console.status("[cyan]Generating reports...", spinner="dots"):
            self.scanner.scan_and_analyze()
            self.scanner.generate_report(self.output_file)

    def show_final_summary(self):
        """Show final summary with color-coded results"""
        self.console.print("\n" + "="*70)
        self.console.print("[bold green]✓ Scan Complete![/bold green]", justify="center")
        self.console.print("="*70 + "\n")

        # Summary table
        summary_table = Table(title="Final Results", box=box.DOUBLE, show_header=True)
        summary_table.add_column("Metric", style="cyan", justify="left")
        summary_table.add_column("Count", justify="right")
        summary_table.add_column("Status", justify="center")

        summary_table.add_row(
            "Hosts Scanned",
            str(self.stats['hosts_scanned']),
            "✓"
        )

        summary_table.add_row(
            "Services Analyzed",
            str(self.stats['services_analyzed']),
            "✓"
        )

        summary_table.add_row(
            "Total CVEs Found",
            str(self.stats['cves_found']),
            "⚠️" if self.stats['cves_found'] > 0 else "✓"
        )

        # RCE row - red if found
        rce_count = str(self.stats['rce_found'])
        rce_status = "🚨" if self.stats['rce_found'] > 0 else "✓"
        if self.stats['rce_found'] > 0:
            rce_count = f"[bold red]{rce_count}[/bold red]"
            rce_status = f"[bold red]{rce_status}[/bold red]"

        summary_table.add_row(
            "RCE Vulnerabilities",
            rce_count,
            rce_status
        )

        # Critical row - red if found
        crit_count = str(self.stats['critical_found'])
        crit_status = "🔴" if self.stats['critical_found'] > 0 else "✓"
        if self.stats['critical_found'] > 0:
            crit_count = f"[bold red]{crit_count}[/bold red]"

        summary_table.add_row(
            "Critical Severity",
            crit_count,
            crit_status
        )

        # High row - orange if found
        high_count = str(self.stats['high_found'])
        high_status = "🟠" if self.stats['high_found'] > 0 else "✓"
        if self.stats['high_found'] > 0:
            high_count = f"[bold orange3]{high_count}[/bold orange3]"

        summary_table.add_row(
            "High Severity",
            high_count,
            high_status
        )

        self.console.print(summary_table)

        # Output files
        self.console.print("\n[bold cyan]Generated Reports:[/bold cyan]\n")

        reports = [
            ("JSON Report", self.output_file, "📄"),
            ("Summary Report", self.output_file.replace('.json', '_summary.md'), "📝"),
        ]

        if self.stats['rce_found'] > 0:
            reports.append((
                "RCE Critical Report",
                self.output_file.replace('.json', '_RCE_CRITICAL.md'),
                "🚨"
            ))

        for name, path, icon in reports:
            if Path(path).exists():
                self.console.print(f"  {icon} [cyan]{name}:[/cyan] {path}")

        # Warnings if RCE or Critical found
        if self.stats['rce_found'] > 0:
            self.console.print("\n[bold red]⚠️  WARNING: RCE VULNERABILITIES DETECTED![/bold red]")
            self.console.print("[red]   Review the RCE Critical Report immediately![/red]")

        if self.stats['critical_found'] > 0:
            self.console.print("\n[bold red]⚠️  CRITICAL VULNERABILITIES FOUND![/bold red]")
            self.console.print("[red]   Immediate patching recommended![/red]")

        self.console.print("\n" + "="*70 + "\n")

    def run(self):
        """Main TUI workflow"""
        try:
            self.show_banner()
            self.configure_scanner()
            self.scan_with_live_ui()
            self.show_final_summary()

        except KeyboardInterrupt:
            self.console.print("\n\n[yellow]Scan interrupted by user[/yellow]")
            sys.exit(0)
        except Exception as e:
            self.console.print(f"\n[red]Error: {e}[/red]")
            if Confirm.ask("\nShow traceback?", default=False):
                raise
            sys.exit(1)


def main():
    """Entry point for TUI"""
    tui = CVEScannerTUI()
    tui.run()


if __name__ == "__main__":
    main()
