#!/usr/bin/env python3
"""
FastPort Professional TUI - Enhanced interactive port scanner
with real-time performance metrics, SIMD status, and polished UI
"""

import asyncio
import argparse
import json
import sys
from typing import List, Dict, Optional
from datetime import datetime
from dataclasses import dataclass, field

try:
    from rich.console import Console
    from rich.live import Live
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn
    )
    from rich.text import Text
    from rich.align import Align
    from rich.box import DOUBLE, ROUNDED, HEAVY
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Error: This module requires 'rich'. Install with: pip install rich")
    sys.exit(1)

# Try to import Rust core
try:
    import fastport_core
    RUST_CORE_AVAILABLE = True
except ImportError:
    RUST_CORE_AVAILABLE = False
    print("Warning: fastport_core not available. Using Python-only mode.")
    print("For maximum performance, build the Rust core: cd fastport-core && maturin develop")

from scanner import AsyncPortScanner, parse_ports


@dataclass
class ScannerStats:
    """Real-time scanner statistics"""
    start_time: datetime = field(default_factory=datetime.now)
    targets_scanned: int = 0
    ports_scanned: int = 0
    ports_open: int = 0
    ports_closed: int = 0
    packets_per_second: float = 0.0
    current_target: str = ""
    simd_variant: str = "Python"
    worker_count: int = 0
    cpu_features: str = ""


class FastPortProTUI:
    """Enhanced TUI with professional polish"""

    def __init__(self, console: Console):
        self.console = console
        self.stats = ScannerStats()
        self.results: List[Dict] = []
        self.rust_scanner = None

        # Initialize Rust scanner if available
        if RUST_CORE_AVAILABLE:
            try:
                self.rust_scanner = fastport_core.FastPortScanner(workers=None)
                self.stats.simd_variant = self.rust_scanner.get_simd_variant()
                self.stats.worker_count = self.rust_scanner.get_worker_count()
                self.stats.cpu_features = fastport_core.get_cpu_features()
            except Exception as e:
                self.console.print(f"[yellow]Warning: Could not initialize Rust core: {e}[/yellow]")
                RUST_CORE_AVAILABLE = False

    def create_header(self) -> Panel:
        """Create stylized header with branding"""
        title_text = Text()
        title_text.append("⚡ FastPort ", style="bold bright_cyan")
        title_text.append("Professional ", style="bold bright_white")
        title_text.append("v1.0", style="bold bright_green")

        subtitle = Text()
        if RUST_CORE_AVAILABLE:
            subtitle.append("🚀 ", style="bright_yellow")
            subtitle.append(f"SIMD: {self.stats.simd_variant} ", style="bright_cyan")
            subtitle.append(f"| Workers: {self.stats.worker_count} ", style="bright_magenta")
            subtitle.append("| Status: ", style="dim")
            subtitle.append("ACCELERATED", style="bold bright_green blink")
        else:
            subtitle.append("⚠️  ", style="bright_yellow")
            subtitle.append("Python Mode ", style="bright_yellow")
            subtitle.append("| ", style="dim")
            subtitle.append("Rust core not loaded", style="dim")

        header_content = Align.center(
            Text.assemble(title_text, "\n", subtitle),
            vertical="middle"
        )

        return Panel(
            header_content,
            box=HEAVY,
            style="bright_cyan",
            border_style="bright_cyan bold"
        )

    def create_stats_panel(self) -> Panel:
        """Create system stats panel"""
        elapsed = (datetime.now() - self.stats.start_time).total_seconds()

        # Calculate ports per second
        if elapsed > 0:
            pps = self.stats.ports_scanned / elapsed
        else:
            pps = 0

        stats_table = Table.grid(padding=(0, 2))
        stats_table.add_column(style="cyan bold", justify="right")
        stats_table.add_column(style="bright_white")

        # Scan statistics
        stats_table.add_row("⏱  Elapsed:", f"{elapsed:.1f}s")
        stats_table.add_row("🎯 Targets:", f"{self.stats.targets_scanned}")
        stats_table.add_row("🔍 Ports Scanned:", f"{self.stats.ports_scanned:,}")
        stats_table.add_row("✅ Ports Open:", f"[bright_green]{self.stats.ports_open}[/bright_green]")
        stats_table.add_row("❌ Ports Closed:", f"[dim]{self.stats.ports_closed:,}[/dim]")
        stats_table.add_row("⚡ Speed:", f"[bright_yellow]{pps:,.0f}[/bright_yellow] ports/sec")

        # Performance metrics
        if RUST_CORE_AVAILABLE:
            stats_table.add_row("", "")
            stats_table.add_row("💻 SIMD:", f"[bright_cyan]{self.stats.simd_variant}[/bright_cyan]")
            stats_table.add_row("🧵 Workers:", f"[bright_magenta]{self.stats.worker_count}[/bright_magenta]")

        return Panel(
            stats_table,
            title="[bold bright_cyan]📊 Statistics[/bold bright_cyan]",
            box=ROUNDED,
            border_style="bright_cyan"
        )

    def create_activity_panel(self) -> Panel:
        """Create current activity panel"""
        if self.stats.current_target:
            activity_text = Text()
            activity_text.append("🎯 Scanning: ", style="bold bright_yellow")
            activity_text.append(self.stats.current_target, style="bright_white bold")
        else:
            activity_text = Text("⏸  Idle", style="dim")

        # Add recent discovery (if any)
        if self.results and len(self.results) > 0:
            latest = self.results[-1]
            activity_text.append("\n\n", style="")
            activity_text.append("🆕 Latest: ", style="bold bright_green")
            activity_text.append(f"{latest['hostname']}:{latest['port']} ", style="bright_white")
            if latest.get('service'):
                activity_text.append(f"({latest['service']})", style="bright_cyan")

        return Panel(
            Align.center(activity_text, vertical="middle"),
            title="[bold bright_magenta]⚡ Activity[/bold bright_magenta]",
            box=ROUNDED,
            border_style="bright_magenta",
            height=8
        )

    def create_results_table(self) -> Panel:
        """Create results table with color coding"""
        table = Table(
            show_header=True,
            header_style="bold bright_cyan",
            border_style="bright_blue",
            box=ROUNDED,
            expand=True
        )

        table.add_column("Host", style="bright_white", no_wrap=True)
        table.add_column("Port", style="bright_yellow", justify="right")
        table.add_column("State", style="bright_green", justify="center")
        table.add_column("Service", style="cyan")
        table.add_column("Version", style="bright_magenta")
        table.add_column("Time", style="dim", justify="right")

        # Show last 15 results
        for result in self.results[-15:]:
            host = result['hostname']
            port = str(result['port'])
            state = "●" if result.get('is_open', True) else "○"
            service = result.get('service', '-')
            version = result.get('version', '-')
            response_time = f"{result.get('response_time_ms', 0)}ms"

            table.add_row(host, port, state, service, version, response_time)

        if not self.results:
            table.add_row("-", "-", "-", "[dim]No results yet[/dim]", "-", "-")

        return Panel(
            table,
            title=f"[bold bright_green]🔍 Open Ports ({self.stats.ports_open})[/bold bright_green]",
            box=ROUNDED,
            border_style="bright_green"
        )

    def create_system_info(self) -> Panel:
        """Create system information panel"""
        if RUST_CORE_AVAILABLE and self.rust_scanner:
            try:
                benchmark_result = fastport_core.benchmark_simd()
                info_text = Text(benchmark_result, style="bright_white")
            except:
                info_text = Text(self.stats.cpu_features, style="bright_white")
        else:
            info_text = Text("Python-only mode\nFor best performance, compile Rust core", style="yellow")

        return Panel(
            info_text,
            title="[bold bright_yellow]🖥  System Info[/bold bright_yellow]",
            box=ROUNDED,
            border_style="bright_yellow",
            height=8
        )

    def create_dashboard(self) -> Layout:
        """Create complete dashboard layout"""
        layout = Layout()

        # Main structure
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="body"),
            Layout(name="footer", size=1)
        )

        # Header
        layout["header"].update(self.create_header())

        # Body split into left sidebar and main area
        layout["body"].split_row(
            Layout(name="sidebar", ratio=1),
            Layout(name="main", ratio=2)
        )

        # Sidebar split into stats and activity
        layout["body"]["sidebar"].split_column(
            Layout(name="stats"),
            Layout(name="system", size=10)
        )

        layout["body"]["sidebar"]["stats"].update(self.create_stats_panel())
        layout["body"]["sidebar"]["system"].update(self.create_system_info())

        # Main area shows results
        layout["body"]["main"].update(self.create_results_table())

        # Footer
        footer_text = Text()
        footer_text.append("FastPort Professional", style="dim")
        footer_text.append(" | ", style="dim")
        footer_text.append("Ctrl+C to stop", style="bright_red")
        layout["footer"].update(Align.center(footer_text))

        return layout

    async def scan_with_live_ui(
        self,
        targets: List[str],
        ports: List[int],
        workers: int = 200,
        timeout: int = 2
    ):
        """Run scan with live updating UI"""
        self.stats.start_time = datetime.now()

        with Live(self.create_dashboard(), refresh_per_second=4, console=self.console) as live:
            for target_idx, target in enumerate(targets, 1):
                self.stats.current_target = target
                self.stats.targets_scanned = target_idx
                live.update(self.create_dashboard())

                # Create scanner
                scanner = AsyncPortScanner(target, ports, max_workers=workers, timeout=timeout)

                # Scan
                scan_results = await scanner.scan()

                # Process results
                for result in scan_results:
                    if result['is_open']:
                        self.stats.ports_open += 1
                        self.results.append(result)
                    else:
                        self.stats.ports_closed += 1

                    self.stats.ports_scanned += 1
                    live.update(self.create_dashboard())

            # Final update
            self.stats.current_target = ""
            live.update(self.create_dashboard())

        # Show completion message
        self.console.print("\n")
        self.console.print(Panel(
            f"[bright_green]✅ Scan Complete![/bright_green]\n\n"
            f"Scanned {self.stats.targets_scanned} targets\n"
            f"Found {self.stats.ports_open} open ports\n"
            f"Time: {(datetime.now() - self.stats.start_time).total_seconds():.1f}s",
            title="[bold bright_green]Success[/bold bright_green]",
            border_style="bright_green",
            box=HEAVY
        ))


async def main():
    parser = argparse.ArgumentParser(
        description="FastPort Professional - High-Performance Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  fastport-pro-tui example.com -p 80,443,8080
  fastport-pro-tui 192.168.1.1 -p 1-1000
  fastport-pro-tui target.com -p 22,80,443,3306,6379 -w 500
        """
    )

    parser.add_argument('target', help='Target hostname or IP')
    parser.add_argument('-p', '--ports', required=True, help='Ports to scan (e.g., 80,443,8000-9000)')
    parser.add_argument('-w', '--workers', type=int, default=200, help='Max concurrent workers (default: 200)')
    parser.add_argument('-t', '--timeout', type=int, default=2, help='Connection timeout in seconds (default: 2)')
    parser.add_argument('-o', '--output', help='Save results to JSON file')

    args = parser.parse_args()

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    console = Console()
    tui = FastPortProTUI(console)

    try:
        await tui.scan_with_live_ui(
            targets=[args.target],
            ports=ports,
            workers=args.workers,
            timeout=args.timeout
        )

        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(tui.results, f, indent=2, default=str)
            console.print(f"\n[bright_green]Results saved to {args.output}[/bright_green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
