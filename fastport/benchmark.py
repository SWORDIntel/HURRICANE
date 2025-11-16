#!/usr/bin/env python3
"""
FastPort Benchmarking Suite

Compares FastPort performance against NMAP and Masscan
"""

import asyncio
import subprocess
import time
import sys
import json
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import track
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import fastport_core
    RUST_CORE_AVAILABLE = True
except ImportError:
    RUST_CORE_AVAILABLE = False

from fastport.scanner import AsyncPortScanner


@dataclass
class BenchmarkResult:
    tool: str
    port_count: int
    duration_seconds: float
    ports_per_second: float
    simd_variant: Optional[str] = None
    worker_count: Optional[int] = None


class PortScannerBenchmark:
    """Benchmark FastPort against other scanners"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or (Console() if RICH_AVAILABLE else None)
        self.results: List[BenchmarkResult] = []

    def print(self, *args, **kwargs):
        """Print with or without rich"""
        if self.console:
            self.console.print(*args, **kwargs)
        else:
            print(*args, **kwargs)

    async def benchmark_fastport(self, target: str, ports: List[int], workers: int = 200) -> BenchmarkResult:
        """Benchmark FastPort scanner"""
        self.print(f"[cyan]Benchmarking FastPort ({len(ports)} ports)...[/cyan]")

        scanner = AsyncPortScanner(target, ports, max_workers=workers, timeout=1)

        start_time = time.time()
        results = await scanner.scan()
        duration = time.time() - start_time

        pps = len(ports) / duration

        simd_variant = None
        worker_count = workers

        if RUST_CORE_AVAILABLE:
            try:
                rust_scanner = fastport_core.FastPortScanner(workers=None)
                simd_variant = rust_scanner.get_simd_variant()
                worker_count = rust_scanner.get_worker_count()
            except:
                pass

        return BenchmarkResult(
            tool=f"FastPort ({simd_variant or 'Python'})",
            port_count=len(ports),
            duration_seconds=duration,
            ports_per_second=pps,
            simd_variant=simd_variant,
            worker_count=worker_count
        )

    def benchmark_nmap(self, target: str, ports: List[int], timing: str = "-T4") -> Optional[BenchmarkResult]:
        """Benchmark NMAP scanner"""
        self.print(f"[cyan]Benchmarking NMAP {timing} ({len(ports)} ports)...[/cyan]")

        # Check if nmap is available
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.print("[yellow]NMAP not found, skipping[/yellow]")
            return None

        # Build port list
        port_spec = ','.join(str(p) for p in ports[:100])  # Limit to first 100 for nmap
        if len(ports) > 100:
            self.print(f"[yellow]Limiting NMAP to first 100 ports for fair comparison[/yellow]")

        cmd = ['nmap', timing, '-p', port_spec, '--open', target]

        try:
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            duration = time.time() - start_time

            if result.returncode != 0:
                self.print(f"[yellow]NMAP failed: {result.stderr}[/yellow]")
                return None

            pps = len(ports[:100]) / duration

            return BenchmarkResult(
                tool=f"NMAP {timing}",
                port_count=len(ports[:100]),
                duration_seconds=duration,
                ports_per_second=pps
            )
        except subprocess.TimeoutExpired:
            self.print("[yellow]NMAP timed out (5 minutes)[/yellow]")
            return None
        except Exception as e:
            self.print(f"[yellow]NMAP benchmark failed: {e}[/yellow]")
            return None

    def benchmark_masscan(self, target: str, ports: List[int]) -> Optional[BenchmarkResult]:
        """Benchmark Masscan scanner"""
        self.print(f"[cyan]Benchmarking Masscan ({len(ports)} ports)...[/cyan]")

        # Check if masscan is available
        try:
            subprocess.run(['masscan', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.print("[yellow]Masscan not found, skipping[/yellow]")
            return None

        # Build port list
        port_spec = ','.join(str(p) for p in ports)

        cmd = ['masscan', target, '-p', port_spec, '--rate', '1000', '--wait', '0']

        try:
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            duration = time.time() - start_time

            if result.returncode != 0:
                self.print(f"[yellow]Masscan failed: {result.stderr}[/yellow]")
                return None

            pps = len(ports) / duration

            return BenchmarkResult(
                tool="Masscan",
                port_count=len(ports),
                duration_seconds=duration,
                ports_per_second=pps
            )
        except subprocess.TimeoutExpired:
            self.print("[yellow]Masscan timed out (5 minutes)[/yellow]")
            return None
        except Exception as e:
            self.print(f"[yellow]Masscan benchmark failed: {e}[/yellow]")
            return None

    async def run_full_benchmark(self, target: str = "scanme.nmap.org"):
        """Run comprehensive benchmark suite"""
        self.print("\n")
        self.print(Panel.fit(
            "[bold bright_cyan]FastPort Benchmark Suite[/bold bright_cyan]\n"
            "[dim]Comparing FastPort vs NMAP vs Masscan[/dim]",
            border_style="bright_cyan"
        ))

        # Test configurations
        test_configs = [
            ("Quick Scan (10 ports)", list(range(1, 11))),
            ("Common Ports (100 ports)", [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                                           143, 443, 445, 993, 995, 1723, 3306, 3389,
                                           5900, 8080] + list(range(8000, 8080))),
            ("Full 1K Scan (1000 ports)", list(range(1, 1001))),
        ]

        for test_name, ports in test_configs:
            self.print(f"\n[bold bright_yellow]━━━ {test_name} ━━━[/bold bright_yellow]\n")

            # FastPort benchmark
            fastport_result = await self.benchmark_fastport(target, ports)
            self.results.append(fastport_result)

            # NMAP benchmarks
            for timing in ["-T4", ""]:
                timing_label = timing if timing else "default"
                nmap_result = self.benchmark_nmap(target, ports, timing=timing)
                if nmap_result:
                    self.results.append(nmap_result)

            # Masscan benchmark
            masscan_result = self.benchmark_masscan(target, ports)
            if masscan_result:
                self.results.append(masscan_result)

        # Display results
        self.display_results()

        # Save results
        self.save_results()

    def display_results(self):
        """Display benchmark results in a table"""
        self.print("\n")
        self.print(Panel.fit(
            "[bold bright_green]Benchmark Results[/bold bright_green]",
            border_style="bright_green"
        ))

        if not RICH_AVAILABLE:
            # Plain text table
            print(f"\n{'Tool':<30} {'Ports':<10} {'Duration':<12} {'Ports/sec':<15}")
            print("=" * 70)
            for result in self.results:
                print(f"{result.tool:<30} {result.port_count:<10} "
                      f"{result.duration_seconds:>10.2f}s {result.ports_per_second:>13,.0f}")
            return

        # Rich table
        table = Table(show_header=True, header_style="bold bright_cyan")
        table.add_column("Tool", style="bright_white", no_wrap=True)
        table.add_column("Ports", justify="right", style="bright_yellow")
        table.add_column("Duration", justify="right", style="cyan")
        table.add_column("Ports/sec", justify="right", style="bright_green")
        table.add_column("SIMD", style="bright_magenta")
        table.add_column("Workers", justify="right", style="dim")

        for result in self.results:
            tool_style = "bold bright_cyan" if "FastPort" in result.tool else "white"

            table.add_row(
                f"[{tool_style}]{result.tool}[/{tool_style}]",
                f"{result.port_count:,}",
                f"{result.duration_seconds:.2f}s",
                f"{result.ports_per_second:,.0f}",
                result.simd_variant or "-",
                str(result.worker_count) if result.worker_count else "-"
            )

        self.console.print(table)

        # Performance comparison
        self.print("\n[bold bright_yellow]Performance Analysis:[/bold bright_yellow]\n")

        fastport_results = [r for r in self.results if "FastPort" in r.tool]
        nmap_results = [r for r in self.results if "NMAP" in r.tool]
        masscan_results = [r for r in self.results if "Masscan" in r.tool]

        if fastport_results and nmap_results:
            avg_fastport_pps = sum(r.ports_per_second for r in fastport_results) / len(fastport_results)
            avg_nmap_pps = sum(r.ports_per_second for r in nmap_results) / len(nmap_results)
            speedup = avg_fastport_pps / avg_nmap_pps

            self.print(f"📊 FastPort is [bold bright_green]{speedup:.2f}x faster[/bold bright_green] than NMAP on average")

        if fastport_results and masscan_results:
            avg_masscan_pps = sum(r.ports_per_second for r in masscan_results) / len(masscan_results)
            comparison = avg_fastport_pps / avg_masscan_pps

            if comparison >= 0.95:
                self.print(f"⚡ FastPort matches Masscan performance ([bold bright_yellow]{comparison:.2f}x[/bold bright_yellow])")
            elif comparison >= 0.80:
                self.print(f"⚡ FastPort is competitive with Masscan ([bold bright_yellow]{comparison:.2f}x[/bold bright_yellow])")
            else:
                self.print(f"⚠️  FastPort is slower than Masscan ([bold yellow]{comparison:.2f}x[/bold yellow])")

        if RUST_CORE_AVAILABLE:
            self.print(f"\n💡 Running with [bold bright_cyan]Rust core[/bold bright_cyan] and "
                      f"[bold bright_magenta]{fastport_results[0].simd_variant}[/bold bright_magenta] SIMD")
        else:
            self.print(f"\n⚠️  Running in [bold yellow]Python-only mode[/bold yellow]")
            self.print(f"   For maximum performance, compile Rust core: [dim]cd fastport-core && maturin develop[/dim]")

    def save_results(self, filename: str = "benchmark_results.json"):
        """Save results to JSON file"""
        results_dict = [asdict(r) for r in self.results]

        with open(filename, 'w') as f:
            json.dump(results_dict, f, indent=2)

        self.print(f"\n[dim]Results saved to {filename}[/dim]")


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="FastPort Benchmark Suite")
    parser.add_argument('--target', default='scanme.nmap.org',
                       help='Target to benchmark against (default: scanme.nmap.org)')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick benchmark (10 ports only)')

    args = parser.parse_args()

    console = Console() if RICH_AVAILABLE else None
    benchmark = PortScannerBenchmark(console)

    if args.quick:
        # Quick benchmark
        ports = list(range(1, 11))
        print(f"Running quick benchmark on {args.target} (10 ports)")

        result = await benchmark.benchmark_fastport(args.target, ports)
        benchmark.results.append(result)

        nmap_result = benchmark.benchmark_nmap(args.target, ports, timing="-T4")
        if nmap_result:
            benchmark.results.append(nmap_result)

        benchmark.display_results()
    else:
        # Full benchmark
        await benchmark.run_full_benchmark(args.target)

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
