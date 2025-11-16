#!/usr/bin/env python3
"""
Automatic CVE Scanner for Port Scanner Output
Integrates port scanning with CVE vulnerability database lookup
Focuses on RCE (Remote Code Execution) vulnerabilities
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from .cve_lookup import CVELookup, CVERecord, ServiceVulnerability


@dataclass
class ServiceWithCVEs:
    """Service from port scan with CVE analysis"""
    hostname: str
    port: int
    service_name: str
    version: Optional[str]
    banner: Optional[str]
    vulnerabilities: Optional[ServiceVulnerability] = None


@dataclass
class HostVulnerabilityReport:
    """Vulnerability report for a single host"""
    hostname: str
    gpu_cluster_detected: bool
    total_services: int
    services_with_versions: int
    services_with_cves: int
    total_cves: int
    total_rce_cves: int
    critical_cves: int
    high_cves: int
    services: List[ServiceWithCVEs]


class AutoCVEScanner:
    """Automatic CVE scanner for port scanner output"""

    def __init__(self, port_scan_json: str, api_key: Optional[str] = None, rce_only: bool = False, use_rich: bool = True):
        """
        Initialize auto CVE scanner

        Args:
            port_scan_json: Path to port scanner output JSON
            api_key: Optional NVD API key
            rce_only: If True, only report RCE vulnerabilities
            use_rich: If True, use rich console for better output
        """
        self.port_scan_json = port_scan_json
        self.cve_lookup = CVELookup(api_key=api_key)
        self.rce_only = rce_only
        self.host_reports: List[HostVulnerabilityReport] = []
        self.use_rich = use_rich and RICH_AVAILABLE
        self.console = Console() if self.use_rich else None

    def load_port_scan_data(self) -> List[Dict]:
        """Load port scanner output JSON"""
        try:
            with open(self.port_scan_json, 'r') as f:
                data = json.load(f)

            # Support multiple JSON formats for compatibility
            if isinstance(data, list):
                # Direct list of hosts
                return data
            elif isinstance(data, dict):
                # Try different dict keys in order of preference
                for key in ['scanned_hosts', 'hosts', 'results']:
                    if key in data:
                        return data[key]
                # If single host object
                if 'hostname' in data:
                    return [data]
                # Unknown format
                print(f"[!] Unknown JSON format. Expected list or dict with 'scanned_hosts'/'hosts'/'results' key")
                return []
            else:
                print(f"[!] Unknown JSON format")
                return []

        except Exception as e:
            print(f"[!] Error loading port scan data: {e}")
            return []

    def scan_and_analyze(self):
        """Main workflow: load port scan results and perform CVE lookups"""
        hosts = self.load_port_scan_data()

        if not hosts:
            self._print("[!] No hosts found in port scan output", style="red")
            return

        self._print(f"\n[*] Loaded {len(hosts)} hosts from port scan", style="cyan")
        self._print(f"[*] Starting automatic CVE analysis...", style="cyan")
        self._print(f"[*] RCE-only mode: {self.rce_only}\n", style="yellow" if self.rce_only else "cyan")

        if self.use_rich:
            # Use rich progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console
            ) as progress:
                task = progress.add_task("[cyan]Scanning hosts...", total=len(hosts))

                for i, host_data in enumerate(hosts, 1):
                    hostname = host_data.get('hostname', 'unknown')
                    progress.update(task, description=f"[cyan]Scanning {hostname}")

                    report = self._analyze_host(host_data)
                    self.host_reports.append(report)

                    progress.advance(task)

                progress.update(task, description="[green]✓ Scan complete")
        else:
            # Fallback to simple output
            for i, host_data in enumerate(hosts, 1):
                print(f"\n{'='*70}")
                print(f"Host {i}/{len(hosts)}: {host_data.get('hostname', 'unknown')}")
                print(f"{'='*70}")

                report = self._analyze_host(host_data)
                self.host_reports.append(report)

        self._print(f"\n[+] Analysis complete for {len(hosts)} hosts", style="green")

    def _print(self, message: str, style: str = ""):
        """Print message with optional style"""
        if self.use_rich and self.console:
            self.console.print(message, style=style)
        else:
            print(message)

    def _analyze_host(self, host_data: Dict) -> HostVulnerabilityReport:
        """Analyze a single host from port scan results"""
        hostname = host_data.get('hostname', 'unknown')
        gpu_cluster = host_data.get('gpu_cluster_detected', False)
        detected_services = host_data.get('detected_services', [])

        print(f"\n[*] Analyzing {len(detected_services)} services...")
        if gpu_cluster:
            print(f"[!] GPU cluster detected on this host")

        services_with_cves = []
        total_cves = 0
        total_rce = 0
        total_critical = 0
        total_high = 0
        services_with_versions = 0

        for service in detected_services:
            port = service.get('port')
            service_name = service.get('service_name', 'Unknown')
            version = service.get('version')
            banner = service.get('banner', '')

            # Skip if no version detected (can't do specific CVE lookup)
            if not version:
                service_cve = ServiceWithCVEs(
                    hostname=hostname,
                    port=port,
                    service_name=service_name,
                    version=None,
                    banner=banner[:100] if banner else None,
                    vulnerabilities=None
                )
                services_with_cves.append(service_cve)
                continue

            services_with_versions += 1

            print(f"\n[*] Service: {service_name} {version} (port {port})")

            # Perform CVE lookup with version
            vuln = self.cve_lookup.lookup_service_with_version(service_name, version)

            # If RCE-only mode, filter to only RCE CVEs
            if self.rce_only and vuln.rce_count > 0:
                rce_cves = self.cve_lookup.get_rce_only(vuln)
                # Update vulnerability object with only RCE CVEs
                vuln.cves = rce_cves
                vuln.total_cves = len(rce_cves)
                # Recalculate severity counts
                vuln.critical_count = sum(1 for c in rce_cves if c.severity == 'CRITICAL')
                vuln.high_count = sum(1 for c in rce_cves if c.severity == 'HIGH')
                vuln.medium_count = sum(1 for c in rce_cves if c.severity == 'MEDIUM')
                vuln.low_count = sum(1 for c in rce_cves if c.severity == 'LOW')

            service_cve = ServiceWithCVEs(
                hostname=hostname,
                port=port,
                service_name=service_name,
                version=version,
                banner=banner[:100] if banner else None,
                vulnerabilities=vuln
            )

            services_with_cves.append(service_cve)

            if vuln.total_cves > 0:
                total_cves += vuln.total_cves
                total_rce += vuln.rce_count
                total_critical += vuln.critical_count
                total_high += vuln.high_count

        report = HostVulnerabilityReport(
            hostname=hostname,
            gpu_cluster_detected=gpu_cluster,
            total_services=len(detected_services),
            services_with_versions=services_with_versions,
            services_with_cves=sum(1 for s in services_with_cves if s.vulnerabilities and s.vulnerabilities.total_cves > 0),
            total_cves=total_cves,
            total_rce_cves=total_rce,
            critical_cves=total_critical,
            high_cves=total_high,
            services=services_with_cves
        )

        self._print_host_summary(report)

        return report

    def _print_host_summary(self, report: HostVulnerabilityReport):
        """Print summary for a host"""
        print(f"\n{'─'*70}")
        print(f"SUMMARY for {report.hostname}")
        print(f"{'─'*70}")
        print(f"Total services scanned: {report.total_services}")
        print(f"Services with versions: {report.services_with_versions}")
        print(f"Services with CVEs: {report.services_with_cves}")
        print(f"Total CVEs found: {report.total_cves}")

        if report.total_rce_cves > 0:
            print(f"\n[!!!] RCE VULNERABILITIES: {report.total_rce_cves}")
        if report.critical_cves > 0:
            print(f"[!] Critical vulnerabilities: {report.critical_cves}")
        if report.high_cves > 0:
            print(f"[!] High vulnerabilities: {report.high_cves}")

    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate comprehensive vulnerability report"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"cve_scan_report_{timestamp}.json"

        # Calculate overall statistics
        total_hosts = len(self.host_reports)
        hosts_with_cves = sum(1 for r in self.host_reports if r.total_cves > 0)
        hosts_with_rce = sum(1 for r in self.host_reports if r.total_rce_cves > 0)
        total_cves = sum(r.total_cves for r in self.host_reports)
        total_rce = sum(r.total_rce_cves for r in self.host_reports)
        total_critical = sum(r.critical_cves for r in self.host_reports)
        total_high = sum(r.high_cves for r in self.host_reports)

        report = {
            'metadata': {
                'scan_timestamp': datetime.now().isoformat(),
                'source_file': self.port_scan_json,
                'rce_only_mode': self.rce_only,
                'scanner_version': '1.0.0'
            },
            'summary': {
                'total_hosts_scanned': total_hosts,
                'hosts_with_vulnerabilities': hosts_with_cves,
                'hosts_with_rce_vulnerabilities': hosts_with_rce,
                'total_cves_found': total_cves,
                'total_rce_cves': total_rce,
                'total_critical': total_critical,
                'total_high': total_high
            },
            'hosts': []
        }

        # Add host reports
        for host_report in self.host_reports:
            host_dict = {
                'hostname': host_report.hostname,
                'gpu_cluster_detected': host_report.gpu_cluster_detected,
                'statistics': {
                    'total_services': host_report.total_services,
                    'services_with_versions': host_report.services_with_versions,
                    'services_with_cves': host_report.services_with_cves,
                    'total_cves': host_report.total_cves,
                    'rce_cves': host_report.total_rce_cves,
                    'critical': host_report.critical_cves,
                    'high': host_report.high_cves
                },
                'services': []
            }

            # Add services with vulnerabilities
            for service in host_report.services:
                if service.vulnerabilities and service.vulnerabilities.total_cves > 0:
                    service_dict = {
                        'port': service.port,
                        'service_name': service.service_name,
                        'version': service.version,
                        'banner': service.banner,
                        'vulnerabilities': {
                            'total_cves': service.vulnerabilities.total_cves,
                            'rce_count': service.vulnerabilities.rce_count,
                            'critical_count': service.vulnerabilities.critical_count,
                            'high_count': service.vulnerabilities.high_count,
                            'medium_count': service.vulnerabilities.medium_count,
                            'low_count': service.vulnerabilities.low_count,
                            'cves': [asdict(cve) for cve in service.vulnerabilities.cves]  # ALL CVEs (no limit)
                        }
                    }
                    host_dict['services'].append(service_dict)

            report['hosts'].append(host_dict)

        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] CVE report saved to: {output_file}")

        # Generate markdown summary
        summary_file = output_file.replace('.json', '_summary.md')
        self._generate_markdown_summary(summary_file, report)
        print(f"[+] Summary report saved to: {summary_file}")

        # Generate RCE-specific report if RCEs found
        if total_rce > 0:
            rce_file = output_file.replace('.json', '_RCE_CRITICAL.md')
            self._generate_rce_report(rce_file, report)
            print(f"[!!!] RCE-specific report saved to: {rce_file}")

        return output_file

    def _generate_markdown_summary(self, output_file: str, report: Dict):
        """Generate markdown summary report"""
        summary = report['summary']

        md = f"""# Automated CVE Vulnerability Scan Report

**Generated:** {report['metadata']['scan_timestamp']}
**Source:** {report['metadata']['source_file']}
**RCE-Only Mode:** {report['metadata']['rce_only_mode']}

## Executive Summary

This report identifies known CVE vulnerabilities in services detected during port scanning,
with automatic version detection and CVE database matching.

### Key Findings

- **Hosts Scanned:** {summary['total_hosts_scanned']}
- **Hosts with Vulnerabilities:** {summary['hosts_with_vulnerabilities']}
- **Hosts with RCE Vulnerabilities:** {summary['hosts_with_rce_vulnerabilities']}
- **Total CVEs Found:** {summary['total_cves_found']}
  - **RCE (Remote Code Execution):** {summary['total_rce_cves']}
  - Critical: {summary['total_critical']}
  - High: {summary['total_high']}

{"## ⚠️ CRITICAL: RCE VULNERABILITIES FOUND" if summary['total_rce_cves'] > 0 else ""}
{f"This scan identified **{summary['total_rce_cves']} Remote Code Execution (RCE)** vulnerabilities across {summary['hosts_with_rce_vulnerabilities']} hosts." if summary['total_rce_cves'] > 0 else ""}
{f"These are **CRITICAL** security issues that allow attackers to execute arbitrary code remotely." if summary['total_rce_cves'] > 0 else ""}

---

## Vulnerable Hosts

"""

        # List all hosts with vulnerabilities
        for host in report['hosts']:
            if host['statistics']['total_cves'] > 0:
                stats = host['statistics']
                md += f"### {host['hostname']}\n\n"

                if host.get('gpu_cluster_detected'):
                    md += "**🎓 GPU Cluster Detected**\n\n"

                md += f"- **Total CVEs:** {stats['total_cves']}\n"

                if stats['rce_cves'] > 0:
                    md += f"- **⚠️ RCE Vulnerabilities:** {stats['rce_cves']}\n"

                md += f"- **Critical:** {stats['critical']}\n"
                md += f"- **High:** {stats['high']}\n"
                md += f"- **Vulnerable Services:** {stats['services_with_cves']}\n\n"

                # List vulnerable services
                for service in host['services']:
                    vulns = service['vulnerabilities']
                    md += f"#### Port {service['port']}: {service['service_name']} {service['version']}\n\n"
                    md += f"- Total CVEs: {vulns['total_cves']}\n"

                    if vulns['rce_count'] > 0:
                        md += f"- **⚠️ RCE CVEs: {vulns['rce_count']}**\n"

                    md += f"- Critical: {vulns['critical_count']}, High: {vulns['high_count']}, Medium: {vulns['medium_count']}\n\n"

                    # List ALL CVEs for this service (not just top 3)
                    if vulns['cves']:
                        md += f"**All {len(vulns['cves'])} CVEs:**\n\n"

                        # Group by severity for better readability
                        critical_cves = [c for c in vulns['cves'] if c.get('severity') == 'CRITICAL']
                        high_cves = [c for c in vulns['cves'] if c.get('severity') == 'HIGH']
                        medium_cves = [c for c in vulns['cves'] if c.get('severity') == 'MEDIUM']
                        low_cves = [c for c in vulns['cves'] if c.get('severity') == 'LOW']

                        # List Critical first
                        if critical_cves:
                            md += "**CRITICAL:**\n\n"
                            for cve in critical_cves:
                                rce_tag = " 🚨[RCE]" if cve.get('is_rce') else ""
                                exploit_tag = " ⚡[EXPLOIT]" if cve.get('exploit_available') else ""
                                md += f"- **{cve['cve_id']}** (CVSS: {cve['cvss_score']}){rce_tag}{exploit_tag}\n"
                                md += f"  {cve['description'][:150]}...\n\n"

                        # Then High
                        if high_cves:
                            md += "**HIGH:**\n\n"
                            for cve in high_cves:
                                rce_tag = " 🚨[RCE]" if cve.get('is_rce') else ""
                                exploit_tag = " ⚡[EXPLOIT]" if cve.get('exploit_available') else ""
                                md += f"- **{cve['cve_id']}** (CVSS: {cve['cvss_score']}){rce_tag}{exploit_tag}\n"
                                md += f"  {cve['description'][:150]}...\n\n"

                        # Then Medium (collapsed for readability)
                        if medium_cves:
                            md += f"**MEDIUM ({len(medium_cves)}):**\n\n"
                            for cve in medium_cves:
                                md += f"- {cve['cve_id']} (CVSS: {cve['cvss_score']})\n"

                        # Then Low (collapsed)
                        if low_cves:
                            md += f"\n**LOW ({len(low_cves)}):**\n\n"
                            for cve in low_cves:
                                md += f"- {cve['cve_id']} (CVSS: {cve['cvss_score']})\n"

                        md += "\n"

                md += "---\n\n"

        md += """
## Recommendations

### Immediate Actions (RCE Vulnerabilities)

1. **CRITICAL:** Patch or disable services with RCE vulnerabilities immediately
2. Isolate affected hosts from public network if patching not possible
3. Implement network segmentation to limit RCE exploitation
4. Monitor affected services for exploitation attempts

### Short-term (1-2 weeks)

1. Patch all Critical and High severity vulnerabilities
2. Conduct penetration testing on affected hosts
3. Review and restrict network access to vulnerable services
4. Implement Web Application Firewall (WAF) rules

### Long-term

1. Establish automated vulnerability scanning pipeline
2. Integrate CVE checking into CI/CD and deployment processes
3. Implement continuous monitoring for new CVEs
4. Train staff on security patching best practices

---

*Report generated by HDAIS Automatic CVE Scanner*
*Powered by NVD (National Vulnerability Database)*
"""

        with open(output_file, 'w') as f:
            f.write(md)

    def _generate_rce_report(self, output_file: str, report: Dict):
        """Generate RCE-specific critical report"""
        md = f"""# 🚨 CRITICAL: RCE VULNERABILITY REPORT

**Generated:** {report['metadata']['scan_timestamp']}
**Source:** {report['metadata']['source_file']}

## ⚠️ URGENT: Remote Code Execution Vulnerabilities Detected

This report lists **ONLY** Remote Code Execution (RCE) vulnerabilities found during scanning.
RCE vulnerabilities are **CRITICAL** as they allow attackers to execute arbitrary code on your systems.

### Summary

- **Total RCE CVEs:** {report['summary']['total_rce_cves']}
- **Hosts Affected:** {report['summary']['hosts_with_rce_vulnerabilities']}
- **Critical RCE:** {sum(1 for h in report['hosts'] for s in h['services'] for cve in s['vulnerabilities']['cves'] if cve.get('is_rce') and cve['severity'] == 'CRITICAL')}

---

## Affected Systems

"""

        # List hosts with RCE vulnerabilities
        for host in report['hosts']:
            rce_services = []
            for service in host['services']:
                rce_cves = [cve for cve in service['vulnerabilities']['cves'] if cve.get('is_rce')]
                if rce_cves:
                    rce_services.append({'service': service, 'rce_cves': rce_cves})

            if rce_services:
                md += f"### 🎯 {host['hostname']}\n\n"

                if host.get('gpu_cluster_detected'):
                    md += "**🎓 GPU Cluster - HIGH VALUE TARGET**\n\n"

                for item in rce_services:
                    service = item['service']
                    rce_cves = item['rce_cves']

                    md += f"#### Port {service['port']}: {service['service_name']} {service['version']}\n\n"
                    md += f"**{len(rce_cves)} RCE Vulnerabilities Found:**\n\n"

                    for cve in rce_cves:
                        exploit_tag = " **[EXPLOIT AVAILABLE]**" if cve.get('exploit_available') else ""
                        network_tag = " [NETWORK]" if cve.get('attack_vector') == 'NETWORK' else ""

                        md += f"##### {cve['cve_id']} - {cve['severity']} (CVSS: {cve['cvss_score']}){exploit_tag}{network_tag}\n\n"
                        md += f"{cve['description']}\n\n"

                        if cve.get('references'):
                            md += "**References:**\n"
                            for ref in cve['references'][:3]:
                                md += f"- {ref}\n"
                            md += "\n"

                    md += "---\n\n"

        md += """
## Immediate Response Required

### 1. Containment (Within 24 hours)

- [ ] Identify and isolate affected hosts
- [ ] Restrict network access to vulnerable services
- [ ] Enable additional monitoring/logging
- [ ] Alert security team and management

### 2. Patching (Within 1 week)

- [ ] Verify patches available for all RCE vulnerabilities
- [ ] Test patches in non-production environment
- [ ] Apply patches to production systems
- [ ] Verify patches successfully applied

### 3. Validation (Ongoing)

- [ ] Conduct vulnerability rescan
- [ ] Review logs for exploitation attempts
- [ ] Update security baselines
- [ ] Document lessons learned

---

**⚠️ TREAT THIS AS A SECURITY INCIDENT ⚠️**

RCE vulnerabilities represent an **IMMINENT THREAT** to your infrastructure.
These should be addressed with maximum priority.

*Report generated by HDAIS Automatic CVE Scanner*
"""

        with open(output_file, 'w') as f:
            f.write(md)

    def print_final_summary(self):
        """Print final summary of scan"""
        total_hosts = len(self.host_reports)
        hosts_with_cves = sum(1 for r in self.host_reports if r.total_cves > 0)
        hosts_with_rce = sum(1 for r in self.host_reports if r.total_rce_cves > 0)
        total_cves = sum(r.total_cves for r in self.host_reports)
        total_rce = sum(r.total_rce_cves for r in self.host_reports)
        total_critical = sum(r.critical_cves for r in self.host_reports)
        total_high = sum(r.high_cves for r in self.host_reports)

        if self.use_rich:
            # Rich formatted summary
            self.console.print("\n")
            self.console.rule("[bold cyan]AUTOMATIC CVE SCAN - FINAL SUMMARY")

            # Create summary table
            table = Table(title="Scan Results", box=box.ROUNDED, show_header=True)
            table.add_column("Metric", style="cyan", justify="left")
            table.add_column("Count", justify="right")
            table.add_column("Status", justify="center")

            table.add_row("Hosts Scanned", str(total_hosts), "✓")
            table.add_row("Hosts with Vulnerabilities", str(hosts_with_cves), "⚠️" if hosts_with_cves > 0 else "✓")
            table.add_row("Total CVEs Found", str(total_cves), "⚠️" if total_cves > 0 else "✓")

            # RCE row - red if found
            rce_status = "🚨" if total_rce > 0 else "✓"
            rce_style = "bold red" if total_rce > 0 else "white"
            table.add_row(
                "RCE Vulnerabilities",
                f"[{rce_style}]{total_rce}[/{rce_style}]",
                f"[{rce_style}]{rce_status}[/{rce_style}]"
            )

            # Critical row
            crit_style = "bold red" if total_critical > 0 else "white"
            table.add_row(
                "Critical Severity",
                f"[{crit_style}]{total_critical}[/{crit_style}]",
                "🔴" if total_critical > 0 else "✓"
            )

            # High row
            high_style = "bold orange3" if total_high > 0 else "white"
            table.add_row(
                "High Severity",
                f"[{high_style}]{total_high}[/{high_style}]",
                "🟠" if total_high > 0 else "✓"
            )

            self.console.print(table)

            # Warnings
            if total_rce > 0:
                self.console.print()
                self.console.print(Panel(
                    f"[bold red]⚠️  WARNING: {total_rce} RCE VULNERABILITIES DETECTED![/bold red]\n"
                    f"[red]Affected Hosts: {hosts_with_rce}[/red]\n"
                    "[red]Review the RCE Critical Report immediately![/red]",
                    title="[bold red]CRITICAL ALERT",
                    border_style="red"
                ))

            self.console.rule()
            self.console.print()

        else:
            # Fallback to simple output
            print("\n" + "="*70)
            print("AUTOMATIC CVE SCAN - FINAL SUMMARY")
            print("="*70)
            print(f"\nHosts Scanned: {total_hosts}")
            print(f"Hosts with Vulnerabilities: {hosts_with_cves}")

            if total_rce > 0:
                print(f"\n[!!!] CRITICAL: {total_rce} RCE VULNERABILITIES FOUND")
                print(f"[!!!] Affected Hosts: {hosts_with_rce}")

            print(f"\nTotal CVEs Found: {total_cves}")
            print("="*70 + "\n")


def main():
    """Command-line interface"""
    parser = argparse.ArgumentParser(
        description='Automatic CVE Scanner - Analyze port scan results for vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with automatic CVE lookup
  %(prog)s port_scan_results.json

  # With NVD API key (recommended for better rate limits)
  %(prog)s port_scan_results.json --api-key YOUR_API_KEY

  # RCE-only mode (only report Remote Code Execution vulnerabilities)
  %(prog)s port_scan_results.json --rce-only

  # Custom output file
  %(prog)s port_scan_results.json -o vulnerability_report.json

Workflow:
  1. Run port scanner: hdais-portscan gpu_clusters.json
  2. Run CVE analysis: %(prog)s port_scan_results.json
  3. Review generated reports (JSON + Markdown)
        """
    )

    parser.add_argument('port_scan_json', help='JSON output from port scanner')
    parser.add_argument('-k', '--api-key', help='NVD API key (optional, increases rate limit)')
    parser.add_argument('-o', '--output', help='Output file for CVE report')
    parser.add_argument('--rce-only', action='store_true', help='Only report RCE vulnerabilities')

    args = parser.parse_args()

    # Create scanner
    scanner = AutoCVEScanner(args.port_scan_json, api_key=args.api_key, rce_only=args.rce_only)

    # Scan and analyze
    scanner.scan_and_analyze()

    # Generate reports
    scanner.generate_report(args.output)

    # Print final summary
    scanner.print_final_summary()

    return 0


if __name__ == "__main__":
    exit(main())
