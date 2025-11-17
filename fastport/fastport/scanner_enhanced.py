#!/usr/bin/env python3
"""
Enhanced Scanner with Stop/Resume and Verbose Feedback
Extends the base scanner with checkpoint system and detailed progress tracking
Includes automatic Cisco AnyConnect detection and credential testing
"""

import json
import signal
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
from dataclasses import dataclass, asdict, field
import time

from .scanner import (
    GPUClusterScanner, EnhancedAsset, ServiceDetection,
    GPU_CLUSTER_PORTS, COMMON_PORTS, TOP_1000_PORTS
)

try:
    from .anyconnect_tester import AnyConnectTester
    ANYCONNECT_AVAILABLE = True
except ImportError:
    ANYCONNECT_AVAILABLE = False


@dataclass
class AnyConnectVulnerability:
    """AnyConnect vulnerability detection result"""
    endpoint_url: str
    version: Optional[str] = None
    vulnerable: bool = False
    working_credentials: List[Dict[str, str]] = field(default_factory=list)
    auth_method: Optional[str] = None
    session_token: Optional[str] = None


@dataclass
class ScanCheckpoint:
    """Checkpoint data for resumable scans"""
    checkpoint_timestamp: str
    total_targets: int
    completed_targets: int
    remaining_targets: List[Dict[str, str]]
    completed_results: List[Dict]
    scan_config: Dict
    verbose: bool = False


class EnhancedGPUScanner(GPUClusterScanner):
    """
    Enhanced scanner with stop/resume capability and verbose feedback

    Features:
    - Checkpoint system for resumable scans
    - Graceful interruption handling (Ctrl+C)
    - Verbose progress feedback (toggleable)
    - Incremental result saving
    - Detailed statistics and timing
    - Automatic Cisco AnyConnect detection and credential testing
    """

    def __init__(self, port_mode: str = "common", scanner_mode: str = "async",
                 verbose: bool = False, checkpoint_file: Optional[str] = None,
                 test_anyconnect: bool = True):
        """
        Initialize enhanced scanner

        Args:
            port_mode: Port scanning mode (common, gpu, top1000, all)
            scanner_mode: Scanner implementation (async, masscan, thread)
            verbose: Enable verbose progress output
            checkpoint_file: Path to checkpoint file for resume/save
            test_anyconnect: Test default credentials on AnyConnect endpoints
        """
        super().__init__(port_mode, scanner_mode)

        self.verbose = verbose
        self.checkpoint_file = checkpoint_file or ".scanner_checkpoint.json"
        self.test_anyconnect = test_anyconnect and ANYCONNECT_AVAILABLE
        self.interrupted = False
        self.start_time = None
        self.completed_count = 0
        self.total_count = 0
        self.anyconnect_vulnerabilities = []

        # Initialize AnyConnect tester if enabled
        if self.test_anyconnect:
            self.anyconnect_tester = AnyConnectTester(timeout=5, verbose=False)
        else:
            self.anyconnect_tester = None

        # Setup signal handlers for graceful interruption
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        """Handle interrupt signals (Ctrl+C, SIGTERM) gracefully"""
        if not self.interrupted:
            self.interrupted = True
            self._vprint("\n[!] Interrupt received. Saving checkpoint...", force=True)
            self._save_checkpoint()
            self._vprint(f"[+] Checkpoint saved to {self.checkpoint_file}", force=True)
            self._vprint("[!] Run with --resume to continue from checkpoint", force=True)
            sys.exit(0)

    def _vprint(self, message: str, force: bool = False):
        """Print message if verbose mode is enabled

        Args:
            message: Message to print
            force: Force print even if verbose is False
        """
        if self.verbose or force:
            print(message)
            sys.stdout.flush()

    def _test_anyconnect_vulnerability(self, hostname: str, detected_services: List[ServiceDetection]):
        """
        Test for Cisco AnyConnect and vulnerable credentials

        Args:
            hostname: Target hostname
            detected_services: List of detected services on the host
        """
        if not self.anyconnect_tester:
            return

        # Check if HTTPS ports are open (AnyConnect typically on 443/8443)
        https_ports = [svc.port for svc in detected_services if svc.port in [443, 8443, 10443]]

        if not https_ports:
            return

        self._vprint(f"\n    [*] Checking for Cisco AnyConnect on {hostname}")

        for port in https_ports:
            try:
                # Detect AnyConnect
                endpoint = self.anyconnect_tester.detect_anyconnect(hostname, port)

                if endpoint:
                    self._vprint(f"    [+] Cisco AnyConnect detected on port {port}", force=True)
                    if endpoint.version:
                        self._vprint(f"        Version: {endpoint.version}", force=True)

                    # Test default credentials (test:test is first in the list)
                    self._vprint(f"    [*] Testing default credentials (test:test and others)...")

                    cred_results = self.anyconnect_tester.test_credentials(endpoint, test_defaults=True)

                    # Check for successful authentications
                    successful_auths = [r for r in cred_results if r.success]

                    if successful_auths:
                        # Create vulnerability record
                        vuln = AnyConnectVulnerability(
                            endpoint_url=endpoint.url,
                            version=endpoint.version,
                            vulnerable=True,
                            working_credentials=[
                                {'username': auth.username, 'password': auth.password}
                                for auth in successful_auths
                            ],
                            auth_method=successful_auths[0].auth_method,
                            session_token=successful_auths[0].session_token
                        )

                        self.anyconnect_vulnerabilities.append(vuln)

                        self._vprint(f"\n    [!!!] CRITICAL: AnyConnect vulnerable to default credentials!", force=True)
                        self._vprint(f"        Endpoint: {endpoint.url}", force=True)
                        for auth in successful_auths:
                            self._vprint(f"        Working credentials: {auth.username}:{auth.password}", force=True)
                        self._vprint(f"        Auth method: {successful_auths[0].auth_method}", force=True)

                        # Highlight test:test specifically
                        test_test_auth = [a for a in successful_auths if a.username == 'test' and a.password == 'test']
                        if test_test_auth:
                            self._vprint(f"        [!!!] test:test credentials work!", force=True)

                    else:
                        self._vprint(f"    [-] No default credentials worked")

            except Exception as e:
                self._vprint(f"    [!] Error testing AnyConnect on port {port}: {e}")

    def _save_checkpoint(self):
        """Save current scan state to checkpoint file"""
        if not hasattr(self, '_remaining_targets'):
            return

        checkpoint = ScanCheckpoint(
            checkpoint_timestamp=datetime.now().isoformat(),
            total_targets=self.total_count,
            completed_targets=self.completed_count,
            remaining_targets=self._remaining_targets,
            completed_results=[asdict(r) for r in self.results],
            scan_config={
                'port_mode': self.port_mode,
                'scanner_mode': self.scanner_mode,
                'verbose': self.verbose
            },
            verbose=self.verbose
        )

        try:
            with open(self.checkpoint_file, 'w') as f:
                json.dump(asdict(checkpoint), f, indent=2)
            self._vprint(f"[+] Checkpoint saved: {self.completed_count}/{self.total_count} targets completed")
        except Exception as e:
            print(f"[!] Error saving checkpoint: {e}", file=sys.stderr)

    def _load_checkpoint(self) -> Optional[ScanCheckpoint]:
        """Load checkpoint from file

        Returns:
            ScanCheckpoint if exists, None otherwise
        """
        if not os.path.exists(self.checkpoint_file):
            return None

        try:
            with open(self.checkpoint_file, 'r') as f:
                data = json.load(f)

            # Reconstruct results from checkpoint
            results = []
            for r_dict in data['completed_results']:
                # Reconstruct ServiceDetection objects
                services = []
                for s in r_dict['detected_services']:
                    services.append(ServiceDetection(**s))

                # Reconstruct EnhancedAsset
                r_dict['detected_services'] = services
                results.append(EnhancedAsset(**r_dict))

            checkpoint = ScanCheckpoint(
                checkpoint_timestamp=data['checkpoint_timestamp'],
                total_targets=data['total_targets'],
                completed_targets=data['completed_targets'],
                remaining_targets=data['remaining_targets'],
                completed_results=data['completed_results'],
                scan_config=data['scan_config'],
                verbose=data.get('verbose', False)
            )

            # Restore results
            self.results = results

            return checkpoint
        except Exception as e:
            print(f"[!] Error loading checkpoint: {e}", file=sys.stderr)
            return None

    def scan_from_gpu_report_enhanced(self, gpu_json_path: str, confidence_filter: str = "HIGH",
                                     resume: bool = False, checkpoint_interval: int = 5) -> List[EnhancedAsset]:
        """
        Enhanced scan with stop/resume capability and verbose feedback

        Args:
            gpu_json_path: Path to GPU cluster analysis JSON
            confidence_filter: Only scan hosts with this confidence or higher (HIGH, MEDIUM, LOW)
            resume: If True, attempt to resume from checkpoint
            checkpoint_interval: Save checkpoint every N hosts

        Returns:
            List of EnhancedAsset with scan results
        """
        self.start_time = time.time()

        # Try to resume from checkpoint
        if resume:
            checkpoint = self._load_checkpoint()
            if checkpoint:
                self._vprint(f"[+] Resuming from checkpoint: {checkpoint.completed_targets}/{checkpoint.total_targets} completed", force=True)
                self._vprint(f"[+] Checkpoint timestamp: {checkpoint.checkpoint_timestamp}", force=True)

                self._remaining_targets = checkpoint.remaining_targets
                self.completed_count = checkpoint.completed_targets
                self.total_count = checkpoint.total_targets

                # Restore results already loaded in _load_checkpoint
                self._vprint(f"[+] Loaded {len(self.results)} completed scans from checkpoint")
            else:
                self._vprint("[!] No checkpoint found, starting fresh scan", force=True)
                resume = False

        # If not resuming, load fresh targets
        if not resume:
            self._vprint(f"[+] Loading targets from {gpu_json_path}")

            try:
                with open(gpu_json_path, 'r') as f:
                    gpu_data = json.load(f)
            except Exception as e:
                print(f"[!] Error loading GPU report: {e}", file=sys.stderr)
                return []

            # Filter candidates by confidence
            confidence_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            min_confidence = confidence_order.get(confidence_filter, 3)

            candidates = gpu_data.get('gpu_cluster_candidates', [])
            targets = []

            for candidate in candidates:
                conf_score = candidate.get('confidence_score', 0)

                # Determine confidence level
                if conf_score >= 1.5:
                    conf_level = 'HIGH'
                    conf_value = 3
                elif conf_score >= 0.8:
                    conf_level = 'MEDIUM'
                    conf_value = 2
                else:
                    conf_level = 'LOW'
                    conf_value = 1

                if conf_value >= min_confidence:
                    targets.append({
                        'hostname': candidate['hostname'],
                        'university': candidate['university'],
                        'confidence': conf_level
                    })

            self._remaining_targets = targets
            self.total_count = len(targets)
            self.completed_count = 0
            self.results = []

            self._vprint(f"[+] Found {self.total_count} GPU clusters to scan (confidence >= {confidence_filter})", force=True)

        # Scan each remaining target
        self._vprint(f"\n[+] Starting scan of {len(self._remaining_targets)} remaining targets", force=True)
        self._vprint(f"[+] Checkpoint will be saved every {checkpoint_interval} hosts")
        self._vprint(f"[+] Press Ctrl+C to interrupt and save progress\n")

        while self._remaining_targets:
            if self.interrupted:
                break

            target = self._remaining_targets.pop(0)
            self.completed_count += 1

            self._vprint(f"\n[{self.completed_count}/{self.total_count}] Scanning {target['hostname']} ({target['university']})")
            self._vprint(f"    Confidence: {target['confidence']}")
            self._vprint(f"    Port mode: {self.port_mode}")

            scan_start = time.time()

            try:
                result = self.scan_host(
                    target['hostname'],
                    target['university'],
                    target['confidence']
                )

                scan_duration = time.time() - scan_start

                self.results.append(result)

                # Verbose output
                self._vprint(f"    Duration: {scan_duration:.2f}s")
                self._vprint(f"    Open ports: {result.total_open_ports}")

                if result.detected_services:
                    self._vprint(f"    Detected services:")
                    for svc in result.detected_services[:5]:  # Show first 5
                        version_info = f" ({svc.version})" if svc.version else ""
                        self._vprint(f"      - {svc.port}/{svc.service_name}{version_info}")
                    if len(result.detected_services) > 5:
                        self._vprint(f"      ... and {len(result.detected_services) - 5} more")

                if result.high_risk_services:
                    self._vprint(f"    [!] High-risk services: {', '.join(result.high_risk_services)}")

                # Test for AnyConnect if enabled
                if self.test_anyconnect and result.detected_services:
                    self._test_anyconnect_vulnerability(target['hostname'], result.detected_services)

            except Exception as e:
                self._vprint(f"    [!] Error scanning {target['hostname']}: {e}")

            # Save checkpoint periodically
            if self.completed_count % checkpoint_interval == 0:
                self._save_checkpoint()

                # Show progress statistics
                elapsed = time.time() - self.start_time
                rate = self.completed_count / elapsed
                remaining = len(self._remaining_targets)
                eta = remaining / rate if rate > 0 else 0

                self._vprint(f"\n--- Progress Statistics ---")
                self._vprint(f"    Completed: {self.completed_count}/{self.total_count} ({100*self.completed_count/self.total_count:.1f}%)")
                self._vprint(f"    Elapsed time: {elapsed/60:.1f} minutes")
                self._vprint(f"    Scan rate: {rate*60:.1f} hosts/minute")
                self._vprint(f"    ETA: {eta/60:.1f} minutes")
                self._vprint(f"    Checkpoint saved")

        # Final checkpoint
        if self._remaining_targets:
            self._save_checkpoint()
        else:
            # Clean up checkpoint file when complete
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
                self._vprint(f"\n[+] Scan complete! Checkpoint file removed.", force=True)

        # Final statistics
        total_time = time.time() - self.start_time
        self._vprint(f"\n=== Scan Complete ===", force=True)
        self._vprint(f"Total hosts scanned: {self.completed_count}", force=True)
        self._vprint(f"Total time: {total_time/60:.1f} minutes", force=True)
        self._vprint(f"Average rate: {self.completed_count/(total_time/60):.1f} hosts/minute", force=True)

        total_open_ports = sum(r.total_open_ports for r in self.results)
        hosts_with_risk = sum(1 for r in self.results if r.high_risk_services)

        self._vprint(f"Total open ports found: {total_open_ports}", force=True)
        self._vprint(f"Hosts with high-risk services: {hosts_with_risk}", force=True)

        # AnyConnect vulnerability summary
        if self.anyconnect_vulnerabilities:
            self._vprint(f"\n[!!!] CRITICAL SECURITY FINDINGS:", force=True)
            self._vprint(f"AnyConnect endpoints with default credentials: {len(self.anyconnect_vulnerabilities)}", force=True)
            for vuln in self.anyconnect_vulnerabilities:
                self._vprint(f"  - {vuln.endpoint_url}", force=True)
                for cred in vuln.working_credentials:
                    self._vprint(f"    * {cred['username']}:{cred['password']}", force=True)

        return self.results

    def generate_report(self, output_file: str):
        """Generate enhanced report with checkpoint and timing information"""
        report = {
            'metadata': {
                'scan_timestamp': datetime.now().isoformat(),
                'scanner_version': '2.0.0-enhanced',
                'total_hosts_scanned': len(self.results),
                'scan_duration_seconds': time.time() - self.start_time if self.start_time else 0,
                'verbose_mode': self.verbose,
                'checkpoint_file': self.checkpoint_file
            },
            'summary': {
                'total_open_ports': sum(r.total_open_ports for r in self.results),
                'hosts_with_high_risk_services': sum(1 for r in self.results if r.high_risk_services),
                'total_high_risk_services': sum(len(r.high_risk_services) for r in self.results),
                'gpu_clusters_detected': sum(1 for r in self.results if r.gpu_cluster_detected),
                'anyconnect_vulnerabilities_found': len(self.anyconnect_vulnerabilities)
            },
            'anyconnect_vulnerabilities': [
                {
                    'endpoint_url': vuln.endpoint_url,
                    'version': vuln.version,
                    'vulnerable': vuln.vulnerable,
                    'working_credentials': vuln.working_credentials,
                    'auth_method': vuln.auth_method,
                    'has_test_test': any(c['username'] == 'test' and c['password'] == 'test'
                                        for c in vuln.working_credentials)
                }
                for vuln in self.anyconnect_vulnerabilities
            ],
            'scanned_hosts': [
                {
                    'hostname': r.hostname,
                    'university': r.university,
                    'gpu_confidence': r.gpu_confidence,
                    'total_open_ports': r.total_open_ports,
                    'high_risk_services': r.high_risk_services,
                    'gpu_cluster_detected': r.gpu_cluster_detected,
                    'detected_services': [
                        {
                            'port': s.port,
                            'service': s.service_name,
                            'banner': s.banner,
                            'version': s.version,
                            'ssl_enabled': s.ssl_enabled
                        }
                        for s in r.detected_services
                    ],
                    'scan_timestamp': r.scan_timestamp
                }
                for r in self.results
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        self._vprint(f"\n[+] Enhanced report saved to {output_file}", force=True)


def main():
    """CLI interface for enhanced scanner"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Enhanced GPU Cluster Scanner with Stop/Resume and Verbose Feedback',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start fresh scan with verbose output
  python -m fastport.scanner_enhanced -i gpu_clusters.json -o results.json --verbose

  # Resume interrupted scan
  python -m fastport.scanner_enhanced -i gpu_clusters.json -o results.json --resume --verbose

  # Custom checkpoint file
  python -m fastport.scanner_enhanced -i gpu_clusters.json -o results.json --checkpoint my_scan.ckpt

  # Quiet mode (minimal output)
  python -m fastport.scanner_enhanced -i gpu_clusters.json -o results.json

Features:
  - Press Ctrl+C to gracefully interrupt and save progress
  - Use --resume to continue from where you left off
  - Automatic checkpoints saved every 5 hosts
  - Detailed progress statistics in verbose mode
        """
    )

    parser.add_argument('-i', '--input', required=True,
                       help='Input GPU cluster analysis JSON file')
    parser.add_argument('-o', '--output', required=True,
                       help='Output enhanced scan results JSON file')
    parser.add_argument('-c', '--confidence', default='HIGH',
                       choices=['HIGH', 'MEDIUM', 'LOW'],
                       help='Minimum confidence level to scan (default: HIGH)')
    parser.add_argument('-p', '--port-mode', default='common',
                       choices=['gpu', 'common', 'top1000', 'all'],
                       help='Port scanning mode (default: common)')
    parser.add_argument('-s', '--scanner-mode', default='async',
                       choices=['async', 'masscan', 'thread'],
                       help='Scanner implementation (default: async)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose progress output')
    parser.add_argument('--resume', '-r', action='store_true',
                       help='Resume from checkpoint if available')
    parser.add_argument('--checkpoint', default='.scanner_checkpoint.json',
                       help='Checkpoint file path (default: .scanner_checkpoint.json)')
    parser.add_argument('--checkpoint-interval', type=int, default=5,
                       help='Save checkpoint every N hosts (default: 5)')
    parser.add_argument('--test-anyconnect', action='store_true', default=True,
                       help='Test Cisco AnyConnect endpoints for default credentials (default: enabled)')
    parser.add_argument('--no-anyconnect', action='store_true',
                       help='Disable AnyConnect credential testing')

    args = parser.parse_args()

    # Create enhanced scanner
    scanner = EnhancedGPUScanner(
        port_mode=args.port_mode,
        scanner_mode=args.scanner_mode,
        verbose=args.verbose,
        checkpoint_file=args.checkpoint,
        test_anyconnect=args.test_anyconnect and not args.no_anyconnect
    )

    print("[+] Enhanced GPU Cluster Scanner v2.0")
    print(f"[+] Port mode: {args.port_mode}")
    print(f"[+] Scanner mode: {args.scanner_mode}")
    print(f"[+] Verbose: {args.verbose}")
    print(f"[+] Resume: {args.resume}")
    print(f"[+] Checkpoint file: {args.checkpoint}")
    print(f"[+] AnyConnect testing: {'enabled' if scanner.test_anyconnect else 'disabled'}")

    # Run enhanced scan
    results = scanner.scan_from_gpu_report_enhanced(
        args.input,
        confidence_filter=args.confidence,
        resume=args.resume,
        checkpoint_interval=args.checkpoint_interval
    )

    # Generate report
    scanner.generate_report(args.output)

    print(f"\n[+] Scan complete!")
    print(f"[+] Scanned {len(results)} hosts")
    print(f"[+] Results saved to {args.output}")


if __name__ == '__main__':
    main()
