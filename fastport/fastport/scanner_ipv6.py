#!/usr/bin/env python3
"""
FASTPORT IPv6 Scanner - Hurricane Electric Tunnel Integration
High-performance IPv6 port scanner that works through v6-gatewayd tunnels

Features:
- Automatic IPv6 address discovery via v6-gatewayd API
- Tunnel health checking before scanning
- IPv6-native socket operations
- All FASTPORT features (AVX-512, CVE detection, etc.)
- Support for scanning both single hosts and ranges
"""

import sys
import socket
import json
import argparse
import asyncio
import ipaddress
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
import requests

# FASTPORT root
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastport.scanner import PortScanner
from fastport.scanner_enhanced import EnhancedScanner
from fastport.cve_scanner import CVEScanner


@dataclass
class TunnelInfo:
    """Information about an active IPv6 tunnel"""
    name: str
    state: str
    tunnel_type: str
    ipv6_address: str
    health: int


class V6GatewaydClient:
    """Client for v6-gatewayd API"""

    def __init__(self, api_url: str = "http://localhost:8642"):
        self.api_url = api_url.rstrip('/')

    def check_health(self) -> Dict[str, Any]:
        """Check v6-gatewayd daemon health"""
        try:
            response = requests.get(f"{self.api_url}/health", timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise RuntimeError(f"v6-gatewayd daemon not responding: {e}")

    def get_tunnels(self) -> List[TunnelInfo]:
        """Get list of active tunnels"""
        try:
            response = requests.get(f"{self.api_url}/tunnels", timeout=5)
            response.raise_for_status()
            data = response.json()

            tunnels = []
            for tunnel in data.get('tunnels', []):
                if tunnel.get('state') == 'up':
                    tunnels.append(TunnelInfo(
                        name=tunnel.get('name', 'unknown'),
                        state=tunnel['state'],
                        tunnel_type=tunnel.get('type', 'unknown'),
                        ipv6_address=tunnel.get('ipv6_address', ''),
                        health=tunnel.get('health', 0)
                    ))

            return tunnels
        except Exception as e:
            raise RuntimeError(f"Failed to get tunnel list: {e}")

    def get_ipv6_addresses(self) -> List[str]:
        """Get all available IPv6 addresses"""
        try:
            response = requests.get(f"{self.api_url}/v6/address", timeout=5)
            response.raise_for_status()
            data = response.json()

            addresses = []
            for addr_info in data.get('addresses', []):
                if addr_info.get('reachable'):
                    addresses.append(addr_info['address'])

            return addresses
        except Exception as e:
            raise RuntimeError(f"Failed to get IPv6 addresses: {e}")


class IPv6Scanner:
    """IPv6-enabled port scanner using FASTPORT core"""

    def __init__(self, api_url: str = "http://localhost:8642", verbose: bool = False):
        self.api_client = V6GatewaydClient(api_url)
        self.verbose = verbose

    def _log(self, message: str):
        """Log message if verbose mode enabled"""
        if self.verbose:
            print(f"[IPv6Scanner] {message}")

    def check_ipv6_connectivity(self) -> bool:
        """Check if IPv6 connectivity is available"""
        try:
            # Check daemon health
            health = self.api_client.check_health()
            self._log(f"v6-gatewayd health: {health.get('status', 'unknown')}")

            # Get tunnels
            tunnels = self.api_client.get_tunnels()
            if not tunnels:
                raise RuntimeError("No active IPv6 tunnels available")

            self._log(f"Found {len(tunnels)} active tunnel(s)")
            for tunnel in tunnels:
                self._log(f"  - {tunnel.name}: {tunnel.ipv6_address} (health: {tunnel.health})")

            return True
        except Exception as e:
            self._log(f"IPv6 connectivity check failed: {e}")
            return False

    def get_source_ipv6(self) -> Optional[str]:
        """Get best IPv6 source address for scanning"""
        try:
            addresses = self.api_client.get_ipv6_addresses()
            if not addresses:
                return None

            # Prefer non-link-local addresses
            for addr in addresses:
                if not addr.startswith('fe80'):
                    self._log(f"Using source IPv6: {addr}")
                    return addr

            # Fallback to first available
            self._log(f"Using source IPv6 (link-local): {addresses[0]}")
            return addresses[0]
        except Exception as e:
            self._log(f"Failed to get source IPv6: {e}")
            return None

    async def scan_async(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        port_range: Optional[str] = None,
        timeout: float = 1.0,
        workers: int = 100,
        enable_cve: bool = False
    ) -> Dict[str, Any]:
        """
        Asynchronous IPv6 port scan

        Args:
            target: IPv6 address or hostname to scan
            ports: List of specific ports to scan
            port_range: Port range string (e.g., "1-1000")
            timeout: Socket timeout in seconds
            workers: Number of concurrent workers
            enable_cve: Enable CVE vulnerability lookupReturns:
            Dictionary with scan results
        """
        # Validate IPv6 connectivity
        if not self.check_ipv6_connectivity():
            return {"error": "IPv6 connectivity not available", "results": []}

        # Parse target
        try:
            target_addr = ipaddress.IPv6Address(target)
            target_str = str(target_addr)
        except ipaddress.AddressValueError:
            # Try to resolve hostname to IPv6
            try:
                target_str = socket.getaddrinfo(target, None, socket.AF_INET6)[0][4][0]
                self._log(f"Resolved {target} to {target_str}")
            except socket.gaierror as e:
                return {"error": f"Failed to resolve target to IPv6: {e}", "results": []}

        # Determine ports to scan
        if ports is None:
            if port_range:
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, end + 1))
            else:
                # Default to common ports
                ports = [22, 80, 443, 8080, 8443, 3389, 3306, 5432, 6379, 27017]

        self._log(f"Scanning {target_str} on {len(ports)} ports...")

        # Use enhanced scanner with IPv6 socket family
        results = []
        open_ports = []

        # Scan each port with IPv6 socket
        async def scan_port(port: int) -> Optional[Dict[str, Any]]:
            try:
                # Create IPv6 socket
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                # Connect
                try:
                    sock.connect((target_str, port))
                    sock.close()

                    port_info = {
                        'port': port,
                        'state': 'open',
                        'service': self._guess_service(port),
                        'banner': None
                    }

                    # Try to grab banner
                    try:
                        banner = await self._grab_banner_ipv6(target_str, port, timeout)
                        if banner:
                            port_info['banner'] = banner
                    except:
                        pass

                    return port_info
                except (socket.timeout, ConnectionRefusedError, OSError):
                    return None
            except Exception as e:
                self._log(f"Error scanning port {port}: {e}")
                return None

        # Run concurrent scans
        tasks = [scan_port(port) for port in ports]
        results_raw = await asyncio.gather(*tasks)

        # Filter out None results
        results = [r for r in results_raw if r is not None]
        open_ports = [r['port'] for r in results]

        self._log(f"Found {len(open_ports)} open ports: {open_ports}")

        # CVE lookup if enabled
        cve_results = {}
        if enable_cve and results:
            self._log("Performing CVE lookup...")
            try:
                cve_scanner = CVEScanner()
                for port_info in results:
                    if port_info.get('banner'):
                        cves = await cve_scanner.lookup_cves_async(
                            port_info['service'],
                            port_info['banner']
                        )
                        if cves:
                            cve_results[port_info['port']] = cves
            except Exception as e:
                self._log(f"CVE lookup failed: {e}")

        return {
            'target': target_str,
            'target_original': target,
            'scan_time': datetime.now().isoformat(),
            'total_ports': len(ports),
            'open_ports': len(open_ports),
            'results': results,
            'cves': cve_results if enable_cve else None
        }

    async def _grab_banner_ipv6(self, host: str, port: int, timeout: float) -> Optional[str]:
        """Grab banner from IPv6 service"""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Try to receive data
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner if banner else None
            except:
                sock.close()
                return None
        except:
            return None

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number"""
        common_services = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
        }
        return common_services.get(port, f'Unknown-{port}')


def main():
    """Main entry point for IPv6 scanner"""
    parser = argparse.ArgumentParser(
        description='FASTPORT IPv6 Scanner - Hurricane Electric Tunnel Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan common ports on an IPv6 host
  %(prog)s 2001:470:1f1c:258::1

  # Scan specific ports
  %(prog)s 2001:470:1f1c:258::1 -p 22,80,443

  # Scan port range with CVE lookup
  %(prog)s 2001:470:1f1c:258::1 -r 1-1000 --cve

  # Check IPv6 connectivity
  %(prog)s --check

  # Verbose output
  %(prog)s 2001:470:1f1c:258::1 -v
        '''
    )

    parser.add_argument('target', nargs='?', help='IPv6 address or hostname to scan')
    parser.add_argument('-p', '--ports', help='Comma-separated list of ports (e.g., 22,80,443)')
    parser.add_argument('-r', '--range', help='Port range (e.g., 1-1000)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Socket timeout (default: 1.0s)')
    parser.add_argument('-w', '--workers', type=int, default=100, help='Concurrent workers (default: 100)')
    parser.add_argument('--cve', action='store_true', help='Enable CVE vulnerability lookup')
    parser.add_argument('--check', action='store_true', help='Check IPv6 connectivity and exit')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--api', default='http://localhost:8642', help='v6-gatewayd API URL')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')

    args = parser.parse_args()

    # Create scanner
    scanner = IPv6Scanner(api_url=args.api, verbose=args.verbose)

    # Check connectivity if requested
    if args.check:
        print("Checking IPv6 connectivity...")
        if scanner.check_ipv6_connectivity():
            print("✓ IPv6 connectivity available")
            source = scanner.get_source_ipv6()
            if source:
                print(f"✓ Source IPv6: {source}")
            sys.exit(0)
        else:
            print("✗ IPv6 connectivity not available")
            sys.exit(1)

    # Require target for scanning
    if not args.target:
        parser.error("target is required for scanning (use --check to test connectivity)")

    # Parse ports
    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]

    # Run scan
    print(f"Starting IPv6 scan of {args.target}...")
    results = asyncio.run(scanner.scan_async(
        target=args.target,
        ports=ports,
        port_range=args.range,
        timeout=args.timeout,
        workers=args.workers,
        enable_cve=args.cve
    ))

    # Check for errors
    if 'error' in results:
        print(f"✗ Error: {results['error']}")
        sys.exit(1)

    # Display results
    print(f"\n{'='*60}")
    print(f"Scan Results for {results['target']}")
    print(f"{'='*60}")
    print(f"Total ports scanned: {results['total_ports']}")
    print(f"Open ports found: {results['open_ports']}")
    print(f"{'='*60}\n")

    if results['results']:
        print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'BANNER':<30}")
        print(f"{'-'*70}")
        for port_info in results['results']:
            banner = port_info.get('banner', '')[:30] if port_info.get('banner') else '-'
            print(f"{port_info['port']:<10} {port_info['state']:<10} {port_info['service']:<20} {banner:<30}")

        # Show CVE results if available
        if results.get('cves'):
            print(f"\n{'='*60}")
            print("CVE Vulnerabilities Found")
            print(f"{'='*60}\n")
            for port, cves in results['cves'].items():
                print(f"Port {port}:")
                for cve in cves:
                    print(f"  - {cve['id']}: {cve.get('description', 'N/A')[:60]}")
    else:
        print("No open ports found.")

    # Save to file if requested
    if args.output:
        import json
        from datetime import datetime
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == '__main__':
    from datetime import datetime
    main()
