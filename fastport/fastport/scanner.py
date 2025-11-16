#!/usr/bin/env python3
"""
GPU Cluster Enhanced Port Scanner
Performs targeted port scanning on detected GPU clusters for CVE analysis
Features:
- Async scanning with asyncio for maximum performance
- Masscan integration for ultra-fast scanning
- Configurable port ranges (1-65535)
- Service detection and banner grabbing
"""

import socket
import json
import argparse
import concurrent.futures
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import ssl
import re
import asyncio
import subprocess
import shutil
from pathlib import Path


# Common GPU/HPC/ML service ports
GPU_CLUSTER_PORTS = {
    # Jupyter
    8888: 'Jupyter Notebook/Lab',
    8889: 'Jupyter Notebook (alt)',

    # Ray
    6379: 'Redis (Ray)',
    6380: 'Redis (alt)',
    8265: 'Ray Dashboard',
    8000: 'Ray Serve',
    10001: 'Ray GCS Server',

    # ML Frameworks
    6006: 'TensorBoard',
    5000: 'MLflow',
    4040: 'Spark UI',
    8080: 'Spark Master UI',
    8081: 'Spark Worker UI',

    # Workflow Management
    8793: 'Airflow Webserver',
    5555: 'Airflow Flower',
    8888: 'Dask Dashboard',

    # Container Orchestration
    8001: 'Kubernetes Dashboard',
    10250: 'Kubelet',
    6443: 'Kubernetes API',

    # HPC/Job Schedulers
    6817: 'SLURM slurmctld',
    6818: 'SLURM slurmdbd',

    # Monitoring
    9090: 'Prometheus',
    3000: 'Grafana',
    9100: 'Node Exporter',
    9200: 'Elasticsearch',
    5601: 'Kibana',

    # Remote Access
    22: 'SSH',
    3389: 'RDP',
    5900: 'VNC',

    # Web Interfaces
    80: 'HTTP',
    443: 'HTTPS',
    8000: 'HTTP (alt)',
    8080: 'HTTP (alt 2)',
    8443: 'HTTPS (alt)',

    # Database
    3306: 'MySQL',
    5432: 'PostgreSQL',
    27017: 'MongoDB',
    6379: 'Redis',

    # Message Queues
    5672: 'RabbitMQ',
    9092: 'Kafka',
}

# Extended common ports for wider scanning
COMMON_PORTS = {
    **GPU_CLUSTER_PORTS,  # Include all GPU/HPC ports
    21: 'FTP',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    110: 'POP3',
    111: 'RPCbind',
    135: 'MS-RPC',
    139: 'NetBIOS',
    143: 'IMAP',
    445: 'SMB',
    465: 'SMTPS',
    587: 'SMTP Submission',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MS SQL Server',
    1521: 'Oracle',
    2049: 'NFS',
    2375: 'Docker',
    2376: 'Docker TLS',
    3000: 'Grafana',
    3128: 'Squid Proxy',
    3306: 'MySQL',
    3389: 'RDP',
    4369: 'Erlang',
    5000: 'Flask/MLflow',
    5432: 'PostgreSQL',
    5601: 'Kibana',
    5672: 'RabbitMQ',
    5900: 'VNC',
    6379: 'Redis',
    6443: 'Kubernetes API',
    7001: 'Cassandra',
    8000: 'HTTP Alt',
    8008: 'HTTP Alt',
    8080: 'HTTP Proxy',
    8443: 'HTTPS Alt',
    8888: 'Jupyter',
    9000: 'SonarQube',
    9090: 'Prometheus',
    9200: 'Elasticsearch',
    9300: 'Elasticsearch Transport',
    10000: 'Webmin',
    11211: 'Memcached',
    27017: 'MongoDB',
    50000: 'SAP',
}

# Top 1000 most common ports (nmap top-ports style)
TOP_1000_PORTS = list(range(1, 1001))


@dataclass
class ServiceDetection:
    """Detected service on a port"""
    port: int
    state: str  # open, closed, filtered
    service_name: str
    banner: Optional[str] = None
    version: Optional[str] = None
    ssl_enabled: bool = False


@dataclass
class EnhancedAsset:
    """Asset with enhanced port scan results"""
    hostname: str
    university: str
    gpu_confidence: str
    detected_services: List[ServiceDetection]
    total_open_ports: int
    high_risk_services: List[str]
    scan_timestamp: str
    gpu_cluster_detected: bool = False  # NEW: Flag indicating GPU cluster detection


def extract_service_version(banner: str, port: int, service_name: str) -> Optional[str]:
    """
    Extract service version from banner for CVE analysis

    Args:
        banner: Service banner text
        port: Port number
        service_name: Service name

    Returns:
        Version string if detected, None otherwise
    """
    if not banner:
        return None

    banner_lower = banner.lower()

    # SSH version detection
    if 'ssh' in service_name.lower() or port == 22:
        match = re.search(r'ssh[_-](\d+\.\d+(?:\.\d+)?)', banner_lower)
        if match:
            return match.group(1)
        # OpenSSH specific
        match = re.search(r'openssh[_-](\d+\.\d+(?:p\d+)?)', banner_lower)
        if match:
            return f"OpenSSH {match.group(1)}"

    # HTTP/Web server version detection
    if port in [80, 443, 8080, 8443, 8000] or 'http' in service_name.lower():
        # Apache
        match = re.search(r'apache[/\s](\d+\.\d+\.\d+)', banner_lower)
        if match:
            return f"Apache {match.group(1)}"
        # Nginx
        match = re.search(r'nginx[/\s](\d+\.\d+\.\d+)', banner_lower)
        if match:
            return f"nginx {match.group(1)}"
        # Generic HTTP version
        match = re.search(r'http/(\d+\.\d+)', banner_lower)
        if match:
            return f"HTTP {match.group(1)}"

    # Redis version detection
    if 'redis' in service_name.lower() or port in [6379, 6380]:
        match = re.search(r'redis_version:(\d+\.\d+\.\d+)', banner_lower)
        if match:
            return f"Redis {match.group(1)}"

    # MySQL version detection
    if 'mysql' in service_name.lower() or port == 3306:
        match = re.search(r'(\d+\.\d+\.\d+)', banner)
        if match:
            return f"MySQL {match.group(1)}"

    # PostgreSQL version detection
    if 'postgres' in service_name.lower() or port == 5432:
        match = re.search(r'postgresql\s+(\d+\.\d+)', banner_lower)
        if match:
            return f"PostgreSQL {match.group(1)}"

    # Jupyter version detection
    if 'jupyter' in service_name.lower() or port in [8888, 8889]:
        match = re.search(r'jupyter[_/\s]+(\d+\.\d+\.\d+)', banner_lower)
        if match:
            return f"Jupyter {match.group(1)}"

    # Kubernetes version detection
    if 'kubernetes' in service_name.lower() or port == 6443:
        match = re.search(r'v(\d+\.\d+\.\d+)', banner)
        if match:
            return f"Kubernetes {match.group(1)}"

    # Elasticsearch version detection
    if 'elasticsearch' in service_name.lower() or port == 9200:
        match = re.search(r'"number"\s*:\s*"(\d+\.\d+\.\d+)"', banner)
        if match:
            return f"Elasticsearch {match.group(1)}"

    # Generic version pattern (e.g., "service/1.2.3")
    match = re.search(r'(\d+\.\d+\.\d+)', banner)
    if match:
        return match.group(1)

    return None


def is_gpu_cluster_port(port: int) -> bool:
    """
    Check if a port indicates a GPU cluster service

    Args:
        port: Port number

    Returns:
        True if port is associated with GPU/HPC/ML services
    """
    gpu_cluster_indicators = {
        6443,  # Kubernetes API
        8888, 8889,  # Jupyter
        6379,  # Redis (Ray)
        8265,  # Ray Dashboard
        6006,  # TensorBoard
        5000,  # MLflow
        6817, 6818,  # SLURM
        10250,  # Kubelet
        9090,  # Prometheus (common in ML clusters)
    }
    return port in gpu_cluster_indicators


class AsyncPortScanner:
    """
    High-performance async port scanner using asyncio
    Much faster than thread-based scanning for I/O-bound operations
    """

    def __init__(self, timeout: float = 1.0, max_concurrent: int = 500):
        """
        Initialize async scanner

        Args:
            timeout: Connection timeout in seconds
            max_concurrent: Maximum concurrent connections
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent

    async def scan_port(self, hostname: str, port: int, semaphore: asyncio.Semaphore, enhanced_banner: bool = False) -> Optional[ServiceDetection]:
        """
        Async scan a single port with optional enhanced banner grabbing

        Args:
            hostname: Target hostname
            port: Port to scan
            semaphore: Semaphore to limit concurrency
            enhanced_banner: If True, use service-specific probes for better version detection

        Returns:
            ServiceDetection if port is open, None otherwise
        """
        async with semaphore:
            try:
                # Attempt async connection
                conn = asyncio.open_connection(hostname, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

                # Port is open
                service_name = COMMON_PORTS.get(port, f'Unknown ({port})')
                banner = None
                version = None

                # Try to grab banner with service-specific probes
                try:
                    if enhanced_banner:
                        banner = await self._enhanced_banner_grab(reader, writer, port, hostname)
                    else:
                        # Basic HTTP probe
                        writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
                        await writer.drain()
                        banner_data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                        banner = banner_data.decode('utf-8', errors='ignore').strip()[:500]

                    # Extract version from banner
                    if banner:
                        version = extract_service_version(banner, port, service_name)
                except:
                    pass

                writer.close()
                await writer.wait_closed()

                return ServiceDetection(
                    port=port,
                    state='open',
                    service_name=service_name,
                    banner=banner,
                    version=version,
                    ssl_enabled=False  # SSL detection is expensive, skip for speed
                )

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None

    async def _enhanced_banner_grab(self, reader, writer, port: int, hostname: str) -> Optional[str]:
        """
        Service-specific banner grabbing for better version detection

        Args:
            reader: Async stream reader
            writer: Async stream writer
            port: Port number
            hostname: Target hostname

        Returns:
            Banner string if successful, None otherwise
        """
        try:
            # SSH (22)
            if port == 22:
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                return banner_data.decode('utf-8', errors='ignore').strip()[:500]

            # HTTP/HTTPS (80, 443, 8080, 8443, 8000, etc.)
            elif port in [80, 443, 8080, 8443, 8000, 8008, 8888]:
                writer.write(b'GET / HTTP/1.1\r\nHost: ' + hostname.encode() + b'\r\nUser-Agent: Mozilla/5.0\r\n\r\n')
                await writer.drain()
                banner_data = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                return banner_data.decode('utf-8', errors='ignore').strip()[:1000]

            # Redis (6379, 6380)
            elif port in [6379, 6380]:
                writer.write(b'INFO\r\n')
                await writer.drain()
                banner_data = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                return banner_data.decode('utf-8', errors='ignore').strip()[:1000]

            # Elasticsearch (9200)
            elif port == 9200:
                writer.write(b'GET / HTTP/1.1\r\nHost: ' + hostname.encode() + b'\r\n\r\n')
                await writer.drain()
                banner_data = await asyncio.wait_for(reader.read(2048), timeout=1.0)
                return banner_data.decode('utf-8', errors='ignore').strip()[:1000]

            # MySQL (3306)
            elif port == 3306:
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                return banner_data.decode('utf-8', errors='ignore').strip()[:500]

            # PostgreSQL (5432)
            elif port == 5432:
                # PostgreSQL startup message
                writer.write(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
                await writer.drain()
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                return banner_data.decode('utf-8', errors='ignore').strip()[:500]

            # Default: just read what's available
            else:
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                return banner_data.decode('utf-8', errors='ignore').strip()[:500]

        except Exception:
            return None

    async def scan_host_async(self, hostname: str, ports: List[int], enhanced_banner: bool = False) -> List[ServiceDetection]:
        """
        Async scan multiple ports on a host

        Args:
            hostname: Target hostname
            ports: List of ports to scan
            enhanced_banner: If True, use enhanced banner grabbing for version detection

        Returns:
            List of ServiceDetection for open ports
        """
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [self.scan_port(hostname, port, semaphore, enhanced_banner) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out None and exceptions
        return [r for r in results if isinstance(r, ServiceDetection)]

    def scan_host(self, hostname: str, ports: List[int]) -> List[ServiceDetection]:
        """
        Synchronous wrapper for async scanning

        Args:
            hostname: Target hostname
            ports: List of ports to scan

        Returns:
            List of ServiceDetection for open ports
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.scan_host_async(hostname, ports))


class MasscanScanner:
    """
    Ultra-fast port scanner using masscan
    Requires masscan to be installed: apt-get install masscan
    Can scan 1000s of ports in seconds
    """

    def __init__(self, rate: int = 10000):
        """
        Initialize masscan scanner

        Args:
            rate: Packets per second (default 10000)
        """
        self.rate = rate
        self.masscan_available = shutil.which('masscan') is not None

    def is_available(self) -> bool:
        """Check if masscan is installed"""
        return self.masscan_available

    def scan_host(self, hostname: str, ports: List[int]) -> List[ServiceDetection]:
        """
        Scan host using masscan

        Args:
            hostname: Target hostname
            ports: List of ports to scan

        Returns:
            List of ServiceDetection for open ports
        """
        if not self.masscan_available:
            return []

        try:
            # Build port range string
            port_str = ','.join(map(str, ports))

            # Run masscan
            cmd = [
                'masscan',
                hostname,
                '-p', port_str,
                '--rate', str(self.rate),
                '--open-only',
                '--output-format', 'json',
                '--output-filename', '-'  # Output to stdout
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                return []

            # Parse masscan JSON output
            open_ports = []
            for line in result.stdout.strip().split('\n'):
                if not line or line.startswith('#'):
                    continue
                try:
                    data = json.loads(line)
                    port = data.get('ports', [{}])[0].get('port')
                    if port:
                        service_name = COMMON_PORTS.get(port, f'Unknown ({port})')
                        open_ports.append(ServiceDetection(
                            port=port,
                            state='open',
                            service_name=service_name,
                            banner=None,
                            ssl_enabled=False
                        ))
                except json.JSONDecodeError:
                    continue

            return sorted(open_ports, key=lambda x: x.port)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []


class GPUPortScanner:
    """
    Enhanced port scanner for GPU cluster assets
    Supports multiple scanning backends:
    - 'async': Fast async scanning with asyncio (default, 10-50x faster than threads)
    - 'masscan': Ultra-fast masscan (100x faster, requires masscan installed)
    - 'thread': Legacy thread-based scanning (slower, more compatible)
    """

    def __init__(self,
                 timeout: float = 1.0,
                 threads: int = 10,
                 scanner_mode: str = 'async',
                 port_range: str = 'gpu',
                 max_concurrent: int = 500):
        """
        Initialize scanner

        Args:
            timeout: Connection timeout in seconds
            threads: Number of threads (for thread mode)
            scanner_mode: 'async', 'masscan', or 'thread'
            port_range: 'gpu' (default 80 ports), 'common' (150 ports),
                       'top1000' (1-1000), 'all' (1-65535), or 'custom:1-1000'
            max_concurrent: Max concurrent connections (async mode)
        """
        self.timeout = timeout
        self.threads = threads
        self.scanner_mode = scanner_mode
        self.max_concurrent = max_concurrent
        self.results: List[EnhancedAsset] = []

        # Parse port range
        self.ports = self._parse_port_range(port_range)

        # Initialize scanners
        self.async_scanner = AsyncPortScanner(timeout=timeout, max_concurrent=max_concurrent)
        self.masscan_scanner = MasscanScanner(rate=10000)

        # Check scanner availability
        if scanner_mode == 'masscan' and not self.masscan_scanner.is_available():
            print("[!] Masscan not found, falling back to async scanner")
            self.scanner_mode = 'async'

    def _parse_port_range(self, port_range: str) -> List[int]:
        """
        Parse port range specification

        Args:
            port_range: Port range string

        Returns:
            List of ports to scan
        """
        if port_range == 'gpu':
            return list(GPU_CLUSTER_PORTS.keys())
        elif port_range == 'common':
            return sorted(set(COMMON_PORTS.keys()))
        elif port_range == 'top1000':
            return list(range(1, 1001))
        elif port_range == 'all':
            return list(range(1, 65536))
        elif port_range.startswith('custom:'):
            # Parse custom range like 'custom:1-1000' or 'custom:80,443,8080'
            range_spec = port_range.split(':', 1)[1]
            ports = []
            for part in range_spec.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
            return sorted(set(ports))
        else:
            print(f"[!] Unknown port range '{port_range}', using GPU ports")
            return list(GPU_CLUSTER_PORTS.keys())

    def scan_port(self, hostname: str, port: int) -> Optional[ServiceDetection]:
        """
        Scan a single port and attempt service detection

        Args:
            hostname: Target hostname
            port: Port number to scan

        Returns:
            ServiceDetection if port is open, None otherwise
        """
        try:
            # Attempt connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((hostname, port))

            if result == 0:  # Port is open
                service_name = GPU_CLUSTER_PORTS.get(port, f'Unknown ({port})')
                banner = None
                ssl_enabled = False

                # Try to grab banner
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner_data = sock.recv(1024)
                    banner = banner_data.decode('utf-8', errors='ignore').strip()[:200]
                except:
                    pass

                # Check if SSL/TLS is available
                if port in [443, 8443, 6443]:
                    try:
                        context = ssl.create_default_context()
                        with context.wrap_socket(sock, server_hostname=hostname):
                            ssl_enabled = True
                    except:
                        pass

                sock.close()

                return ServiceDetection(
                    port=port,
                    state='open',
                    service_name=service_name,
                    banner=banner,
                    ssl_enabled=ssl_enabled
                )
            else:
                sock.close()
                return None

        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception as e:
            print(f"[!] Error scanning {hostname}:{port} - {e}")
            return None

    def scan_host(self, hostname: str, university: str, confidence: str) -> EnhancedAsset:
        """
        Scan all configured ports on a host using selected scanner
        If GPU cluster is detected, automatically perform extended scan with enhanced banner grabbing

        Args:
            hostname: Target hostname
            university: University name
            confidence: GPU detection confidence

        Returns:
            EnhancedAsset with scan results
        """
        print(f"\n[*] Scanning {hostname} ({university})")
        print(f"[*] Mode: {self.scanner_mode}, Ports: {len(self.ports)}")

        detected_services = []
        high_risk_services = []
        gpu_cluster_detected = False

        # Initial scan with configured ports
        if self.scanner_mode == 'masscan':
            print(f"[*] Using masscan (ultra-fast)")
            detected_services = self.masscan_scanner.scan_host(hostname, self.ports)

        elif self.scanner_mode == 'async':
            print(f"[*] Using async scanner (fast)")
            detected_services = self.async_scanner.scan_host(hostname, self.ports)

        else:  # thread mode (legacy)
            print(f"[*] Using thread scanner (legacy)")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self.scan_port, hostname, port): port
                    for port in self.ports
                }

                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        detected_services.append(result)

        # Check if GPU cluster ports are detected
        open_ports = {service.port for service in detected_services}
        gpu_cluster_detected = any(is_gpu_cluster_port(port) for port in open_ports)

        # If GPU cluster detected, perform extended scan on common ports with enhanced banner grabbing
        if gpu_cluster_detected and self.scanner_mode == 'async':
            print(f"[!] GPU cluster detected! Performing extended scan on common ports...")

            # Get common ports that weren't in the initial scan
            extended_ports = sorted(set(COMMON_PORTS.keys()) - open_ports)

            if extended_ports:
                print(f"[*] Scanning {len(extended_ports)} additional ports with enhanced banner grabbing...")
                # Use enhanced banner grabbing for version detection
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                extended_services = loop.run_until_complete(
                    self.async_scanner.scan_host_async(hostname, extended_ports, enhanced_banner=True)
                )

                detected_services.extend(extended_services)
                print(f"[+] Extended scan found {len(extended_services)} additional open ports")

        # Flag high-risk services
        for service in detected_services:
            if service.port in [22, 3389, 5900]:  # Remote access
                high_risk_services.append(f"{service.service_name} (Remote Access)")
            elif service.port in [8888, 8265, 6006, 5000]:  # ML interfaces
                high_risk_services.append(f"{service.service_name} (ML Interface)")
            elif service.port in [6379, 27017, 3306, 5432]:  # Databases
                high_risk_services.append(f"{service.service_name} (Database)")

        # Sort by port number
        detected_services.sort(key=lambda x: x.port)

        print(f"[+] Found {len(detected_services)} total open ports")
        if high_risk_services:
            print(f"[!] High-risk services: {len(high_risk_services)}")

        # Count services with detected versions
        versioned_services = [s for s in detected_services if s.version]
        if versioned_services:
            print(f"[+] Detected versions for {len(versioned_services)} services (ready for CVE analysis)")

        return EnhancedAsset(
            hostname=hostname,
            university=university,
            gpu_confidence=confidence,
            detected_services=detected_services,
            total_open_ports=len(detected_services),
            high_risk_services=high_risk_services,
            scan_timestamp=datetime.now().isoformat(),
            gpu_cluster_detected=gpu_cluster_detected
        )

    def scan_from_gpu_report(self, gpu_json_path: str, confidence_filter: str = "HIGH") -> List[EnhancedAsset]:
        """
        Scan hosts from GPU cluster analysis report

        Args:
            gpu_json_path: Path to GPU cluster analysis JSON
            confidence_filter: Only scan hosts with this confidence or higher (HIGH, MEDIUM, LOW)

        Returns:
            List of EnhancedAsset with scan results
        """
        # Load GPU analysis
        try:
            with open(gpu_json_path, 'r') as f:
                gpu_data = json.load(f)
        except Exception as e:
            print(f"[!] Error loading GPU report: {e}")
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

        print(f"\n[+] Found {len(targets)} GPU clusters to scan (confidence >= {confidence_filter})")

        # Scan each target
        self.results = []
        for target in targets:
            result = self.scan_host(
                target['hostname'],
                target['university'],
                target['confidence']
            )
            self.results.append(result)

        return self.results

    def generate_report(self, output_file: str):
        """Generate enhanced port scan report"""
        report = {
            'metadata': {
                'scan_timestamp': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'total_hosts_scanned': len(self.results)
            },
            'summary': {
                'total_open_ports': sum(r.total_open_ports for r in self.results),
                'hosts_with_high_risk_services': sum(1 for r in self.results if r.high_risk_services),
                'total_high_risk_services': sum(len(r.high_risk_services) for r in self.results)
            },
            'scanned_hosts': [
                {
                    'hostname': r.hostname,
                    'university': r.university,
                    'gpu_confidence': r.gpu_confidence,
                    'total_open_ports': r.total_open_ports,
                    'high_risk_services': r.high_risk_services,
                    'detected_services': [
                        {
                            'port': s.port,
                            'service': s.service_name,
                            'banner': s.banner,
                            'ssl_enabled': s.ssl_enabled
                        }
                        for s in r.detected_services
                    ],
                    'scan_timestamp': r.scan_timestamp
                }
                for r in self.results
            ]
        }

        # Save JSON
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Enhanced port scan report saved: {output_file}")

        # Generate markdown summary
        self._generate_markdown_summary(output_file.replace('.json', '_summary.md'))

    def _generate_markdown_summary(self, output_file: str):
        """Generate markdown summary report"""
        md = f"""# GPU Cluster Enhanced Port Scan Report

**Generated:** {datetime.now().isoformat()}
**Hosts Scanned:** {len(self.results)}

## Summary

- **Total Open Ports:** {sum(r.total_open_ports for r in self.results)}
- **Hosts with High-Risk Services:** {sum(1 for r in self.results if r.high_risk_services)}
- **Total High-Risk Services:** {sum(len(r.high_risk_services) for r in self.results)}

---

## Scanned Hosts

"""

        for result in sorted(self.results, key=lambda x: len(x.high_risk_services), reverse=True):
            md += f"### {result.hostname}\n\n"
            md += f"- **University:** {result.university}\n"
            md += f"- **GPU Confidence:** {result.gpu_confidence}\n"
            md += f"- **Open Ports:** {result.total_open_ports}\n"

            if result.high_risk_services:
                md += f"\n**⚠️ High-Risk Services:**\n"
                for service in result.high_risk_services:
                    md += f"- {service}\n"

            md += f"\n**Detected Services:**\n\n"
            md += "| Port | Service | SSL | Banner |\n"
            md += "|------|---------|-----|--------|\n"

            for service in result.detected_services:
                ssl_icon = "✓" if service.ssl_enabled else "✗"
                banner = service.banner[:50] + "..." if service.banner and len(service.banner) > 50 else (service.banner or "-")
                md += f"| {service.port} | {service.service_name} | {ssl_icon} | {banner} |\n"

            md += "\n---\n\n"

        md += """
## Recommendations

1. **Immediate Actions:**
   - Review all high-risk services (SSH, RDP, VNC, databases)
   - Ensure strong authentication on ML interfaces (Jupyter, Ray, TensorBoard)
   - Restrict access to management interfaces

2. **Security Hardening:**
   - Implement firewall rules to limit exposure
   - Use VPN for remote access services
   - Enable SSL/TLS on all web interfaces
   - Monitor access logs for suspicious activity

3. **CVE Analysis:**
   - Run CVE lookup against all detected services
   - Prioritize patching for publicly exposed services
   - Review vendor security advisories

---

*This scan identified services running on GPU cluster infrastructure for security assessment*
"""

        with open(output_file, 'w') as f:
            f.write(md)

        print(f"[+] Markdown summary saved: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='GPU Cluster Enhanced Port Scanner - Fast, Scalable, Multi-mode',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fast async scan of HIGH confidence GPU clusters (default)
  %(prog)s gpu_cluster_analysis.json

  # Ultra-fast masscan (requires masscan installed)
  %(prog)s gpu_cluster_analysis.json --mode masscan

  # Scan wider port range (top 1000 common ports)
  %(prog)s gpu_cluster_analysis.json --ports top1000

  # Scan ALL ports (1-65535) - takes longer!
  %(prog)s gpu_cluster_analysis.json --ports all --mode async

  # Custom port range
  %(prog)s gpu_cluster_analysis.json --ports custom:1-1000,8000-9000

  # Extended common ports (150 ports)
  %(prog)s gpu_cluster_analysis.json --ports common

  # Scan MEDIUM and HIGH confidence clusters
  %(prog)s gpu_cluster_analysis.json --confidence MEDIUM

  # Maximum concurrency for faster async scanning
  %(prog)s gpu_cluster_analysis.json --concurrent 1000 --ports top1000

Scanner Modes:
  async    - Async I/O scanner (10-50x faster than threads, default)
  masscan  - Ultra-fast masscan (100x faster, requires root/masscan)
  thread   - Legacy thread-based (slower, more compatible)

Port Ranges:
  gpu      - GPU/HPC/ML focused ports (~80 ports, default)
  common   - Common service ports (~150 ports)
  top1000  - Top 1000 most common ports (1-1000)
  all      - All ports (1-65535, slow!)
  custom:X - Custom range: 'custom:1-1000' or 'custom:80,443,8080-8090'
        """
    )

    parser.add_argument('gpu_json', help='GPU cluster analysis JSON file')
    parser.add_argument('-c', '--confidence',
                       choices=['HIGH', 'MEDIUM', 'LOW'],
                       default='HIGH',
                       help='Minimum confidence level to scan (default: HIGH)')
    parser.add_argument('-o', '--output',
                       help='Output file for scan results')
    parser.add_argument('-m', '--mode',
                       choices=['async', 'masscan', 'thread'],
                       default='async',
                       help='Scanner mode: async (default), masscan, or thread')
    parser.add_argument('-p', '--ports',
                       default='gpu',
                       help='Port range: gpu (default), common, top1000, all, or custom:X')
    parser.add_argument('-t', '--threads',
                       type=int,
                       default=10,
                       help='Number of parallel threads for thread mode (default: 10)')
    parser.add_argument('--concurrent',
                       type=int,
                       default=500,
                       help='Max concurrent connections for async mode (default: 500)')
    parser.add_argument('--timeout',
                       type=float,
                       default=1.0,
                       help='Socket timeout in seconds (default: 1.0)')

    args = parser.parse_args()

    # Default output file
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"gpu_port_scan_{timestamp}.json"

    print("="*70)
    print("GPU Cluster Enhanced Port Scanner - FAST MODE")
    print("="*70)
    print(f"\nConfiguration:")
    print(f"  GPU Report: {args.gpu_json}")
    print(f"  Scanner Mode: {args.mode}")
    print(f"  Port Range: {args.ports}")
    print(f"  Confidence Filter: {args.confidence}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Output: {args.output}")
    if args.mode == 'async':
        print(f"  Max Concurrent: {args.concurrent}")
    elif args.mode == 'thread':
        print(f"  Threads: {args.threads}")

    # Create scanner
    scanner = GPUPortScanner(
        timeout=args.timeout,
        threads=args.threads,
        scanner_mode=args.mode,
        port_range=args.ports,
        max_concurrent=args.concurrent
    )

    # Scan targets
    results = scanner.scan_from_gpu_report(args.gpu_json, args.confidence)

    if results:
        # Generate report
        scanner.generate_report(args.output)

        print(f"\n[+] Scan complete!")
        print(f"[+] Scanned {len(results)} GPU clusters")
        print(f"[+] Found {sum(r.total_open_ports for r in results)} open ports")

        high_risk = sum(len(r.high_risk_services) for r in results)
        if high_risk > 0:
            print(f"[!] WARNING: {high_risk} high-risk services detected")
    else:
        print("\n[!] No GPU clusters found matching criteria")

    return 0


if __name__ == "__main__":
    exit(main())
