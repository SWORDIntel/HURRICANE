#!/usr/bin/env python3
"""
Cisco AnyConnect VPN Endpoint Tester

Tests for default/weak credentials on detected Cisco AnyConnect VPN endpoints.
For authorized security testing only.

WARNING: Only use this against systems you have explicit authorization to test.
"""

import requests
import urllib3
from typing import Optional, Dict, List, Tuple
import re
import json
from dataclasses import dataclass, asdict
import ssl

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class AnyConnectEndpoint:
    """Detected Cisco AnyConnect endpoint"""
    url: str
    version: Optional[str] = None
    server_info: Optional[str] = None
    detected: bool = False


@dataclass
class CredentialTestResult:
    """Result of credential testing"""
    endpoint: str
    username: str
    password: str
    success: bool
    response_code: int
    response_message: str
    auth_method: str
    session_token: Optional[str] = None
    additional_info: Dict = None


class AnyConnectTester:
    """
    Cisco AnyConnect VPN endpoint detector and credential tester

    Features:
    - Detects AnyConnect endpoints on common ports (443, 8443)
    - Tests default credentials (test:test and others)
    - Tests weak/common credentials
    - Extracts version information
    """

    # Common AnyConnect URL paths
    ANYCONNECT_PATHS = [
        '/',
        '/+CSCOE+/logon.html',
        '/+CSCOE+/login.html',
        '/vpn/index.html',
        '/vpn/login.html',
        '/vpn/',
    ]

    # Common default/weak credentials to test
    DEFAULT_CREDENTIALS = [
        ('test', 'test'),
        ('admin', 'admin'),
        ('cisco', 'cisco'),
        ('vpn', 'vpn'),
        ('guest', 'guest'),
        ('demo', 'demo'),
        ('user', 'user'),
        ('admin', 'password'),
        ('admin', ''),
        ('', ''),
    ]

    # AnyConnect detection patterns
    DETECTION_PATTERNS = [
        rb'Cisco AnyConnect',
        rb'CSCOE',
        rb'webvpn',
        rb'WebVPN',
        rb'/+CSCOE+/',
        rb'CiscoSecureDesktop',
        rb'Cisco Systems, Inc',
        rb'anyconnect',
    ]

    def __init__(self, timeout: int = 5, verbose: bool = False):
        """
        Initialize AnyConnect tester

        Args:
            timeout: HTTP request timeout in seconds
            verbose: Enable verbose output
        """
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False  # For testing self-signed certs
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def _vprint(self, message: str):
        """Print if verbose mode enabled"""
        if self.verbose:
            print(message)

    def detect_anyconnect(self, hostname: str, port: int = 443) -> Optional[AnyConnectEndpoint]:
        """
        Detect if a host is running Cisco AnyConnect VPN

        Args:
            hostname: Target hostname or IP
            port: Port to check (default: 443)

        Returns:
            AnyConnectEndpoint if detected, None otherwise
        """
        base_url = f"https://{hostname}:{port}"

        for path in self.ANYCONNECT_PATHS:
            url = f"{base_url}{path}"

            try:
                self._vprint(f"[*] Checking {url}")
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)

                # Check response content for AnyConnect patterns
                content = response.content

                for pattern in self.DETECTION_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        self._vprint(f"[+] AnyConnect detected at {url}")

                        # Extract version if possible
                        version = self._extract_version(content, response.headers)
                        server_info = response.headers.get('Server', 'Unknown')

                        return AnyConnectEndpoint(
                            url=url,
                            version=version,
                            server_info=server_info,
                            detected=True
                        )

            except requests.exceptions.RequestException as e:
                self._vprint(f"[-] Error checking {url}: {e}")
                continue

        return None

    def _extract_version(self, content: bytes, headers: Dict) -> Optional[str]:
        """Extract AnyConnect version from response"""
        try:
            content_str = content.decode('utf-8', errors='ignore')

            # Try various version patterns
            patterns = [
                r'AnyConnect\s+(\d+\.\d+\.\d+)',
                r'Version\s+(\d+\.\d+\.\d+)',
                r'webvpn_version\s*=\s*["\']([^"\']+)["\']',
                r'CSCOE\s+(\d+\.\d+)',
            ]

            for pattern in patterns:
                match = re.search(pattern, content_str, re.IGNORECASE)
                if match:
                    return match.group(1)

            # Check headers
            server = headers.get('Server', '')
            if 'AnyConnect' in server or 'CSCOE' in server:
                version_match = re.search(r'(\d+\.\d+\.\d+)', server)
                if version_match:
                    return version_match.group(1)

        except Exception:
            pass

        return None

    def test_credentials(self, endpoint: AnyConnectEndpoint,
                        credentials: List[Tuple[str, str]] = None,
                        test_defaults: bool = True) -> List[CredentialTestResult]:
        """
        Test credentials against AnyConnect endpoint

        Args:
            endpoint: AnyConnectEndpoint to test
            credentials: List of (username, password) tuples to test
            test_defaults: Whether to test default credentials

        Returns:
            List of CredentialTestResult
        """
        results = []

        # Determine which credentials to test
        creds_to_test = []
        if test_defaults:
            creds_to_test.extend(self.DEFAULT_CREDENTIALS)
        if credentials:
            creds_to_test.extend(credentials)

        # Remove duplicates
        creds_to_test = list(set(creds_to_test))

        self._vprint(f"\n[*] Testing {len(creds_to_test)} credential pairs against {endpoint.url}")

        for username, password in creds_to_test:
            self._vprint(f"[*] Testing {username}:{password}")

            result = self._test_single_credential(endpoint, username, password)
            results.append(result)

            if result.success:
                self._vprint(f"[!] SUCCESS: {username}:{password} - {result.response_message}")
            else:
                self._vprint(f"[-] Failed: {username}:{password}")

        return results

    def _test_single_credential(self, endpoint: AnyConnectEndpoint,
                                username: str, password: str) -> CredentialTestResult:
        """
        Test a single credential pair

        Args:
            endpoint: AnyConnect endpoint
            username: Username to test
            password: Password to test

        Returns:
            CredentialTestResult
        """
        # Try different authentication methods
        auth_methods = [
            self._test_form_auth,
            self._test_basic_auth,
            self._test_xml_auth,
        ]

        for auth_method in auth_methods:
            try:
                result = auth_method(endpoint, username, password)
                if result:
                    return result
            except Exception as e:
                self._vprint(f"[!] Exception in {auth_method.__name__}: {e}")

        # All methods failed
        return CredentialTestResult(
            endpoint=endpoint.url,
            username=username,
            password=password,
            success=False,
            response_code=0,
            response_message="All authentication methods failed",
            auth_method="none"
        )

    def _test_form_auth(self, endpoint: AnyConnectEndpoint,
                       username: str, password: str) -> Optional[CredentialTestResult]:
        """Test form-based authentication"""
        # Common AnyConnect login endpoints
        login_paths = [
            '/+webvpn+/index.html',
            '/+CSCOE+/logon.html',
            '/vpn/login.html',
        ]

        base_url = endpoint.url.rsplit('/', 1)[0]  # Remove path, keep base

        for path in login_paths:
            url = f"{base_url}{path}"

            try:
                # Common form field names
                data = {
                    'username': username,
                    'password': password,
                    'group_list': 'DefaultWEBVPNGroup',
                    'Login': 'Login',
                }

                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)

                # Check for successful login indicators
                success_indicators = [
                    b'webvpnlogin',
                    b'portal.html',
                    b'home.html',
                    b'success',
                    b'Welcome',
                ]

                failure_indicators = [
                    b'Login failed',
                    b'Invalid',
                    b'incorrect',
                    b'denied',
                ]

                content = response.content.lower()

                # Check for success
                has_success = any(indicator.lower() in content for indicator in success_indicators)
                has_failure = any(indicator.lower() in content for indicator in failure_indicators)

                # Also check for redirects to portal/home
                if response.status_code in [302, 303, 307] and 'Location' in response.headers:
                    location = response.headers['Location'].lower()
                    if any(s in location for s in ['portal', 'home', 'index', 'welcome']):
                        has_success = True

                if has_success and not has_failure:
                    # Extract session token if available
                    session_token = None
                    if 'Set-Cookie' in response.headers:
                        cookies = response.headers['Set-Cookie']
                        token_match = re.search(r'webvpn=([^;]+)', cookies)
                        if token_match:
                            session_token = token_match.group(1)

                    return CredentialTestResult(
                        endpoint=endpoint.url,
                        username=username,
                        password=password,
                        success=True,
                        response_code=response.status_code,
                        response_message="Form authentication successful",
                        auth_method="form",
                        session_token=session_token
                    )

            except requests.exceptions.RequestException:
                continue

        return None

    def _test_basic_auth(self, endpoint: AnyConnectEndpoint,
                        username: str, password: str) -> Optional[CredentialTestResult]:
        """Test HTTP Basic authentication"""
        try:
            response = self.session.get(
                endpoint.url,
                auth=(username, password),
                timeout=self.timeout
            )

            # 200 or 30x with basic auth usually means success
            if response.status_code in [200, 301, 302, 303]:
                # Check if we got past authentication
                if b'401' not in response.content and b'Unauthorized' not in response.content:
                    return CredentialTestResult(
                        endpoint=endpoint.url,
                        username=username,
                        password=password,
                        success=True,
                        response_code=response.status_code,
                        response_message="Basic authentication successful",
                        auth_method="basic"
                    )

        except requests.exceptions.RequestException:
            pass

        return None

    def _test_xml_auth(self, endpoint: AnyConnectEndpoint,
                      username: str, password: str) -> Optional[CredentialTestResult]:
        """Test XML-based authentication (AnyConnect API)"""
        base_url = endpoint.url.rsplit('/', 1)[0]
        auth_url = f"{base_url}/+webvpn+/login.xml"

        xml_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
    <version who="vpn">3.1.05160</version>
    <device-id>linux-64</device-id>
    <group-access>{endpoint.url}</group-access>
    <capabilities>
        <auth-method>single</auth-method>
    </capabilities>
    <auth>
        <username>{username}</username>
        <password>{password}</password>
    </auth>
</config-auth>'''

        try:
            headers = {
                'Content-Type': 'application/xml',
                'User-Agent': 'AnyConnect Linux_64 3.1.05160'
            }

            response = self.session.post(
                auth_url,
                data=xml_payload,
                headers=headers,
                timeout=self.timeout
            )

            # Check for success in XML response
            if response.status_code == 200:
                content = response.content.decode('utf-8', errors='ignore')

                # Look for success indicators
                if '<auth-reply>' in content and '<error>' not in content:
                    # Extract session token
                    session_token = None
                    token_match = re.search(r'<session-token>([^<]+)</session-token>', content)
                    if token_match:
                        session_token = token_match.group(1)

                    return CredentialTestResult(
                        endpoint=endpoint.url,
                        username=username,
                        password=password,
                        success=True,
                        response_code=response.status_code,
                        response_message="XML API authentication successful",
                        auth_method="xml",
                        session_token=session_token,
                        additional_info={'xml_response': content[:500]}
                    )

        except requests.exceptions.RequestException:
            pass

        return None

    def scan_and_test(self, hostname: str, ports: List[int] = None,
                     test_credentials: bool = True) -> Dict:
        """
        Scan for AnyConnect and test credentials

        Args:
            hostname: Target hostname
            ports: List of ports to check (default: [443, 8443])
            test_credentials: Whether to test credentials after detection

        Returns:
            Dictionary with results
        """
        if ports is None:
            ports = [443, 8443]

        results = {
            'hostname': hostname,
            'endpoints_found': [],
            'credential_tests': []
        }

        # Scan for AnyConnect on specified ports
        for port in ports:
            self._vprint(f"\n[*] Scanning {hostname}:{port} for AnyConnect")
            endpoint = self.detect_anyconnect(hostname, port)

            if endpoint:
                results['endpoints_found'].append(asdict(endpoint))
                self._vprint(f"[+] Found AnyConnect at {endpoint.url}")
                if endpoint.version:
                    self._vprint(f"    Version: {endpoint.version}")

                # Test credentials if requested
                if test_credentials:
                    self._vprint(f"\n[*] Testing default credentials on {endpoint.url}")
                    cred_results = self.test_credentials(endpoint, test_defaults=True)

                    for result in cred_results:
                        results['credential_tests'].append(asdict(result))

                        if result.success:
                            self._vprint(f"\n[!!!] VULNERABLE: Default credentials work!")
                            self._vprint(f"      Username: {result.username}")
                            self._vprint(f"      Password: {result.password}")
                            self._vprint(f"      Method: {result.auth_method}")
                            if result.session_token:
                                self._vprint(f"      Session Token: {result.session_token[:50]}...")

        return results


def main():
    """CLI interface for AnyConnect tester"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Cisco AnyConnect VPN Endpoint Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test single host
  python -m fastport.anyconnect_tester -t vpn.example.com --verbose

  # Test multiple ports
  python -m fastport.anyconnect_tester -t vpn.example.com -p 443 8443 10443

  # Custom credentials
  python -m fastport.anyconnect_tester -t vpn.example.com -u admin -P password123

  # Save results to JSON
  python -m fastport.anyconnect_tester -t vpn.example.com -o results.json

WARNING: Only use against systems you have authorization to test!
        """
    )

    parser.add_argument('-t', '--target', required=True,
                       help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', nargs='+', type=int, default=[443, 8443],
                       help='Ports to scan (default: 443 8443)')
    parser.add_argument('-u', '--username',
                       help='Additional username to test')
    parser.add_argument('-P', '--password',
                       help='Additional password to test')
    parser.add_argument('--no-defaults', action='store_true',
                       help='Do not test default credentials')
    parser.add_argument('-o', '--output',
                       help='Output results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Request timeout in seconds (default: 5)')

    args = parser.parse_args()

    print("[+] Cisco AnyConnect VPN Tester")
    print(f"[+] Target: {args.target}")
    print(f"[+] Ports: {args.ports}")
    print(f"[+] Verbose: {args.verbose}")
    print()

    # Create tester
    tester = AnyConnectTester(timeout=args.timeout, verbose=args.verbose)

    # Prepare custom credentials if provided
    custom_creds = []
    if args.username and args.password:
        custom_creds.append((args.username, args.password))

    # Scan and test
    results = tester.scan_and_test(
        args.target,
        ports=args.ports,
        test_credentials=not args.no_defaults
    )

    # If custom credentials provided, test those too
    if custom_creds and results['endpoints_found']:
        for endpoint_dict in results['endpoints_found']:
            endpoint = AnyConnectEndpoint(**endpoint_dict)
            cred_results = tester.test_credentials(endpoint, credentials=custom_creds, test_defaults=False)
            for result in cred_results:
                results['credential_tests'].append(asdict(result))

    # Print summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Endpoints found: {len(results['endpoints_found'])}")

    successful_auths = [r for r in results['credential_tests'] if r['success']]
    print(f"Successful authentications: {len(successful_auths)}")

    if successful_auths:
        print("\n[!!!] VULNERABLE ENDPOINTS FOUND:")
        for auth in successful_auths:
            print(f"\n  Endpoint: {auth['endpoint']}")
            print(f"  Username: {auth['username']}")
            print(f"  Password: {auth['password']}")
            print(f"  Method: {auth['auth_method']}")

    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == '__main__':
    main()
