#!/usr/bin/env python3
"""
HURRICANE IPv9 Integration Layer
Allows switching between IPv6 (Hurricane Electric) and IPv9 (China Decimal Network) routing

Features:
- DNS resolver switching (standard DNS vs IPv9 DNS servers)
- Routing mode configuration (ipv6, ipv9, dual)
- Integration with v6-gatewayd API
- IPVNINER DNS client integration
"""

import sys
import os
import json
import socket
import requests
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

# Add IPVNINER to path
ipv9_path = Path(__file__).parent.parent / 'ipvniner'
sys.path.insert(0, str(ipv9_path))

try:
    from ipv9tool.core.dns_resolver import DNSResolver as IPv9Resolver
    IPV9_AVAILABLE = True
except ImportError:
    IPV9_AVAILABLE = False
    print("Warning: IPVNINER not available - IPv9 mode disabled")


class RoutingMode(Enum):
    """Network routing modes"""
    IPV6 = "ipv6"      # Standard IPv6 routing through HE tunnel
    IPV9 = "ipv9"      # IPv9 DNS overlay routing
    DUAL = "dual"      # Both IPv6 and IPv9 available


@dataclass
class RoutingConfig:
    """Routing configuration"""
    mode: RoutingMode
    ipv9_dns_servers: List[str]
    ipv9_enabled: bool
    ipv6_enabled: bool
    prefer_ipv9: bool  # When in dual mode, prefer IPv9 resolution


class HurricaneRouter:
    """
    Routing manager for HURRICANE v6-gatewayd
    Handles switching between IPv6 and IPv9 routing modes
    """

    # Default IPv9 DNS servers (China)
    IPV9_DNS_SERVERS = [
        '202.170.218.93',  # Primary IPv9 DNS
        '61.244.5.162'     # Secondary IPv9 DNS
    ]

    def __init__(
        self,
        config_file: str = "/etc/v6-gatewayd-routing.conf",
        api_url: str = "http://localhost:8642"
    ):
        self.config_file = config_file
        self.api_url = api_url.rstrip('/')
        self.config = self.load_config()
        self.ipv9_resolver = None

        if IPV9_AVAILABLE and self.config.ipv9_enabled:
            self._init_ipv9_resolver()

    def load_config(self) -> RoutingConfig:
        """Load routing configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    return RoutingConfig(
                        mode=RoutingMode(data.get('mode', 'ipv6')),
                        ipv9_dns_servers=data.get('ipv9_dns_servers', self.IPV9_DNS_SERVERS),
                        ipv9_enabled=data.get('ipv9_enabled', False),
                        ipv6_enabled=data.get('ipv6_enabled', True),
                        prefer_ipv9=data.get('prefer_ipv9', False)
                    )
            except Exception as e:
                print(f"Warning: Failed to load config: {e}")

        # Default configuration
        return RoutingConfig(
            mode=RoutingMode.IPV6,
            ipv9_dns_servers=self.IPV9_DNS_SERVERS,
            ipv9_enabled=False,
            ipv6_enabled=True,
            prefer_ipv9=False
        )

    def save_config(self) -> bool:
        """Save current configuration to file"""
        try:
            data = {
                'mode': self.config.mode.value,
                'ipv9_dns_servers': self.config.ipv9_dns_servers,
                'ipv9_enabled': self.config.ipv9_enabled,
                'ipv6_enabled': self.config.ipv6_enabled,
                'prefer_ipv9': self.config.prefer_ipv9
            }

            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def _init_ipv9_resolver(self):
        """Initialize IPv9 DNS resolver"""
        if not IPV9_AVAILABLE:
            print("IPv9 resolver not available")
            return

        try:
            self.ipv9_resolver = IPv9Resolver(
                dns_servers=self.config.ipv9_dns_servers,
                timeout=5
            )
            print(f"IPv9 resolver initialized with servers: {self.config.ipv9_dns_servers}")
        except Exception as e:
            print(f"Failed to initialize IPv9 resolver: {e}")

    def set_mode(self, mode: RoutingMode) -> bool:
        """
        Set routing mode

        Args:
            mode: Routing mode to set (ipv6, ipv9, dual)

        Returns:
            True if successful
        """
        old_mode = self.config.mode
        self.config.mode = mode

        # Update enabled flags
        if mode == RoutingMode.IPV6:
            self.config.ipv6_enabled = True
            self.config.ipv9_enabled = False
        elif mode == RoutingMode.IPV9:
            self.config.ipv6_enabled = False
            self.config.ipv9_enabled = True
            if not self.ipv9_resolver:
                self._init_ipv9_resolver()
        elif mode == RoutingMode.DUAL:
            self.config.ipv6_enabled = True
            self.config.ipv9_enabled = True
            if not self.ipv9_resolver:
                self._init_ipv9_resolver()

        # Save configuration
        if self.save_config():
            print(f"Routing mode changed: {old_mode.value} → {mode.value}")
            return True
        else:
            # Rollback on failure
            self.config.mode = old_mode
            return False

    def resolve_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Resolve domain using current routing mode

        Args:
            domain: Domain to resolve (supports both standard and .chn domains)

        Returns:
            Resolution result with IP addresses and metadata
        """
        result = {
            'domain': domain,
            'mode': self.config.mode.value,
            'ipv6_address': None,
            'ipv4_address': None,
            'ipv9_resolved': False,
            'error': None
        }

        # IPv9 resolution for .chn domains or when IPv9 preferred
        if self.config.ipv9_enabled and (domain.endswith('.chn') or self.config.prefer_ipv9):
            if self.ipv9_resolver:
                try:
                    ipv9_result = self.ipv9_resolver.resolve(domain)
                    if ipv9_result and ipv9_result.get('success'):
                        result['ipv4_address'] = ipv9_result.get('ip_address')
                        result['ipv9_resolved'] = True
                        result['ipv9_server'] = ipv9_result.get('dns_server')
                        return result
                except Exception as e:
                    result['error'] = f"IPv9 resolution failed: {e}"

        # Standard IPv6/IPv4 resolution
        if self.config.ipv6_enabled or not result['ipv9_resolved']:
            try:
                # Try IPv6 first
                try:
                    addrs = socket.getaddrinfo(domain, None, socket.AF_INET6)
                    if addrs:
                        result['ipv6_address'] = addrs[0][4][0]
                except:
                    pass

                # Try IPv4
                try:
                    addrs = socket.getaddrinfo(domain, None, socket.AF_INET)
                    if addrs:
                        result['ipv4_address'] = addrs[0][4][0]
                except:
                    pass

                if result['ipv6_address'] or result['ipv4_address']:
                    return result
                else:
                    result['error'] = "No addresses found"
            except Exception as e:
                result['error'] = f"DNS resolution failed: {e}"

        return result

    def get_status(self) -> Dict[str, Any]:
        """Get current routing status"""
        # Check v6-gatewayd daemon
        v6gw_status = "unknown"
        tunnels = []
        try:
            response = requests.get(f"{self.api_url}/health", timeout=2)
            if response.status_code == 200:
                v6gw_status = "running"
                # Get tunnels
                tunnels_resp = requests.get(f"{self.api_url}/tunnels", timeout=2)
                if tunnels_resp.status_code == 200:
                    data = tunnels_resp.json()
                    tunnels = data.get('tunnels', [])
        except:
            v6gw_status = "stopped"

        return {
            'routing_mode': self.config.mode.value,
            'ipv6_enabled': self.config.ipv6_enabled,
            'ipv9_enabled': self.config.ipv9_enabled,
            'prefer_ipv9': self.config.prefer_ipv9,
            'ipv9_available': IPV9_AVAILABLE,
            'ipv9_dns_servers': self.config.ipv9_dns_servers if self.config.ipv9_enabled else None,
            'v6gw_daemon': v6gw_status,
            'active_tunnels': len([t for t in tunnels if t.get('state') == 'up']),
            'config_file': self.config_file
        }

    def test_connectivity(self) -> Dict[str, Any]:
        """Test connectivity for all enabled modes"""
        results = {
            'ipv6': None,
            'ipv9': None
        }

        # Test IPv6
        if self.config.ipv6_enabled:
            try:
                # Try to resolve Google's IPv6 DNS
                addr_info = socket.getaddrinfo('ipv6.google.com', None, socket.AF_INET6)
                if addr_info:
                    results['ipv6'] = {
                        'status': 'ok',
                        'test_domain': 'ipv6.google.com',
                        'resolved': addr_info[0][4][0]
                    }
            except Exception as e:
                results['ipv6'] = {
                    'status': 'failed',
                    'error': str(e)
                }

        # Test IPv9
        if self.config.ipv9_enabled and self.ipv9_resolver:
            try:
                test_result = self.ipv9_resolver.resolve('www.v9.chn')
                if test_result and test_result.get('success'):
                    results['ipv9'] = {
                        'status': 'ok',
                        'test_domain': 'www.v9.chn',
                        'resolved': test_result.get('ip_address'),
                        'dns_server': test_result.get('dns_server')
                    }
                else:
                    results['ipv9'] = {
                        'status': 'failed',
                        'error': 'Resolution failed'
                    }
            except Exception as e:
                results['ipv9'] = {
                    'status': 'failed',
                    'error': str(e)
                }

        return results


def main():
    """CLI interface for routing management"""
    import argparse

    parser = argparse.ArgumentParser(
        description='HURRICANE Routing Manager - IPv6/IPv9 Switching',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Show current routing status
  %(prog)s status

  # Switch to IPv6 mode
  %(prog)s set-mode ipv6

  # Switch to IPv9 mode
  %(prog)s set-mode ipv9

  # Enable dual mode (both IPv6 and IPv9)
  %(prog)s set-mode dual

  # Resolve domain
  %(prog)s resolve www.v9.chn

  # Test connectivity
  %(prog)s test
        '''
    )

    parser.add_argument('command', choices=['status', 'set-mode', 'resolve', 'test'],
                       help='Command to execute')
    parser.add_argument('args', nargs='*', help='Command arguments')
    parser.add_argument('--config', default='/etc/v6-gatewayd-routing.conf',
                       help='Config file path')
    parser.add_argument('--api', default='http://localhost:8642',
                       help='v6-gatewayd API URL')

    args = parser.parse_args()

    # Create router
    router = HurricaneRouter(config_file=args.config, api_url=args.api)

    # Execute command
    if args.command == 'status':
        status = router.get_status()
        print(json.dumps(status, indent=2))

    elif args.command == 'set-mode':
        if not args.args:
            print("Error: mode required (ipv6, ipv9, dual)")
            sys.exit(1)

        try:
            mode = RoutingMode(args.args[0])
            if router.set_mode(mode):
                print(f"✓ Routing mode set to: {mode.value}")
                status = router.get_status()
                print(json.dumps(status, indent=2))
            else:
                print("✗ Failed to set routing mode")
                sys.exit(1)
        except ValueError:
            print(f"Error: Invalid mode '{args.args[0]}' (must be: ipv6, ipv9, dual)")
            sys.exit(1)

    elif args.command == 'resolve':
        if not args.args:
            print("Error: domain required")
            sys.exit(1)

        domain = args.args[0]
        result = router.resolve_domain(domain)
        print(json.dumps(result, indent=2))

    elif args.command == 'test':
        results = router.test_connectivity()
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
