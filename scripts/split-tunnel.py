#!/usr/bin/env python3
"""
Split Tunneling Configuration System
Allows routing different applications/domains through IPv6 or IPv9 selectively
"""

import json
import os
import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class TunnelRoute(Enum):
    """Routing destination"""
    IPV6 = "ipv6"
    IPV9 = "ipv9"
    AUTO = "auto"  # Automatic based on domain TLD


@dataclass
class RoutingRule:
    """Individual routing rule"""
    name: str
    pattern: str  # Domain pattern or application name
    route: TunnelRoute
    enabled: bool = True
    priority: int = 100  # Lower = higher priority


class SplitTunnelConfig:
    """Split tunneling configuration manager"""

    def __init__(self, config_file: str = "/etc/v6-gatewayd-split-tunnel.json"):
        self.config_file = config_file
        self.rules: List[RoutingRule] = []
        self.load()

    def load(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.rules = [
                        RoutingRule(
                            name=r['name'],
                            pattern=r['pattern'],
                            route=TunnelRoute(r['route']),
                            enabled=r.get('enabled', True),
                            priority=r.get('priority', 100)
                        )
                        for r in data.get('rules', [])
                    ]
            except Exception as e:
                print(f"Warning: Failed to load split tunnel config: {e}")
                self._load_defaults()
        else:
            self._load_defaults()

    def _load_defaults(self):
        """Load default routing rules"""
        self.rules = [
            RoutingRule(
                name="IPv9 Domains",
                pattern="*.chn",
                route=TunnelRoute.IPV9,
                priority=10
            ),
            RoutingRule(
                name="IPv6 Preferred Sites",
                pattern="*.google.com,*.cloudflare.com,*.he.net",
                route=TunnelRoute.IPV6,
                priority=20
            ),
            RoutingRule(
                name="Auto Route Everything Else",
                pattern="*",
                route=TunnelRoute.AUTO,
                priority=1000
            )
        ]

    def save(self) -> bool:
        """Save configuration to file"""
        try:
            data = {
                'rules': [
                    {
                        'name': r.name,
                        'pattern': r.pattern,
                        'route': r.route.value,
                        'enabled': r.enabled,
                        'priority': r.priority
                    }
                    for r in self.rules
                ]
            }

            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving split tunnel config: {e}")
            return False

    def add_rule(self, rule: RoutingRule) -> bool:
        """Add new routing rule"""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        return self.save()

    def remove_rule(self, name: str) -> bool:
        """Remove routing rule by name"""
        self.rules = [r for r in self.rules if r.name != name]
        return self.save()

    def update_rule(self, name: str, updates: Dict) -> bool:
        """Update existing rule"""
        for rule in self.rules:
            if rule.name == name:
                if 'pattern' in updates:
                    rule.pattern = updates['pattern']
                if 'route' in updates:
                    rule.route = TunnelRoute(updates['route'])
                if 'enabled' in updates:
                    rule.enabled = updates['enabled']
                if 'priority' in updates:
                    rule.priority = updates['priority']
                self.rules.sort(key=lambda r: r.priority)
                return self.save()
        return False

    def match_domain(self, domain: str) -> Optional[TunnelRoute]:
        """Find matching route for domain"""
        for rule in sorted(self.rules, key=lambda r: r.priority):
            if not rule.enabled:
                continue

            # Convert pattern to regex
            patterns = rule.pattern.split(',')
            for pattern in patterns:
                pattern = pattern.strip()
                # Convert glob pattern to regex
                regex_pattern = pattern.replace('.', r'\\.').replace('*', '.*')
                if re.match(f"^{regex_pattern}$", domain, re.IGNORECASE):
                    return rule.route

        return TunnelRoute.AUTO

    def get_rules_dict(self) -> List[Dict]:
        """Get rules as dictionary list"""
        return [
            {
                'name': r.name,
                'pattern': r.pattern,
                'route': r.route.value,
                'enabled': r.enabled,
                'priority': r.priority
            }
            for r in sorted(self.rules, key=lambda r: r.priority)
        ]


def main():
    """CLI for split tunnel management"""
    import argparse

    parser = argparse.ArgumentParser(description='Split Tunneling Configuration')
    parser.add_argument('command', choices=['list', 'add', 'remove', 'test'],
                       help='Command to execute')
    parser.add_argument('--name', help='Rule name')
    parser.add_argument('--pattern', help='Domain pattern (e.g., *.chn, *.google.com)')
    parser.add_argument('--route', choices=['ipv6', 'ipv9', 'auto'], help='Routing destination')
    parser.add_argument('--priority', type=int, default=100, help='Priority (lower = higher)')
    parser.add_argument('--domain', help='Domain to test routing')

    args = parser.parse_args()

    config = SplitTunnelConfig()

    if args.command == 'list':
        print("Split Tunneling Rules:")
        print("-" * 80)
        for rule in config.get_rules_dict():
            status = "✓" if rule['enabled'] else "✗"
            print(f"{status} [{rule['priority']:3d}] {rule['name']:30s} {rule['pattern']:30s} → {rule['route']}")

    elif args.command == 'add':
        if not all([args.name, args.pattern, args.route]):
            print("Error: --name, --pattern, and --route required")
            return 1

        rule = RoutingRule(
            name=args.name,
            pattern=args.pattern,
            route=TunnelRoute(args.route),
            priority=args.priority
        )

        if config.add_rule(rule):
            print(f"✓ Added rule: {args.name}")
        else:
            print("✗ Failed to add rule")
            return 1

    elif args.command == 'remove':
        if not args.name:
            print("Error: --name required")
            return 1

        if config.remove_rule(args.name):
            print(f"✓ Removed rule: {args.name}")
        else:
            print("✗ Failed to remove rule")
            return 1

    elif args.command == 'test':
        if not args.domain:
            print("Error: --domain required")
            return 1

        route = config.match_domain(args.domain)
        print(f"Domain: {args.domain}")
        print(f"Route:  {route.value}")

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
