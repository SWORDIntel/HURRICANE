#!/usr/bin/env python3
"""
Hurricane Router API Extension - Standalone
Adds IPv9/IPv6 routing control endpoints

Runs on port 8643 and proxies to v6-gatewayd on port 8642
"""

import sys
import json
import os
import socket
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from flask import Flask, request, jsonify, Response
import requests

# Add IPVNINER to path
PROJECT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_DIR / 'ipvniner'))

# Try to import IPv9 resolver
try:
    from ipv9tool.core.dns_resolver import DNSResolver as IPv9Resolver
    IPV9_AVAILABLE = True
except:
    IPv9Resolver = None
    IPV9_AVAILABLE = False

app = Flask(__name__)


class RoutingMode(Enum):
    IPV6 = "ipv6"
    IPV9 = "ipv9"
    DUAL = "dual"


@dataclass
class RoutingConfig:
    mode: RoutingMode
    ipv9_dns_servers: List[str]
    ipv9_enabled: bool
    ipv6_enabled: bool
    prefer_ipv9: bool


class SimpleRouter:
    IPV9_DNS_SERVERS = ['202.170.218.93', '61.244.5.162']

    def __init__(self, config_file="/etc/v6-gatewayd-routing.conf"):
        self.config_file = config_file
        self.config = self.load_config()
        self.ipv9_resolver = None
        if IPV9_AVAILABLE and self.config.ipv9_enabled:
            try:
                self.ipv9_resolver = IPv9Resolver(dns_servers=self.config.ipv9_dns_servers, timeout=5)
            except:
                pass

    def load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    data = json.load(f)
                    return RoutingConfig(
                        mode=RoutingMode(data.get('mode', 'ipv6')),
                        ipv9_dns_servers=data.get('ipv9_dns_servers', self.IPV9_DNS_SERVERS),
                        ipv9_enabled=data.get('ipv9_enabled', False),
                        ipv6_enabled=data.get('ipv6_enabled', True),
                        prefer_ipv9=data.get('prefer_ipv9', False)
                    )
            except:
                pass

        return RoutingConfig(
            mode=RoutingMode.IPV6,
            ipv9_dns_servers=self.IPV9_DNS_SERVERS,
            ipv9_enabled=False,
            ipv6_enabled=True,
            prefer_ipv9=False
        )

    def save_config(self):
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
        except:
            return False

    def set_mode(self, mode: RoutingMode):
        self.config.mode = mode
        if mode == RoutingMode.IPV6:
            self.config.ipv6_enabled = True
            self.config.ipv9_enabled = False
        elif mode == RoutingMode.IPV9:
            self.config.ipv6_enabled = False
            self.config.ipv9_enabled = True
            if not self.ipv9_resolver and IPV9_AVAILABLE:
                try:
                    self.ipv9_resolver = IPv9Resolver(dns_servers=self.config.ipv9_dns_servers, timeout=5)
                except:
                    pass
        elif mode == RoutingMode.DUAL:
            self.config.ipv6_enabled = True
            self.config.ipv9_enabled = True
            if not self.ipv9_resolver and IPV9_AVAILABLE:
                try:
                    self.ipv9_resolver = IPv9Resolver(dns_servers=self.config.ipv9_dns_servers, timeout=5)
                except:
                    pass
        return self.save_config()

    def get_status(self):
        return {
            'routing_mode': self.config.mode.value,
            'ipv6_enabled': self.config.ipv6_enabled,
            'ipv9_enabled': self.config.ipv9_enabled,
            'prefer_ipv9': self.config.prefer_ipv9,
            'ipv9_available': IPV9_AVAILABLE,
            'ipv9_dns_servers': self.config.ipv9_dns_servers if self.config.ipv9_enabled else None
        }


# Global router
router = SimpleRouter()


@app.route('/routing/mode', methods=['GET', 'POST'])
def routing_mode():
    if request.method == 'GET':
        return jsonify({
            'mode': router.config.mode.value,
            'ipv6_enabled': router.config.ipv6_enabled,
            'ipv9_enabled': router.config.ipv9_enabled
        })
    else:
        data = request.get_json()
        if not data or 'mode' not in data:
            return jsonify({'error': 'mode required'}), 400
        try:
            mode = RoutingMode(data['mode'])
            if router.set_mode(mode):
                return jsonify({'success': True, 'mode': mode.value})
            return jsonify({'error': 'Failed to set mode'}), 500
        except ValueError:
            return jsonify({'error': 'Invalid mode'}), 400


@app.route('/routing/status')
def routing_status():
    return jsonify(router.get_status())


@app.route('/<path:path>', methods=['GET', 'POST'])
@app.route('/', defaults={'path': ''})
def proxy(path):
    url = f"http://localhost:8642/{path}"
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers if k != 'Host'},
            data=request.get_data(),
            params=request.args,
            timeout=10
        )
        return Response(resp.content, resp.status_code, [(k, v) for k, v in resp.headers.items() if k.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection']])
    except:
        return jsonify({'error': 'v6-gatewayd unavailable'}), 503


if __name__ == '__main__':
    print("Hurricane Router API starting on port 8643")
    print(f"Routing mode: {router.config.mode.value}")
    print(f"IPv6 enabled: {router.config.ipv6_enabled}")
    print(f"IPv9 enabled: {router.config.ipv9_enabled}")
    print(f"IPv9 available: {IPV9_AVAILABLE}")
    app.run(host='127.0.0.1', port=8643)
