#!/usr/bin/env python3
"""
Hurricane Router API Extension
Adds IPv9/IPv6 routing control endpoints to v6-gatewayd API

This service runs alongside v6-gatewayd and provides additional endpoints:
- GET/POST /routing/mode - Get or set routing mode (ipv6/ipv9/dual)
- GET /routing/status - Get routing status
- POST /routing/resolve - Resolve domain through selected routing mode
- GET /routing/test - Test connectivity for all modes

Proxies all other requests to v6-gatewayd daemon.
"""

import sys
import json
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify, Response
import requests

# Add router script to path
SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_DIR / 'ipvniner'))

try:
    from ipv9tool.core.dns_resolver import DNSResolver as IPv9Resolver
    IPV9_AVAILABLE = True
except ImportError:
    IPV9Resolver = None
    IPV9_AVAILABLE = False

app = Flask(__name__)

# Configuration
V6GW_API_URL = "http://localhost:8642"
ROUTER_API_PORT = 8643
ROUTER_CONFIG = "/etc/v6-gatewayd-routing.conf"

# Global router instance
router = None


def init_router():
    """Initialize router instance"""
    global router
    router = HurricaneRouter(config_file=ROUTER_CONFIG, api_url=V6GW_API_URL)


@app.route('/routing/mode', methods=['GET', 'POST'])
def routing_mode():
    """Get or set routing mode"""
    if request.method == 'GET':
        return jsonify({
            'mode': router.config.mode.value,
            'ipv6_enabled': router.config.ipv6_enabled,
            'ipv9_enabled': router.config.ipv9_enabled,
            'prefer_ipv9': router.config.prefer_ipv9
        })

    elif request.method == 'POST':
        data = request.get_json()
        if not data or 'mode' not in data:
            return jsonify({'error': 'mode parameter required'}), 400

        try:
            mode = RoutingMode(data['mode'])
            if router.set_mode(mode):
                return jsonify({
                    'success': True,
                    'mode': mode.value,
                    'message': f'Routing mode set to {mode.value}'
                })
            else:
                return jsonify({'error': 'Failed to set routing mode'}), 500
        except ValueError:
            return jsonify({'error': f'Invalid mode: {data["mode"]}'}), 400


@app.route('/routing/status', methods=['GET'])
def routing_status():
    """Get comprehensive routing status"""
    status = router.get_status()
    return jsonify(status)


@app.route('/routing/resolve', methods=['POST'])
def routing_resolve():
    """Resolve domain using current routing mode"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'domain parameter required'}), 400

    domain = data['domain']
    result = router.resolve_domain(domain)
    return jsonify(result)


@app.route('/routing/test', methods=['GET'])
def routing_test():
    """Test connectivity for all enabled modes"""
    results = router.test_connectivity()
    return jsonify(results)


@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(path):
    """Proxy all other requests to v6-gatewayd"""
    url = f"{V6GW_API_URL}/{path}"

    try:
        # Forward request to v6-gatewayd
        resp = requests.request(
            method=request.method,
            url=url,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            params=request.args,
            allow_redirects=False,
            timeout=30
        )

        # Create response
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]

        response = Response(resp.content, resp.status_code, headers)
        return response

    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'v6-gatewayd daemon not running'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Hurricane Router API Extension')
    parser.add_argument('--port', type=int, default=ROUTER_API_PORT,
                       help=f'API port (default: {ROUTER_API_PORT})')
    parser.add_argument('--v6gw-api', default=V6GW_API_URL,
                       help=f'v6-gatewayd API URL (default: {V6GW_API_URL})')
    parser.add_argument('--config', default=ROUTER_CONFIG,
                       help=f'Router config file (default: {ROUTER_CONFIG})')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')

    args = parser.parse_args()

    # Update globals
    global V6GW_API_URL, ROUTER_CONFIG
    V6GW_API_URL = args.v6gw_api
    ROUTER_CONFIG = args.config

    # Initialize router
    init_router()

    print(f"Hurricane Router API starting on port {args.port}")
    print(f"v6-gatewayd API: {V6GW_API_URL}")
    print(f"Routing mode: {router.config.mode.value}")

    # Start Flask app
    app.run(host='127.0.0.1', port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
