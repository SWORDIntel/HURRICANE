#!/usr/bin/env python3
"""
HURRICANE Comprehensive API
Complete integration: Routing + Split Tunneling + FASTPORT + Real-time Streaming

Port 8643 - All-in-one API with SSE support for real-time updates
"""

import sys
import json
import os
import asyncio
import threading
from pathlib import Path
from flask import Flask, request, jsonify, Response, stream_with_context
from queue import Queue
import requests
import time

# Add paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_DIR / 'fastport'))
sys.path.insert(0, str(PROJECT_DIR / 'ipvniner'))
sys.path.insert(0, str(SCRIPT_DIR))

try:
    from fastport.scanner_unified import UnifiedScanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False

try:
    from split_tunnel import SplitTunnelConfig, RoutingRule, TunnelRoute
    SPLIT_TUNNEL_AVAILABLE = True
except ImportError:
    SPLIT_TUNNEL_AVAILABLE = False

app = Flask(__name__)

# Configuration
V6GW_API_URL = "http://localhost:8642"
ROUTER_CONFIG = "/etc/v6-gatewayd-routing.conf"
SPLIT_TUNNEL_CONFIG = "/etc/v6-gatewayd-split-tunnel.json"

# Global state
routing_config = {}
split_tunnel_config = None
active_scans = {}  # scan_id -> scan_info
scan_outputs = {}  # scan_id -> Queue for SSE events


def init_config():
    """Initialize configuration"""
    global split_tunnel_config

    if SPLIT_TUNNEL_AVAILABLE:
        split_tunnel_config = SplitTunnelConfig(SPLIT_TUNNEL_CONFIG)

    # Load routing config
    if os.path.exists(ROUTER_CONFIG):
        try:
            with open(ROUTER_CONFIG) as f:
                routing_config.update(json.load(f))
        except:
            pass


# ==================== Routing Endpoints ====================

@app.route('/routing/mode', methods=['GET', 'POST'])
def routing_mode():
    """Get or set routing mode"""
    if request.method == 'GET':
        return jsonify({
            'mode': routing_config.get('mode', 'ipv6'),
            'ipv6_enabled': routing_config.get('ipv6_enabled', True),
            'ipv9_enabled': routing_config.get('ipv9_enabled', False)
        })
    else:
        data = request.get_json()
        if not data or 'mode' not in data:
            return jsonify({'error': 'mode required'}), 400

        mode = data['mode']
        routing_config['mode'] = mode

        if mode == 'ipv6':
            routing_config['ipv6_enabled'] = True
            routing_config['ipv9_enabled'] = False
        elif mode == 'ipv9':
            routing_config['ipv6_enabled'] = False
            routing_config['ipv9_enabled'] = True
        elif mode == 'dual':
            routing_config['ipv6_enabled'] = True
            routing_config['ipv9_enabled'] = True

        # Save config
        try:
            with open(ROUTER_CONFIG, 'w') as f:
                json.dump(routing_config, f, indent=2)
        except:
            pass

        return jsonify({'success': True, 'mode': mode})


@app.route('/routing/status')
def routing_status():
    """Get routing status"""
    return jsonify({
        'routing_mode': routing_config.get('mode', 'ipv6'),
        'ipv6_enabled': routing_config.get('ipv6_enabled', True),
        'ipv9_enabled': routing_config.get('ipv9_enabled', False),
        'scanner_available': SCANNER_AVAILABLE,
        'split_tunnel_available': SPLIT_TUNNEL_AVAILABLE
    })


# ==================== Split Tunneling Endpoints ====================

@app.route('/split-tunnel/rules', methods=['GET'])
def get_split_tunnel_rules():
    """Get all split tunneling rules"""
    if not SPLIT_TUNNEL_AVAILABLE:
        return jsonify({'error': 'Split tunnel not available'}), 503

    return jsonify({
        'rules': split_tunnel_config.get_rules_dict()
    })


@app.route('/split-tunnel/rules', methods=['POST'])
def add_split_tunnel_rule():
    """Add new split tunneling rule"""
    if not SPLIT_TUNNEL_AVAILABLE:
        return jsonify({'error': 'Split tunnel not available'}), 503

    data = request.get_json()
    if not data or not all(k in data for k in ['name', 'pattern', 'route']):
        return jsonify({'error': 'name, pattern, and route required'}), 400

    rule = RoutingRule(
        name=data['name'],
        pattern=data['pattern'],
        route=TunnelRoute(data['route']),
        enabled=data.get('enabled', True),
        priority=data.get('priority', 100)
    )

    if split_tunnel_config.add_rule(rule):
        return jsonify({'success': True, 'rule': data})
    else:
        return jsonify({'error': 'Failed to add rule'}), 500


@app.route('/split-tunnel/rules/<rule_name>', methods=['DELETE'])
def delete_split_tunnel_rule(rule_name):
    """Delete split tunneling rule"""
    if not SPLIT_TUNNEL_AVAILABLE:
        return jsonify({'error': 'Split tunnel not available'}), 503

    if split_tunnel_config.remove_rule(rule_name):
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Rule not found'}), 404


@app.route('/split-tunnel/rules/<rule_name>', methods=['PATCH'])
def update_split_tunnel_rule(rule_name):
    """Update split tunneling rule"""
    if not SPLIT_TUNNEL_AVAILABLE:
        return jsonify({'error': 'Split tunnel not available'}), 503

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No updates provided'}), 400

    if split_tunnel_config.update_rule(rule_name, data):
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Rule not found'}), 404


@app.route('/split-tunnel/match/<domain>')
def match_split_tunnel(domain):
    """Test which route matches a domain"""
    if not SPLIT_TUNNEL_AVAILABLE:
        return jsonify({'error': 'Split tunnel not available'}), 503

    route = split_tunnel_config.match_domain(domain)
    return jsonify({
        'domain': domain,
        'route': route.value if route else 'auto'
    })


# ==================== Scanner Endpoints ====================

@app.route('/scanner/start', methods=['POST'])
def start_scan():
    """Start new port scan"""
    if not SCANNER_AVAILABLE:
        return jsonify({'error': 'Scanner not available'}), 503

    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({'error': 'target required'}), 400

    # Generate scan ID
    scan_id = f"scan_{int(time.time() * 1000)}"

    # Parse parameters
    target = data['target']
    ports = data.get('ports', None)
    if ports and isinstance(ports, str):
        ports = [int(p.strip()) for p in ports.split(',')]
    port_range = data.get('port_range', None)
    timeout = float(data.get('timeout', 1.0))
    workers = int(data.get('workers', 100))

    # Create output queue for SSE
    scan_outputs[scan_id] = Queue()

    # Start scan in background thread
    def run_scan():
        scanner = UnifiedScanner(verbose=True)

        def progress_callback(progress):
            # Send progress via SSE
            if scan_id in scan_outputs:
                scan_outputs[scan_id].put({
                    'type': 'progress',
                    'data': progress
                })

        # Run scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(scanner.scan_async(
            target=target,
            ports=ports,
            port_range=port_range,
            timeout=timeout,
            workers=workers,
            progress_callback=progress_callback
        ))

        # Store results
        active_scans[scan_id] = {
            'id': scan_id,
            'status': 'completed',
            'results': results
        }

        # Send completion via SSE
        if scan_id in scan_outputs:
            scan_outputs[scan_id].put({
                'type': 'complete',
                'data': results
            })

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    active_scans[scan_id] = {
        'id': scan_id,
        'status': 'running',
        'target': target,
        'started_at': time.time()
    }

    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'stream_url': f'/scanner/stream/{scan_id}'
    })


@app.route('/scanner/stream/<scan_id>')
def stream_scan(scan_id):
    """Stream scan progress via SSE"""
    def generate():
        yield 'data: {"type":"connected"}\n\n'

        if scan_id not in scan_outputs:
            yield 'data: {"type":"error","error":"Scan not found"}\n\n'
            return

        queue = scan_outputs[scan_id]

        while True:
            try:
                msg = queue.get(timeout=30)
                yield f'data: {json.dumps(msg)}\n\n'

                if msg.get('type') == 'complete':
                    break
            except:
                # Timeout, send keepalive
                yield 'data: {"type":"keepalive"}\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/scanner/scans')
def list_scans():
    """List all scans"""
    return jsonify({
        'scans': list(active_scans.values())
    })


@app.route('/scanner/scans/<scan_id>')
def get_scan(scan_id):
    """Get scan results"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404

    return jsonify(active_scans[scan_id])


# ==================== Proxy to v6-gatewayd ====================

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
def proxy(path):
    """Proxy requests to v6-gatewayd"""
    url = f"{V6GW_API_URL}/{path}"

    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers if k != 'Host'},
            data=request.get_data(),
            params=request.args,
            timeout=10
        )

        return Response(
            resp.content,
            resp.status_code,
            [(k, v) for k, v in resp.headers.items()
             if k.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection']]
        )
    except:
        return jsonify({'error': 'v6-gatewayd unavailable'}), 503


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='HURRICANE Comprehensive API')
    parser.add_argument('--port', type=int, default=8643, help='API port (default: 8643)')
    parser.add_argument('--debug', action='store_true', help='Debug mode')

    args = parser.parse_args()

    init_config()

    print("=" * 70)
    print("HURRICANE Comprehensive API")
    print("=" * 70)
    print(f"Port: {args.port}")
    print(f"v6-gatewayd API: {V6GW_API_URL}")
    print(f"Routing config: {ROUTER_CONFIG}")
    print(f"Split tunnel config: {SPLIT_TUNNEL_CONFIG}")
    print(f"Scanner available: {SCANNER_AVAILABLE}")
    print(f"Split tunnel available: {SPLIT_TUNNEL_AVAILABLE}")
    print("=" * 70)

    app.run(host='127.0.0.1', port=args.port, debug=args.debug, threaded=True)


if __name__ == '__main__':
    main()
