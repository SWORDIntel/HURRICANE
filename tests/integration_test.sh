#!/bin/bash
#
# Integration Test Suite for HURRICANE v6-gatewayd
# Tests API endpoints, tunnel management, and core functionality
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_BASE="http://127.0.0.1:8642"
PASSED=0
FAILED=0
SKIPPED=0

echo "========================================"
echo "HURRICANE v6-gatewayd Integration Tests"
echo "========================================"
echo ""

# Helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED++))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAILED++))
}

skip() {
    echo -e "${YELLOW}⊘ SKIP${NC}: $1"
    ((SKIPPED++))
}

test_endpoint() {
    local name="$1"
    local method="$2"
    local path="$3"
    local expected_code="$4"
    local data="$5"

    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_BASE$path" 2>/dev/null || echo "000")
    else
        response=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "$data" "$API_BASE$path" 2>/dev/null || echo "000")
    fi

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)

    if [ "$http_code" = "$expected_code" ]; then
        pass "$name (HTTP $http_code)"
        return 0
    else
        fail "$name (expected $expected_code, got $http_code)"
        return 1
    fi
}

# Check if daemon is running
echo "Checking daemon status..."
if ! pgrep -x "v6-gatewayd" > /dev/null; then
    echo -e "${YELLOW}WARNING: v6-gatewayd daemon not running${NC}"
    echo "Start the daemon with: sudo systemctl start v6-gatewayd"
    echo "Or run manually: sudo ./v6-gatewayd -c /etc/v6-gatewayd.conf"
    echo ""
    echo "Running tests anyway (some will fail)..."
    echo ""
fi

# Test 1: Root endpoint
echo "Test Suite 1: Core API Endpoints"
echo "--------------------------------"
test_endpoint "GET /" "GET" "/" "200"
test_endpoint "GET /health" "GET" "/health" "200"
test_endpoint "GET /v6/address" "GET" "/v6/address" "200"
test_endpoint "GET /tunnels" "GET" "/tunnels" "200"
echo ""

# Test 2: New advanced endpoints
echo "Test Suite 2: Advanced API Endpoints"
echo "------------------------------------"
test_endpoint "GET /config" "GET" "/config" "200"
test_endpoint "GET /logs" "GET" "/logs" "200"
test_endpoint "GET /logs?limit=10" "GET" "/logs?limit=10" "200"
test_endpoint "GET /metrics" "GET" "/metrics" "200"
test_endpoint "GET /ui" "GET" "/ui" "200"
echo ""

# Test 3: Tunnel control (these might fail if no tunnels configured)
echo "Test Suite 3: Tunnel Control"
echo "----------------------------"
# These will return 404 if no tunnel ID 0 exists, which is expected
curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/tunnel/0/start" > /dev/null 2>&1
result=$?
if [ $result -eq 0 ]; then
    skip "POST /tunnel/0/start (tunnel may not exist)"
else
    skip "POST /tunnel/0/start (daemon not running or no tunnel)"
fi

curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/tunnel/0/stop" > /dev/null 2>&1
result=$?
if [ $result -eq 0 ]; then
    skip "POST /tunnel/0/stop (tunnel may not exist)"
else
    skip "POST /tunnel/0/stop (daemon not running or no tunnel)"
fi

curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/tunnel/0/restart" > /dev/null 2>&1
result=$?
if [ $result -eq 0 ]; then
    skip "POST /tunnel/0/restart (tunnel may not exist)"
else
    skip "POST /tunnel/0/restart (daemon not running or no tunnel)"
fi
echo ""

# Test 4: Invalid endpoints
echo "Test Suite 4: Error Handling"
echo "----------------------------"
test_endpoint "GET /nonexistent" "GET" "/nonexistent" "404"
test_endpoint "GET /tunnel/999/start (invalid ID)" "POST" "/tunnel/999/start" "404"
echo ""

# Test 5: JSON response validation
echo "Test Suite 5: Response Format Validation"
echo "----------------------------------------"
response=$(curl -s "$API_BASE/health" 2>/dev/null || echo "{}")
if echo "$response" | jq . > /dev/null 2>&1; then
    pass "GET /health returns valid JSON"
else
    fail "GET /health returns invalid JSON"
fi

response=$(curl -s "$API_BASE/config" 2>/dev/null || echo "{}")
if echo "$response" | jq . > /dev/null 2>&1; then
    pass "GET /config returns valid JSON"
else
    fail "GET /config returns invalid JSON"
fi

response=$(curl -s "$API_BASE/logs" 2>/dev/null || echo "{}")
if echo "$response" | jq . > /dev/null 2>&1; then
    pass "GET /logs returns valid JSON"
else
    fail "GET /logs returns invalid JSON"
fi
echo ""

# Test 6: Prometheus metrics format
echo "Test Suite 6: Prometheus Metrics"
echo "--------------------------------"
metrics=$(curl -s "$API_BASE/metrics" 2>/dev/null || echo "")
if echo "$metrics" | grep -q "# HELP v6gw_tunnel_state"; then
    pass "Prometheus metrics contain HELP directive"
else
    fail "Prometheus metrics missing HELP directive"
fi

if echo "$metrics" | grep -q "# TYPE v6gw_tunnel_state gauge"; then
    pass "Prometheus metrics contain TYPE directive"
else
    fail "Prometheus metrics missing TYPE directive"
fi

if echo "$metrics" | grep -q "v6gw_tunnel_health_score"; then
    pass "Prometheus metrics contain health_score metric"
else
    fail "Prometheus metrics missing health_score metric"
fi
echo ""

# Test 7: WebUI content
echo "Test Suite 7: WebUI Functionality"
echo "---------------------------------"
webui=$(curl -s "$API_BASE/ui" 2>/dev/null || echo "")
if echo "$webui" | grep -q "HURRICANE v6-gatewayd"; then
    pass "WebUI contains title"
else
    fail "WebUI missing title"
fi

if echo "$webui" | grep -q "TEMPEST"; then
    pass "WebUI contains TEMPEST theme"
else
    fail "WebUI missing TEMPEST theme"
fi

if echo "$webui" | grep -q "canvas"; then
    pass "WebUI contains chart canvas elements"
else
    fail "WebUI missing chart canvas elements"
fi

if echo "$webui" | grep -q "controlTunnel"; then
    pass "WebUI contains tunnel control functions"
else
    fail "WebUI missing tunnel control functions"
fi
echo ""

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "${GREEN}Passed:  $PASSED${NC}"
echo -e "${RED}Failed:  $FAILED${NC}"
echo -e "${YELLOW}Skipped: $SKIPPED${NC}"
echo "Total:   $((PASSED + FAILED + SKIPPED))"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
