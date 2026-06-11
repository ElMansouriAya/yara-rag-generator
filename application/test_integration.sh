#!/bin/bash
# test_integration.sh — Test YARA RAG Integration
# 
# Usage:
#   chmod +x test_integration.sh
#   ./test_integration.sh
#
# Requirements:
#   - Flask server running on localhost:5000 (python run_server.py)
#   - curl installed
#   - jq installed (optional, for pretty JSON)

set -e

API_URL="${1:-http://localhost:5000}"
HAVE_JQ=false

# Check if jq is installed
if command -v jq &> /dev/null; then
    HAVE_JQ=true
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    YARA RAG Generator — Integration Test Suite            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Testing API at: $API_URL"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to test endpoint
test_endpoint() {
    local test_name=$1
    local method=$2
    local endpoint=$3
    local data=$4
    local expected_status=$5
    
    echo -ne "${YELLOW}[TEST]${NC} $test_name ... "
    
    local response
    if [ -z "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X $method "$API_URL$endpoint" \
            -H "Content-Type: application/json")
    else
        response=$(curl -s -w "\n%{http_code}" -X $method "$API_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data")
    fi
    
    local status=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)
    
    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP $status)"
        
        if [ "$HAVE_JQ" = true ] && [ ! -z "$body" ]; then
            echo "$body" | jq '.' 2>/dev/null | head -n5 | sed 's/^/  /'
            echo "  ..."
        fi
        
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC} (Expected $expected_status, got $status)"
        echo "Response: $body"
        ((TESTS_FAILED++))
    fi
    echo ""
}

# Test 1: Health Check
test_endpoint \
    "Health Check" \
    "GET" \
    "/health" \
    "" \
    "200"

# Test 2: Generate with Agentic Mode
test_endpoint \
    "Generate YARA Rule (Agentic)" \
    "POST" \
    "/api/generate" \
    '{"query":"Ransomware encrypting files with AES","mode":"agentic"}' \
    "200"

# Test 3: Generate with Baseline Mode
test_endpoint \
    "Generate YARA Rule (Baseline)" \
    "POST" \
    "/api/generate" \
    '{"query":"Keylogger stealing passwords","mode":"baseline"}' \
    "200"

# Test 4: Generate with Invalid Mode
test_endpoint \
    "Generate with Invalid Mode (should fail)" \
    "POST" \
    "/api/generate" \
    '{"query":"test","mode":"invalid_mode"}' \
    "400"

# Test 5: Generate with Empty Query
test_endpoint \
    "Generate with Empty Query (should fail)" \
    "POST" \
    "/api/generate" \
    '{"query":"","mode":"baseline"}' \
    "400"

# Test 6: Explain Rule
test_endpoint \
    "Explain YARA Rule" \
    "POST" \
    "/api/explain" \
    '{"yara_rule":"rule TestRule { strings: $a=\"test\" nocase condition: $a }"}' \
    "200"

# Test 7: Search Knowledge Base
test_endpoint \
    "Search Knowledge Base" \
    "POST" \
    "/api/search" \
    '{"query":"ransomware encryption","k":5}' \
    "200"

# Test 8: Search with Invalid k
test_endpoint \
    "Search with Invalid k (should fail)" \
    "POST" \
    "/api/search" \
    '{"query":"test","k":100}' \
    "400"

# Test 9: Get Statistics
test_endpoint \
    "Get Dataset Statistics" \
    "GET" \
    "/api/stats" \
    "" \
    "200"

# Test 10: Switch Model
test_endpoint \
    "Switch to Flan Model" \
    "POST" \
    "/api/model" \
    '{"model":"flan"}' \
    "200"

# Test 11: Switch to Invalid Model
test_endpoint \
    "Switch to Invalid Model (should fail)" \
    "POST" \
    "/api/model" \
    '{"model":"invalid_model"}' \
    "400"

# Test 12: Benchmark (small)
test_endpoint \
    "Run Benchmark (2 queries)" \
    "POST" \
    "/api/benchmark" \
    '{"queries":["Ransomware with AES","Keylogger"],"references":["rule R1 { strings: $a=\"test\" condition: $a }","rule R2 { strings: $b=\"test\" condition: $b }"]}' \
    "200"

# Test 13: 404 Error
test_endpoint \
    "Invalid Endpoint (should be 404)" \
    "GET" \
    "/nonexistent" \
    "" \
    "404"

# Test 14: Wrong HTTP Method
test_endpoint \
    "Wrong HTTP Method (should be 405)" \
    "GET" \
    "/api/generate" \
    "" \
    "405"

# Test 15: Missing Required Field
test_endpoint \
    "Missing Required Field (should fail)" \
    "POST" \
    "/api/generate" \
    '{"mode":"baseline"}' \
    "400"

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Test Results                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo "Total:  $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
