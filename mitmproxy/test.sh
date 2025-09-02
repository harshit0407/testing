#!/bin/bash

# Example test.sh file - Template for running tests in Conductor
# 
# This script should:
# - Return exit code 0 if all tests pass
# - Return exit code 1 (or any non-zero) if tests fail

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Starting Test Suite ===${NC}"
echo ""

# Initialize test counters
PASSED=0
FAILED=0

# Helper function to run a test
run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -n "Running test: $test_name... "
    
    if eval "$test_command"; then
        echo -e "${GREEN}PASSED${NC}"
        ((PASSED++))
    else
        echo -e "${RED}FAILED${NC}"
        ((FAILED++))
    fi
}

# Run pytest on all test files
run_test "Pytest (all test_*.py)" "pytest test/mitmproxy/addons/test_pii_redaction.py --maxfail=1 --disable-warnings -v"

echo ""
echo -e "${BLUE}=== Test Summary ===${NC}"
echo -e "Tests passed: ${GREEN}${PASSED}${NC}"
echo -e "Tests failed: ${RED}${FAILED}${NC}"

# Exit with appropriate code
if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Some tests failed!${NC}"
    exit 1
fi 