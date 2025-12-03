#!/bin/bash
#
# OWASP Scanner - Example Usage Script
# Demonstrates various scanning scenarios
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         OWASP Scanner - Example Usage Script            ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if scanner exists
if [ ! -f "../scanner.py" ]; then
    echo -e "${RED}Error: scanner.py not found!${NC}"
    echo "Please run this script from the examples directory"
    exit 1
fi

# Example 1: Basic Scan
echo -e "\n${GREEN}Example 1: Basic Security Scan${NC}"
echo -e "${YELLOW}Command: python ../scanner.py https://example.com${NC}"
echo "This performs a comprehensive OWASP Top 10 scan with HTML report"
echo ""
read -p "Press Enter to run Example 1..."
python3 ../scanner.py https://example.com || true

# Example 2: Scan with JSON Output
echo -e "\n${GREEN}Example 2: Scan with JSON Output${NC}"
echo -e "${YELLOW}Command: python ../scanner.py https://example.com -o results.json --format json${NC}"
echo "Generates machine-readable JSON report"
echo ""
read -p "Press Enter to run Example 2..."
python3 ../scanner.py https://example.com -o results.json --format json || true

# Example 3: Comprehensive Scan
echo -e "\n${GREEN}Example 3: Comprehensive Scan with Subdomains${NC}"
echo -e "${YELLOW}Command: python ../scanner.py https://example.com -s -m 10${NC}"
echo "Discovers and scans up to 10 subdomains"
echo ""
read -p "Press Enter to run Example 3..."
python3 ../scanner.py https://example.com -s -m 10 || true

# Example 4: All Report Formats
echo -e "\n${GREEN}Example 4: Generate All Report Formats${NC}"
echo -e "${YELLOW}Command: python ../scanner.py https://example.com --all-formats${NC}"
echo "Creates HTML, JSON, and text reports"
echo ""
read -p "Press Enter to run Example 4..."
python3 ../scanner.py https://example.com --all-formats || true

# Example 5: Quiet Scan
echo -e "\n${GREEN}Example 5: Quiet Scan (No Banner)${NC}"
echo -e "${YELLOW}Command: python ../scanner.py https://example.com --no-banner${NC}"
echo "Runs without ASCII banner"
echo ""
read -p "Press Enter to run Example 5..."
python3 ../scanner.py https://example.com --no-banner || true

echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           All Examples Completed Successfully!           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Check the generated reports in the current directory."
