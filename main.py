#!/usr/bin/env python3
"""
Web Vulnerability Scanner for OWASP Top 10 vulnerabilities:
- Broken Access Control
- Cryptographic Failures

Usage: python3 main.py <target_url>
Example: python3 main.py https://example.com
"""

import os
import sys
import argparse
import requests
from urllib.parse import urlparse

# Add the module directory to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
module_dir = os.path.join(current_dir, 'module')
sys.path.append(module_dir)

# Import the vulnerability scanner modules
from modules.broken_access_control import BrokenAccessControlScanner
from modules.cryptographic_failures import CryptographicFailuresScanner

def validate_url(url):
    """Validate and format the input URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        result = urlparse(url)
        if all([result.scheme, result.netloc]):
            return url
        return None
    except:
        return None
def get_current_time():
    try:
        response = requests.get('http://worldtimeapi.org/api/ip', timeout=5)
        return response.json()['datetime']
    except:
        # Fallback to local time
        from datetime import datetime
        return str(datetime.now())

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Scan a website for OWASP Top 10 vulnerabilities')
    parser.add_argument('url', help='Target URL to scan (e.g., https://example.com)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--no-access-control', action='store_true', help='Skip Broken Access Control scan')
    parser.add_argument('--no-crypto', action='store_true', help='Skip Cryptographic Failures scan')
    
    args = parser.parse_args()
    
    # Validate URL
    target_url = validate_url(args.url)
    if not target_url:
        print(f"Error: Invalid URL format: {args.url}")
        print("Please provide a valid URL (e.g., https://example.com)")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print(f"OWASP Top 10 Vulnerability Scanner")
    print("=" * 60)
    print(f"Target: {target_url}")
    print("Started at: " + get_current_time())
    
    # Initial connection test
    try:
        response = requests.get(target_url, timeout=10)
        print(f"Connection successful: HTTP {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {target_url}: {e}")
        sys.exit(1)
    
    # Initialize scanners
    scan_results = {"vulnerabilities": []}
    
    # Run Broken Access Control scan
    if not args.no_access_control:
        print("\n1. Scanning for Broken Access Control vulnerabilities...")
        access_scanner = BrokenAccessControlScanner(target_url, verbose=args.verbose)
        access_results = access_scanner.scan()
        
        if access_results:
            scan_results["vulnerabilities"].extend(access_results)
            print(f"  [!] Found {len(access_results)} potential Broken Access Control issues")
        else:
            print("  [✓] No Broken Access Control issues detected")
    
    # Run Cryptographic Failures scan
    if not args.no_crypto:
        print("\n2. Scanning for Cryptographic Failures...")
        crypto_scanner = CryptographicFailuresScanner(target_url, verbose=args.verbose)
        crypto_results = crypto_scanner.scan()
        
        if crypto_results:
            scan_results["vulnerabilities"].extend(crypto_results)
            print(f"  [!] Found {len(crypto_results)} potential Cryptographic Failure issues")
        else:
            print("  [✓] No Cryptographic Failure issues detected")
    
    # Display result summary
    print("\n" + "=" * 60)
    print("Scan Summary")
    print("=" * 60)
    
    if not scan_results["vulnerabilities"]:
        print("No vulnerabilities detected.")
    else:
        print(f"Total vulnerabilities found: {len(scan_results['vulnerabilities'])}")
        
        for i, vuln in enumerate(scan_results["vulnerabilities"], 1):
            print(f"\nVulnerability #{i}:")
            print(f"  Type: {vuln['type']}")
            print(f"  Risk Level: {vuln['risk_level']}")
            print(f"  Description: {vuln['description']}")
            print(f"  Location: {vuln['location']}")
            if vuln.get('recommendation'):
                print(f"  Recommendation: {vuln['recommendation']}")
    
    print("\nScan completed.")

if __name__ == "__main__":
    main()