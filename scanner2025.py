#!/usr/bin/env python3
"""
OWASP Top 10:2025 Automated Security Scanner
Enhanced scanner supporting the latest OWASP Top 10:2025 categories

Author: Anubhav Mohandas
Version: 2.1.0 (OWASP 2025 Edition)
"""

import argparse
import requests
import json
import sys
import time
import datetime
from pathlib import Path
from typing import Dict, List, Any
from urllib.parse import urlparse

# Import report generators and utilities from scanner.py
from scanner import VulnerabilityScorer, ReportGenerator, ProgressTracker, print_banner

# Import OWASP scanner
from owasp_scanner import OWASPScanner

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class OWASP2025Scanner(OWASPScanner):
    """
    Enhanced scanner for OWASP Top 10:2025

    OWASP Top 10:2025 Order:
    1. A01:2025 - Broken Access Control
    2. A02:2025 - Security Misconfiguration (moved from #5)
    3. A03:2025 - Software Supply Chain Failures (NEW)
    4. A04:2025 - Cryptographic Failures (moved from #2)
    5. A05:2025 - Injection (moved from #3)
    6. A06:2025 - Insecure Design (moved from #4)
    7. A07:2025 - Authentication Failures (similar to 2021 #7)
    8. A08:2025 - Software or Data Integrity Failures (similar to 2021 #8)
    9. A09:2025 - Logging & Alerting Failures (evolved from 2021 #9)
    10. A10:2025 - Mishandling of Exceptional Conditions (NEW)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.owasp_version = "2025"

    def scan_single_target(self, url):
        """Scan a single target for OWASP Top 10:2025 vulnerabilities"""
        print(f"[*] Scanning {url} (OWASP Top 10:2025)")

        target_results = {
            # Re-ordered according to OWASP 2025
            "A01:2025-Broken_Access_Control": self.check_broken_access_control(url),
            "A02:2025-Security_Misconfiguration": self.check_security_misconfiguration(url),
            "A03:2025-Software_Supply_Chain_Failures": self.check_supply_chain_failures(url),
            "A04:2025-Cryptographic_Failures": self.check_cryptographic_failures(url),
            "A05:2025-Injection": self.check_injection_vulnerabilities(url),
            "A06:2025-Insecure_Design": self.check_insecure_design(url),
            "A07:2025-Authentication_Failures": self.check_authentication_failures(url),
            "A08:2025-Software_Data_Integrity_Failures": self.check_data_integrity(url),
            "A09:2025-Logging_Alerting_Failures": self.check_logging_monitoring(url),
            "A10:2025-Mishandling_Exceptional_Conditions": self.check_exceptional_conditions(url),
        }

        return target_results

    def check_supply_chain_failures(self, url):
        """Check for software supply chain vulnerabilities (NEW in 2025)"""
        results = {"findings": [], "risk_level": "Unknown", "details": {}}

        try:
            from modules.supply_chain_failures import SupplyChainFailuresScanner

            scanner = SupplyChainFailuresScanner(url, verbose=False)
            vulnerabilities = scanner.scan()

            if vulnerabilities:
                results["findings"] = [v['description'] for v in vulnerabilities]
                # Determine risk level from vulnerabilities
                risk_levels = [v.get('risk_level', 'Low') for v in vulnerabilities]
                if 'Critical' in risk_levels:
                    results["risk_level"] = "Critical"
                elif 'High' in risk_levels:
                    results["risk_level"] = "High"
                elif 'Medium' in risk_levels:
                    results["risk_level"] = "Medium"
                else:
                    results["risk_level"] = "Low"

                results["details"]["vulnerabilities"] = vulnerabilities
            else:
                results["risk_level"] = "Low"
                results["findings"].append("No software supply chain issues detected")

        except ImportError:
            results["findings"].append("Supply chain scanner module not available")
            results["risk_level"] = "Unknown"
        except Exception as e:
            results["error"] = str(e)
            results["findings"].append(f"Error during supply chain scan: {str(e)}")

        return results

    def check_exceptional_conditions(self, url):
        """Check for mishandling of exceptional conditions (NEW in 2025)"""
        results = {"findings": [], "risk_level": "Unknown", "details": {}}

        try:
            from modules.exceptional_conditions import ExceptionalConditionsScanner

            scanner = ExceptionalConditionsScanner(url, verbose=False)
            vulnerabilities = scanner.scan()

            if vulnerabilities:
                results["findings"] = [v['description'] for v in vulnerabilities]
                # Determine risk level
                risk_levels = [v.get('risk_level', 'Low') for v in vulnerabilities]
                if 'Critical' in risk_levels or 'High' in risk_levels:
                    results["risk_level"] = "High"
                elif 'Medium' in risk_levels:
                    results["risk_level"] = "Medium"
                else:
                    results["risk_level"] = "Low"

                results["details"]["vulnerabilities"] = vulnerabilities
            else:
                results["risk_level"] = "Low"
                results["findings"].append("Proper exception handling detected")

        except ImportError:
            results["findings"].append("Exceptional conditions scanner module not available")
            results["risk_level"] = "Unknown"
        except Exception as e:
            results["error"] = str(e)
            results["findings"].append(f"Error during exceptional conditions scan: {str(e)}")

        return results


def print_owasp_2025_banner():
    """Display OWASP 2025 specific banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ███╗   ██╗██╗    ██╗ █████╗ ███████╗██████╗                       ║
║   ████╗  ██║██║    ██║██╔══██╗██╔════╝██╔══██╗                      ║
║   ██╔██╗ ██║██║ █╗ ██║███████║███████╗██████╔╝                      ║
║   ██║╚██╗██║██║███╗██║██╔══██║╚════██║██╔═══╝                       ║
║   ██║ ╚████║╚███╔███╔╝██║  ██║███████║██║                           ║
║   ╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝                           ║
║                                                                      ║
║         ⚡ AUTOMATED SECURITY SCANNER v2.1 ⚡                        ║
║         🛡️  OWASP Top 10:2025 Vulnerability Detection               ║
║         ✨ NOW WITH LATEST 2025 CATEGORIES ✨                        ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

    🎯 OWASP Top 10:2025 Coverage:

    1️⃣  A01:2025 - Broken Access Control
    2️⃣  A02:2025 - Security Misconfiguration ⬆️
    3️⃣  A03:2025 - Software Supply Chain Failures ✨ NEW
    4️⃣  A04:2025 - Cryptographic Failures
    5️⃣  A05:2025 - Injection
    6️⃣  A06:2025 - Insecure Design
    7️⃣  A07:2025 - Authentication Failures
    8️⃣  A08:2025 - Software or Data Integrity Failures
    9️⃣  A09:2025 - Logging & Alerting Failures
    🔟 A10:2025 - Mishandling of Exceptional Conditions ✨ NEW

    📊 Enhanced Detection  ✅ Latest Standards
    🚀 Fast & Efficient    💾 Detailed Reports

"""
    print(banner)


def main():
    """Main function for OWASP 2025 scanner"""
    parser = argparse.ArgumentParser(
        description='OWASP Top 10:2025 Automated Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Basic OWASP 2025 scan:
    python scanner2025.py https://example.com

  Full scan with HTML report:
    python scanner2025.py https://example.com -o report.html --format html

  Scan with subdomain discovery:
    python scanner2025.py https://example.com -s --max-subdomains 20

  Generate all report formats:
    python scanner2025.py https://example.com --all-formats

OWASP Top 10:2025 Changes:
  ✨ NEW: A03:2025 - Software Supply Chain Failures
  ✨ NEW: A10:2025 - Mishandling of Exceptional Conditions
  ⬆️  Security Misconfiguration moved to #2 (increased priority)
  🔄 Re-ordered categories reflect current threat landscape

For more information, visit: https://github.com/anubhavmohandas/owasp_scanner
        '''
    )

    parser.add_argument('url', help='Target URL to scan (e.g., https://example.com)')
    parser.add_argument('-o', '--output', help='Output file for the report', default=None)
    parser.add_argument('-f', '--format', choices=['html', 'json', 'text'], default='html',
                       help='Report format (default: html)')
    parser.add_argument('-s', '--subdomains', action='store_true',
                       help='Discover and scan subdomains')
    parser.add_argument('-m', '--max-subdomains', type=int, default=50,
                       help='Maximum number of subdomains to scan (default: 50)')
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of concurrent threads (default: 5)')
    parser.add_argument('--all-formats', action='store_true',
                       help='Generate reports in all formats')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--no-banner', action='store_true',
                       help='Disable banner display')

    args = parser.parse_args()

    # Display OWASP 2025 banner
    if not args.no_banner:
        print_owasp_2025_banner()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url

    print(f"\n{'='*70}")
    print(f"🎯 Target: {args.url}")
    print(f"📋 Standard: OWASP Top 10:2025")
    print(f"🔍 Subdomain Discovery: {'Enabled' if args.subdomains else 'Disabled'}")
    print(f"🧵 Threads: {args.threads}")
    print(f"📊 Report Format: {args.format.upper()}")
    print(f"{'='*70}\n")

    # Initialize progress tracker
    progress = ProgressTracker(total_checks=10)

    # Start scan
    start_time = time.time()

    try:
        scanner = OWASP2025Scanner(
            args.url,
            output_file=None,
            scan_subdomains=args.subdomains,
            threads=args.threads,
            max_subdomains=args.max_subdomains
        )

        print("\n🚀 Starting comprehensive OWASP Top 10:2025 security scan...\n")

        # Run scan with progress tracking
        targets = [args.url]
        if args.subdomains:
            print("📡 Discovering subdomains...")
            discovered = scanner.discover_subdomains()
            if discovered:
                from concurrent.futures import ThreadPoolExecutor
                print("🔍 Verifying subdomain connectivity...")
                with ThreadPoolExecutor(max_workers=args.threads) as executor:
                    verified = list(filter(None, executor.map(scanner.verify_subdomain_connectivity, discovered)))
                targets.extend(verified)

        print(f"\n🎯 Scanning {len(targets)} target(s) with OWASP 2025 checks...\n")

        # Scan all targets
        results = {}
        for target in targets:
            target_results = scanner.scan_single_target(target)
            results[target] = target_results
            progress.update(f"Scanned {target}")

        scanner.results = results

        scan_duration = time.time() - start_time

        print(f"\n\n✅ OWASP 2025 scan completed in {round(scan_duration, 2)} seconds!")

        # Generate reports
        print("\n📝 Generating reports...")

        # Auto-generate output filename
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = urlparse(args.url).netloc.replace(':', '_')

        if args.all_formats:
            html_file = f"owasp2025_report_{domain}_{timestamp}.html"
            json_file = f"owasp2025_report_{domain}_{timestamp}.json"
            text_file = f"owasp2025_report_{domain}_{timestamp}.txt"

            ReportGenerator.generate_html_report(results, html_file, scan_duration)
            ReportGenerator.generate_json_report(results, json_file, scan_duration)
            ReportGenerator.generate_text_report(results, text_file, scan_duration)

            print(f"✅ HTML report: {html_file}")
            print(f"✅ JSON report: {json_file}")
            print(f"✅ Text report: {text_file}")
        else:
            if args.output:
                output_file = args.output
            else:
                ext = {'html': '.html', 'json': '.json', 'text': '.txt'}[args.format]
                output_file = f"owasp2025_report_{domain}_{timestamp}{ext}"

            if args.format == 'html':
                ReportGenerator.generate_html_report(results, output_file, scan_duration)
            elif args.format == 'json':
                ReportGenerator.generate_json_report(results, output_file, scan_duration)
            else:
                ReportGenerator.generate_text_report(results, output_file, scan_duration)

            print(f"✅ Report saved: {output_file}")

        # Print summary
        print("\n" + "="*70)
        print("📊 OWASP 2025 SCAN SUMMARY")
        print("="*70)

        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for target, target_results in results.items():
            for category, result in target_results.items():
                risk_level = result.get('risk_level', 'Unknown')
                findings = result.get('findings', [])
                if risk_level in risk_counts and len(findings) > 0:
                    risk_counts[risk_level] += 1

        print(f"🔴 Critical Issues: {risk_counts['Critical']}")
        print(f"🟠 High Issues: {risk_counts['High']}")
        print(f"🟡 Medium Issues: {risk_counts['Medium']}")
        print(f"🟢 Low Issues: {risk_counts['Low']}")
        print("="*70)

        # Highlight new 2025 categories
        print("\n✨ OWASP 2025 New Categories:")
        print("  • A03:2025 - Software Supply Chain Failures")
        print("  • A10:2025 - Mishandling of Exceptional Conditions")

        if risk_counts['Critical'] > 0 or risk_counts['High'] > 0:
            print("\n⚠️  ATTENTION: Critical or High-risk vulnerabilities detected!")
            print("   Review the generated report and remediate immediately.")
        else:
            print("\n✅ No critical vulnerabilities detected. Review full report for details.")

        print("\n" + "="*70)
        print("Thank you for using OWASP 2025 Automated Scanner!")
        print("="*70 + "\n")

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error during scan: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
