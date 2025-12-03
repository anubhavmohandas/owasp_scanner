#!/usr/bin/env python3
"""
OWASP Top 10 Automated Security Scanner
A comprehensive, automated web application security scanner based on OWASP Top 10 2021

Author: Anubhav Mohandas
Version: 2.0
"""

import argparse
import requests
import json
import re
import time
import ssl
import subprocess
import concurrent.futures
import socket
import dns.resolver
import datetime
import sys
from pathlib import Path
from typing import Dict, List, Any
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class VulnerabilityScorer:
    """Score and prioritize vulnerabilities based on severity and exploitability"""

    CVSS_WEIGHTS = {
        'Critical': 10.0,
        'High': 8.5,
        'Medium': 5.0,
        'Low': 2.0,
        'Info': 0.5
    }

    @staticmethod
    def score_vulnerability(risk_level: str, findings_count: int) -> float:
        """Calculate vulnerability score"""
        base_score = VulnerabilityScorer.CVSS_WEIGHTS.get(risk_level, 0.0)
        # Increase score if multiple findings
        multiplier = min(1.0 + (findings_count - 1) * 0.1, 2.0)
        return round(base_score * multiplier, 2)

    @staticmethod
    def get_remediation_priority(score: float) -> str:
        """Get remediation priority based on score"""
        if score >= 9.0:
            return "IMMEDIATE"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 1.0:
            return "LOW"
        else:
            return "INFO"


class ReportGenerator:
    """Generate comprehensive security reports in multiple formats"""

    @staticmethod
    def generate_html_report(results: Dict, output_file: str, scan_duration: float):
        """Generate detailed HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.1em; opacity: 0.9; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }}
        .summary-card h3 {{ color: #666; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }}
        .summary-card .value {{ font-size: 2.5em; font-weight: bold; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        .content {{ padding: 30px; }}
        .vulnerability-section {{ margin-bottom: 40px; }}
        .vulnerability-section h2 {{ color: #333; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 3px solid #667eea; }}
        .vuln-card {{ background: #f8f9fa; border-left: 5px solid #667eea; padding: 20px; margin-bottom: 20px; border-radius: 5px; }}
        .vuln-card.critical {{ border-left-color: #dc3545; background: #ffe5e5; }}
        .vuln-card.high {{ border-left-color: #fd7e14; background: #fff4e5; }}
        .vuln-card.medium {{ border-left-color: #ffc107; background: #fffbea; }}
        .vuln-card.low {{ border-left-color: #28a745; background: #e8f5e9; }}
        .vuln-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .vuln-title {{ font-size: 1.3em; font-weight: bold; color: #333; }}
        .risk-badge {{ padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em; }}
        .risk-badge.critical {{ background: #dc3545; }}
        .risk-badge.high {{ background: #fd7e14; }}
        .risk-badge.medium {{ background: #ffc107; color: #333; }}
        .risk-badge.low {{ background: #28a745; }}
        .vuln-details {{ margin-top: 15px; }}
        .detail-row {{ margin: 10px 0; }}
        .detail-label {{ font-weight: bold; color: #555; display: inline-block; min-width: 120px; }}
        .detail-value {{ color: #333; }}
        .findings-list {{ background: white; padding: 15px; border-radius: 5px; margin-top: 10px; }}
        .findings-list ul {{ margin-left: 20px; }}
        .findings-list li {{ margin: 5px 0; color: #555; }}
        .footer {{ background: #333; color: white; padding: 20px; text-align: center; border-radius: 0 0 10px 10px; }}
        .score-bar {{ background: #e9ecef; height: 30px; border-radius: 15px; overflow: hidden; margin-top: 10px; }}
        .score-fill {{ height: 100%; background: linear-gradient(90deg, #28a745, #ffc107, #fd7e14, #dc3545); display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; transition: width 0.5s; }}
        .recommendation {{ background: #e7f3ff; border-left: 4px solid #2196F3; padding: 15px; margin-top: 15px; border-radius: 5px; }}
        .recommendation strong {{ color: #1976D2; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ OWASP Security Scan Report</h1>
            <p>Automated Web Application Security Assessment</p>
            <p style="margin-top: 10px; opacity: 0.8;">Generated: {timestamp}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Target</h3>
                <div class="value" style="font-size: 1.2em; color: #667eea;">{target}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="value" style="font-size: 1.5em; color: #667eea;">{duration}s</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="value critical">{critical_count}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="value high">{high_count}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="value medium">{medium_count}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="value low">{low_count}</div>
            </div>
        </div>

        <div class="content">
            {vulnerabilities_html}
        </div>

        <div class="footer">
            <p>OWASP Top 10 Automated Scanner v2.0 | Created by Anubhav Mohandas</p>
            <p style="margin-top: 10px; opacity: 0.8;">This report is for authorized security testing only</p>
        </div>
    </div>
</body>
</html>
"""

        # Calculate statistics
        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        vulnerabilities_html = ""

        for target, target_results in results.items():
            for category, result in target_results.items():
                risk_level = result.get('risk_level', 'Unknown')
                findings = result.get('findings', [])

                if risk_level in risk_counts:
                    if len(findings) > 0:
                        risk_counts[risk_level] += 1

                if findings:
                    # Generate vulnerability card
                    risk_class = risk_level.lower()
                    findings_count = len(findings)
                    score = VulnerabilityScorer.score_vulnerability(risk_level, findings_count)
                    priority = VulnerabilityScorer.get_remediation_priority(score)

                    findings_html = "<div class='findings-list'><ul>"
                    for finding in findings[:10]:  # Limit to first 10 findings
                        findings_html += f"<li>{finding}</li>"
                    if len(findings) > 10:
                        findings_html += f"<li><i>... and {len(findings) - 10} more findings</i></li>"
                    findings_html += "</ul></div>"

                    # Get detailed findings if available
                    details_html = ""
                    if 'details' in result and result['details']:
                        details_html = "<div class='detail-row'><span class='detail-label'>Detailed Findings:</span></div>"
                        for detail_category, detail_findings in result['details'].items():
                            if detail_findings:
                                details_html += f"<div class='detail-row' style='margin-left: 20px;'>"
                                details_html += f"<span class='detail-label'>{detail_category.replace('_', ' ').title()}:</span> "
                                details_html += f"<span class='detail-value'>{len(detail_findings)} issues found</span>"
                                details_html += "</div>"

                    vulnerabilities_html += f"""
                    <div class="vuln-card {risk_class}">
                        <div class="vuln-header">
                            <div class="vuln-title">{category.replace('_', ' ').replace('A0', 'A0').replace(':', ' -')}</div>
                            <span class="risk-badge {risk_class}">{risk_level}</span>
                        </div>
                        <div class="vuln-details">
                            <div class="detail-row">
                                <span class="detail-label">Risk Score:</span>
                                <span class="detail-value">{score}/10.0</span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label">Priority:</span>
                                <span class="detail-value">{priority}</span>
                            </div>
                            <div class="detail-row">
                                <span class="detail-label">Findings Count:</span>
                                <span class="detail-value">{findings_count}</span>
                            </div>
                            {details_html}
                            {findings_html}
                        </div>
                        <div class="recommendation">
                            <strong>💡 Recommendation:</strong> Review and remediate all identified issues based on priority level.
                        </div>
                    </div>
                    """

        if not vulnerabilities_html:
            vulnerabilities_html = "<div style='text-align: center; padding: 40px; color: #28a745;'><h2>✅ No significant vulnerabilities detected!</h2></div>"

        # Fill template
        html_content = html_template.format(
            timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            target=list(results.keys())[0] if results else 'N/A',
            duration=round(scan_duration, 2),
            critical_count=risk_counts['Critical'],
            high_count=risk_counts['High'],
            medium_count=risk_counts['Medium'],
            low_count=risk_counts['Low'],
            vulnerabilities_html=vulnerabilities_html
        )

        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_file

    @staticmethod
    def generate_json_report(results: Dict, output_file: str, scan_duration: float):
        """Generate JSON report"""
        report = {
            'scan_metadata': {
                'timestamp': datetime.datetime.now().isoformat(),
                'scanner_version': '2.0',
                'scan_duration_seconds': round(scan_duration, 2)
            },
            'results': results
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)

        return output_file

    @staticmethod
    def generate_text_report(results: Dict, output_file: str, scan_duration: float):
        """Generate text report"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("OWASP TOP 10 SECURITY SCAN REPORT".center(80))
        report_lines.append("=" * 80)
        report_lines.append(f"\nGenerated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Scan Duration: {round(scan_duration, 2)} seconds")
        report_lines.append("\n" + "=" * 80)

        # Calculate statistics
        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

        for target, target_results in results.items():
            report_lines.append(f"\nTarget: {target}")
            report_lines.append("-" * 80)

            for category, result in target_results.items():
                risk_level = result.get('risk_level', 'Unknown')
                findings = result.get('findings', [])

                if risk_level in risk_counts and len(findings) > 0:
                    risk_counts[risk_level] += 1

                if findings:
                    report_lines.append(f"\n[{risk_level}] {category}")
                    report_lines.append(f"  Findings: {len(findings)}")
                    for finding in findings[:5]:
                        report_lines.append(f"  • {finding}")
                    if len(findings) > 5:
                        report_lines.append(f"  ... and {len(findings) - 5} more")

        report_lines.append("\n" + "=" * 80)
        report_lines.append("SUMMARY")
        report_lines.append("=" * 80)
        report_lines.append(f"Critical: {risk_counts['Critical']}")
        report_lines.append(f"High: {risk_counts['High']}")
        report_lines.append(f"Medium: {risk_counts['Medium']}")
        report_lines.append(f"Low: {risk_counts['Low']}")
        report_lines.append("=" * 80)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))

        return output_file


class ProgressTracker:
    """Track and display scan progress"""

    def __init__(self, total_checks: int = 10):
        self.total_checks = total_checks
        self.current_check = 0
        self.start_time = time.time()

    def update(self, check_name: str):
        """Update progress"""
        self.current_check += 1
        elapsed = time.time() - self.start_time
        percent = (self.current_check / self.total_checks) * 100

        bar_length = 40
        filled_length = int(bar_length * self.current_check // self.total_checks)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)

        print(f"\r[{bar}] {percent:.1f}% | {check_name[:50]:<50} | {elapsed:.1f}s", end='', flush=True)

        if self.current_check >= self.total_checks:
            print()  # New line after completion


# Import the comprehensive scanner class from owasp_scanner.py
from owasp_scanner import OWASPScanner


def print_banner():
    """Display scanner banner"""
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
║         ⚡ AUTOMATED SECURITY SCANNER v2.0 ⚡                        ║
║         🛡️  OWASP Top 10 2021 Vulnerability Detection               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

    🎯 Comprehensive Coverage   ✅ Automated Detection
    📊 Multiple Report Formats  🚀 Fast & Efficient
    🔍 Deep Analysis           💾 Detailed Logging

"""
    print(banner)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='OWASP Top 10 Automated Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Basic scan:
    python scanner.py https://example.com

  Full scan with HTML report:
    python scanner.py https://example.com -o report.html --format html

  Scan with subdomain discovery:
    python scanner.py https://example.com -s --max-subdomains 20

  Generate all report formats:
    python scanner.py https://example.com --all-formats

For more information, visit: https://github.com/yourusername/owasp-scanner
        '''
    )

    parser.add_argument('url', help='Target URL to scan (e.g., https://example.com)')
    parser.add_argument('-o', '--output', help='Output file for the report (default: auto-generated)', default=None)
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

    # Display banner
    if not args.no_banner:
        print_banner()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url

    print(f"\n{'='*70}")
    print(f"🎯 Target: {args.url}")
    print(f"🔍 Subdomain Discovery: {'Enabled' if args.subdomains else 'Disabled'}")
    print(f"🧵 Threads: {args.threads}")
    print(f"📊 Report Format: {args.format.upper()}")
    print(f"{'='*70}\n")

    # Initialize progress tracker
    progress = ProgressTracker(total_checks=10)

    # Start scan
    start_time = time.time()

    try:
        scanner = OWASPScanner(
            args.url,
            output_file=None,  # We'll handle output separately
            scan_subdomains=args.subdomains,
            threads=args.threads,
            max_subdomains=args.max_subdomains
        )

        print("\n🚀 Starting comprehensive OWASP Top 10 security scan...\n")

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

        print(f"\n🎯 Scanning {len(targets)} target(s)...\n")

        # Scan all targets
        results = {}
        for target in targets:
            target_results = scanner.scan_single_target(target)
            results[target] = target_results
            progress.update(f"Scanned {target}")

        scanner.results = results

        scan_duration = time.time() - start_time

        print(f"\n\n✅ Scan completed in {round(scan_duration, 2)} seconds!")

        # Generate reports
        print("\n📝 Generating reports...")

        # Auto-generate output filename if not provided
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = urlparse(args.url).netloc.replace(':', '_')

        if args.all_formats:
            # Generate all formats
            html_file = f"scan_report_{domain}_{timestamp}.html"
            json_file = f"scan_report_{domain}_{timestamp}.json"
            text_file = f"scan_report_{domain}_{timestamp}.txt"

            ReportGenerator.generate_html_report(results, html_file, scan_duration)
            ReportGenerator.generate_json_report(results, json_file, scan_duration)
            ReportGenerator.generate_text_report(results, text_file, scan_duration)

            print(f"✅ HTML report: {html_file}")
            print(f"✅ JSON report: {json_file}")
            print(f"✅ Text report: {text_file}")
        else:
            # Generate single format
            if args.output:
                output_file = args.output
            else:
                ext = {'html': '.html', 'json': '.json', 'text': '.txt'}[args.format]
                output_file = f"scan_report_{domain}_{timestamp}{ext}"

            if args.format == 'html':
                ReportGenerator.generate_html_report(results, output_file, scan_duration)
            elif args.format == 'json':
                ReportGenerator.generate_json_report(results, output_file, scan_duration)
            else:
                ReportGenerator.generate_text_report(results, output_file, scan_duration)

            print(f"✅ Report saved: {output_file}")

        # Print summary
        print("\n" + "="*70)
        print("📊 SCAN SUMMARY")
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

        if risk_counts['Critical'] > 0 or risk_counts['High'] > 0:
            print("\n⚠️  ATTENTION: Critical or High-risk vulnerabilities detected!")
            print("   Review the generated report and remediate immediately.")
        else:
            print("\n✅ No critical vulnerabilities detected. Review full report for details.")

        print("\n" + "="*70)
        print("Thank you for using OWASP Automated Scanner!")
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
