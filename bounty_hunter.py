#!/usr/bin/env python3
"""
Bug Bounty Hunter - Automated Security Testing Platform
Comprehensive automated bug bounty tool with OWASP scanning, reconnaissance,
directory enumeration, and ready-to-submit vulnerability reports

Author: Anubhav Mohandas
Version: 3.0 (Bug Bounty Edition)
"""

import argparse
import requests
import json
import sys
import time
import datetime
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

# Import existing scanners
from scanner2025 import OWASP2025Scanner, VulnerabilityScorer
from scanner import ReportGenerator

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class BugBountyProgram:
    """Parse and store bug bounty program details"""

    def __init__(self, name: str = "", scope: List[str] = None, out_of_scope: List[str] = None,
                 bounty_tiers: Dict[str, str] = None, description: str = ""):
        self.name = name
        self.scope = scope or []
        self.out_of_scope = out_of_scope or []
        self.bounty_tiers = bounty_tiers or {}
        self.description = description

    @classmethod
    def from_text(cls, program_text: str):
        """Parse bug bounty program from text description"""
        program = cls()

        # Extract program name
        name_match = re.search(r'([\w\s]+(?:Program|Security|Bug Bounty))', program_text, re.IGNORECASE)
        if name_match:
            program.name = name_match.group(1).strip()

        # Extract bounty tiers
        bounty_pattern = r'(Low|Medium|High|Critical|Exceptional)\s*(\d+\.?\d*)\s*-\s*(\d+\.?\d*)'
        for match in re.finditer(bounty_pattern, program_text, re.IGNORECASE):
            severity = match.group(1)
            min_score = match.group(2)
            max_score = match.group(3)
            program.bounty_tiers[severity] = f"{min_score} - {max_score}"

        # Extract monetary rewards
        reward_pattern = r'(Low|Medium|High|Critical|Exceptional)\s*€?\$?(\d+(?:,\d+)?)'
        tier_rewards = {}
        for match in re.finditer(reward_pattern, program_text):
            severity = match.group(1)
            amount = match.group(2).replace(',', '')
            tier_rewards[severity] = amount

        if tier_rewards:
            program.bounty_tiers.update({f"{k}_reward": v for k, v in tier_rewards.items()})

        program.description = program_text
        return program

    def get_severity_from_score(self, cvss_score: float) -> str:
        """Map CVSS score to program severity tier"""
        if cvss_score >= 9.5:
            return "Exceptional"
        elif cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"

    def get_bounty_range(self, severity: str) -> Optional[str]:
        """Get bounty range for severity"""
        return self.bounty_tiers.get(severity, "Not specified")


class ReconnaissanceEngine:
    """Enhanced reconnaissance and information gathering"""

    def __init__(self, target_url: str, verbose: bool = False):
        self.target_url = target_url
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.results = {
            'technologies': [],
            'endpoints': [],
            'subdomains': [],
            'interesting_files': [],
            'security_headers': {},
            'cookies': [],
            'forms': [],
            'javascript_files': [],
            'api_endpoints': []
        }

    def log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            print(f"  [RECON] {message}")

    def run_full_recon(self):
        """Run complete reconnaissance"""
        print("\n🔍 Starting Reconnaissance Phase...")

        self.detect_technologies()
        self.find_endpoints()
        self.analyze_javascript()
        self.find_api_endpoints()
        self.check_security_headers()

        return self.results

    def detect_technologies(self):
        """Detect technologies used by the target"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check headers for technology indicators
            tech_headers = {
                'Server': response.headers.get('Server', ''),
                'X-Powered-By': response.headers.get('X-Powered-By', ''),
                'X-AspNet-Version': response.headers.get('X-AspNet-Version', ''),
                'X-Generator': response.headers.get('X-Generator', '')
            }

            technologies = []
            for header, value in tech_headers.items():
                if value:
                    technologies.append(f"{header}: {value}")
                    self.log(f"Technology detected: {header}: {value}")

            # Check HTML for technology signatures
            soup = BeautifulSoup(response.text, 'html.parser')

            # Meta generators
            meta_gen = soup.find('meta', {'name': 'generator'})
            if meta_gen and meta_gen.get('content'):
                technologies.append(f"Generator: {meta_gen['content']}")

            # Check for common frameworks
            if 'wp-content' in response.text or 'wp-includes' in response.text:
                technologies.append("WordPress")
            if 'Drupal' in response.text:
                technologies.append("Drupal")
            if 'ng-app' in response.text or 'angular' in response.text.lower():
                technologies.append("Angular")
            if 'react' in response.text.lower():
                technologies.append("React")
            if 'vue' in response.text.lower():
                technologies.append("Vue.js")

            self.results['technologies'] = list(set(technologies))

        except Exception as e:
            self.log(f"Error in technology detection: {e}")

    def find_endpoints(self):
        """Find all endpoints/links on the page"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            endpoints = set()

            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('/','http')):
                    full_url = urljoin(self.target_url, href)
                    if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                        endpoints.add(full_url)

            # Find forms
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get')
                inputs = [inp.get('name', '') for inp in form.find_all('input')]

                self.results['forms'].append({
                    'action': urljoin(self.target_url, action),
                    'method': method,
                    'inputs': inputs
                })

            self.results['endpoints'] = list(endpoints)
            self.log(f"Found {len(endpoints)} endpoints")

        except Exception as e:
            self.log(f"Error finding endpoints: {e}")

    def analyze_javascript(self):
        """Analyze JavaScript files for interesting patterns"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            js_files = []
            for script in soup.find_all('script', src=True):
                js_url = urljoin(self.target_url, script['src'])
                js_files.append(js_url)

                # Try to fetch and analyze JS file
                try:
                    js_response = self.session.get(js_url, timeout=5, verify=False)
                    js_content = js_response.text

                    # Look for API endpoints
                    api_patterns = [
                        r'["\'/]api["\'/][\w/]+',
                        r'["\'/]v\d+["\'/][\w/]+',
                        r'https?://[^"\']+/api/',
                    ]

                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_content)
                        for match in matches:
                            self.results['api_endpoints'].append(match.strip('"\''))

                    # Look for credentials/keys (potential issues)
                    if re.search(r'(api[_-]?key|secret|password|token)\s*[:=]', js_content, re.I):
                        self.results['interesting_files'].append({
                            'file': js_url,
                            'reason': 'Contains potential API keys or secrets'
                        })

                except:
                    pass

            self.results['javascript_files'] = js_files

        except Exception as e:
            self.log(f"Error analyzing JavaScript: {e}")

    def find_api_endpoints(self):
        """Discover potential API endpoints"""
        common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/graphql',
            '/rest', '/api/docs', '/swagger', '/openapi.json',
            '/api/user', '/api/admin', '/api/auth',
            '/v1', '/v2', '/v3'
        ]

        for path in common_api_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)

                if response.status_code in [200, 201, 401, 403]:
                    self.results['api_endpoints'].append({
                        'url': url,
                        'status': response.status_code,
                        'type': 'Discovered API endpoint'
                    })
                    self.log(f"Found API endpoint: {url} (HTTP {response.status_code})")

            except:
                continue

    def check_security_headers(self):
        """Check for security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'Referrer-Policy': response.headers.get('Referrer-Policy'),
                'Permissions-Policy': response.headers.get('Permissions-Policy')
            }

            self.results['security_headers'] = {k: v for k, v in security_headers.items() if v}

        except Exception as e:
            self.log(f"Error checking security headers: {e}")


class DirectoryEnumerator:
    """Directory and file enumeration (dirbuster-style)"""

    def __init__(self, target_url: str, wordlist: List[str] = None, threads: int = 10):
        self.target_url = target_url
        self.threads = threads
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Mozilla/5.0'}
        self.found_paths = []

        # Default mini wordlist if none provided
        self.wordlist = wordlist or self.get_default_wordlist()

    def get_default_wordlist(self) -> List[str]:
        """Get default wordlist for common paths"""
        return [
            # Admin panels
            'admin', 'administrator', 'admin-panel', 'wp-admin', 'cpanel',
            'admin.php', 'admin/', 'admin/login', 'administrator/', 'moderator/',

            # Common files
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'phpinfo.php', 'info.php', 'test.php', 'config.php',

            # API endpoints
            'api', 'api/v1', 'api/v2', 'graphql', 'rest', 'swagger',

            # Backup files
            'backup', 'backup.zip', 'backup.sql', 'database.sql', 'db.sql',
            'www.zip', 'website.zip', 'old', 'backup.tar.gz',

            # Config files
            '.env', '.git', '.svn', 'config', 'configuration.php',
            'settings.py', 'database.yml', 'config.json',

            # Common directories
            'uploads', 'files', 'images', 'assets', 'static',
            'media', 'content', 'data', 'includes', 'inc',
            'js', 'css', 'fonts', 'lib', 'vendor',

            # Development
            'dev', 'development', 'test', 'testing', 'staging',
            'debug', 'temp', 'tmp', 'cache',

            # Documentation
            'docs', 'doc', 'documentation', 'readme.md', 'README.md',
            'CHANGELOG.md', 'LICENSE',

            # Source control
            '.git/HEAD', '.git/config', '.svn/entries',

            # Package managers
            'package.json', 'composer.json', 'requirements.txt',
            'Gemfile', 'pom.xml', 'build.gradle',
        ]

    def enumerate(self):
        """Perform directory enumeration"""
        print(f"\n📂 Starting Directory Enumeration ({len(self.wordlist)} paths)...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_path, path): path for path in self.wordlist}

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 20 == 0:
                    print(f"  Progress: {completed}/{len(self.wordlist)}", end='\r')

                result = future.result()
                if result:
                    self.found_paths.append(result)

        print(f"\n  ✅ Found {len(self.found_paths)} accessible paths")
        return self.found_paths

    def check_path(self, path: str) -> Optional[Dict]:
        """Check if a path exists"""
        try:
            url = urljoin(self.target_url, path)
            response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)

            if response.status_code in [200, 201, 301, 302, 401, 403]:
                return {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'path': path
                }
        except:
            pass

        return None


class BugBountyReportGenerator:
    """Generate bug bounty formatted reports"""

    @staticmethod
    def generate_submission_report(vulnerabilities: List[Dict], program: BugBountyProgram,
                                   target_url: str, recon_data: Dict) -> str:
        """Generate bug bounty submission report"""

        report = []
        report.append("=" * 80)
        report.append("BUG BOUNTY VULNERABILITY REPORT")
        report.append("=" * 80)
        report.append(f"\nProgram: {program.name}")
        report.append(f"Target: {target_url}")
        report.append(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Reporter: Security Researcher")
        report.append("\n" + "=" * 80)

        # Group vulnerabilities by severity
        vuln_by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('risk_level', 'Unknown')
            if severity not in vuln_by_severity:
                vuln_by_severity[severity] = []
            vuln_by_severity[severity].append(vuln)

        # Report each vulnerability
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in vuln_by_severity:
                report.append(f"\n{'=' * 80}")
                report.append(f"{severity.upper()} SEVERITY FINDINGS")
                report.append(f"{'=' * 80}")

                for idx, vuln in enumerate(vuln_by_severity[severity], 1):
                    report.append(f"\n[{severity.upper()} #{idx}] {vuln.get('type', 'Vulnerability')}")
                    report.append(f"\nCVSS Score: {vuln.get('cvss_score', 'N/A')}")
                    report.append(f"Bounty Tier: {program.get_bounty_range(severity)}")

                    report.append(f"\nDescription:")
                    report.append(f"  {vuln.get('description', 'No description')}")

                    report.append(f"\nLocation:")
                    report.append(f"  {vuln.get('location', target_url)}")

                    if vuln.get('evidence'):
                        report.append(f"\nEvidence:")
                        report.append(f"  {vuln['evidence']}")

                    report.append(f"\nReproduction Steps:")
                    report.append("  1. Navigate to the affected URL")
                    report.append("  2. Observe the vulnerability as described")
                    report.append("  3. Verify the security impact")

                    report.append(f"\nRecommendation:")
                    report.append(f"  {vuln.get('recommendation', 'Apply security best practices')}")

                    report.append(f"\nImpact:")
                    report.append(f"  {BugBountyReportGenerator.get_impact_description(severity)}")

                    report.append("\n" + "-" * 80)

        # Summary
        report.append(f"\n{'=' * 80}")
        report.append("SUMMARY")
        report.append("=" * 80)
        total = sum(len(vulns) for vulns in vuln_by_severity.values())
        report.append(f"\nTotal Vulnerabilities Found: {total}")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = len(vuln_by_severity.get(severity, []))
            if count > 0:
                report.append(f"  {severity}: {count}")

        # Reconnaissance findings
        if recon_data:
            report.append(f"\n{'=' * 80}")
            report.append("RECONNAISSANCE DATA")
            report.append("=" * 80)

            if recon_data.get('technologies'):
                report.append("\nTechnologies Detected:")
                for tech in recon_data['technologies'][:10]:
                    report.append(f"  • {tech}")

            if recon_data.get('api_endpoints'):
                report.append("\nAPI Endpoints Found:")
                for endpoint in recon_data['api_endpoints'][:10]:
                    if isinstance(endpoint, dict):
                        report.append(f"  • {endpoint.get('url', endpoint)}")
                    else:
                        report.append(f"  • {endpoint}")

        report.append(f"\n{'=' * 80}")
        report.append("This report was generated using automated security scanning.")
        report.append("All findings should be verified manually before submission.")
        report.append("=" * 80)

        return '\n'.join(report)

    @staticmethod
    def get_impact_description(severity: str) -> str:
        """Get impact description for severity"""
        impacts = {
            'Critical': 'Can lead to complete system compromise, data breach, or significant business impact',
            'High': 'Can lead to unauthorized access, data exposure, or significant security degradation',
            'Medium': 'Can lead to information disclosure or limited security impact',
            'Low': 'Minimal security impact, information disclosure, or configuration issues'
        }
        return impacts.get(severity, 'Security impact varies based on context')


def print_bounty_hunter_banner():
    """Display bug bounty hunter banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██████╗ ██╗   ██╗ ██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗║
║   ██╔══██╗██║   ██║██╔════╝     ██║  ██║██║   ██║████╗  ██║╚══██╔══╝║
║   ██████╔╝██║   ██║██║  ███╗    ███████║██║   ██║██╔██╗ ██║   ██║   ║
║   ██╔══██╗██║   ██║██║   ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ║
║   ██████╔╝╚██████╔╝╚██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ║
║   ╚═════╝  ╚═════╝  ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ║
║                                                                      ║
║         ⚡ AUTOMATED BUG BOUNTY PLATFORM v3.0 ⚡                     ║
║         🎯 OWASP 2025 + Recon + Enum + Validation                   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

    🔍 Reconnaissance      ✅ OWASP Top 10:2025
    📂 Dir Enumeration     🎯 Auto Validation
    📊 Bounty Reports     💰 Reward Estimation

"""
    print(banner)


def main():
    """Main bug bounty hunter function"""
    parser = argparse.ArgumentParser(
        description='Bug Bounty Hunter - Automated Security Testing Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Full bug bounty scan:
    python bounty_hunter.py https://target.com

  With program details:
    python bounty_hunter.py https://target.com --program "Ubisoft Game Security"

  Comprehensive scan with enumeration:
    python bounty_hunter.py https://target.com --full --enum

  Generate bounty report:
    python bounty_hunter.py https://target.com --bounty-report

For more information, visit: https://github.com/anubhavmohandas/owasp_scanner
        '''
    )

    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--program', help='Bug bounty program name', default='Bug Bounty Program')
    parser.add_argument('--program-file', help='File containing program details')
    parser.add_argument('--full', action='store_true', help='Run full comprehensive scan')
    parser.add_argument('--recon', action='store_true', help='Run reconnaissance phase')
    parser.add_argument('--enum', action='store_true', help='Run directory enumeration')
    parser.add_argument('--owasp', action='store_true', help='Run OWASP Top 10 scan')
    parser.add_argument('--bounty-report', action='store_true', help='Generate bug bounty formatted report')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--wordlist', help='Custom wordlist file for enumeration')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner')

    args = parser.parse_args()

    # Display banner
    if not args.no_banner:
        print_bounty_hunter_banner()

    # Parse program details
    program = BugBountyProgram(name=args.program)
    if args.program_file:
        with open(args.program_file, 'r') as f:
            program = BugBountyProgram.from_text(f.read())

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url

    print(f"\n{'='*70}")
    print(f"🎯 Target: {args.url}")
    print(f"💰 Program: {program.name}")
    print(f"{'='*70}\n")

    start_time = time.time()
    all_vulnerabilities = []
    recon_data = {}
    enum_data = []

    # Run reconnaissance if requested or full scan
    if args.recon or args.full:
        recon = ReconnaissanceEngine(args.url, verbose=args.verbose)
        recon_data = recon.run_full_recon()

        print(f"\n✅ Reconnaissance Complete:")
        print(f"  • Technologies: {len(recon_data.get('technologies', []))}")
        print(f"  • Endpoints: {len(recon_data.get('endpoints', []))}")
        print(f"  • API Endpoints: {len(recon_data.get('api_endpoints', []))}")
        print(f"  • Forms: {len(recon_data.get('forms', []))}")

    # Run directory enumeration if requested or full scan
    if args.enum or args.full:
        wordlist = None
        if args.wordlist:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]

        enumerator = DirectoryEnumerator(args.url, wordlist=wordlist, threads=args.threads)
        enum_data = enumerator.enumerate()

    # Run OWASP scan if requested or full scan
    if args.owasp or args.full:
        print("\n🛡️ Running OWASP Top 10:2025 Scan...")
        scanner = OWASP2025Scanner(args.url, output_file=None,
                                   scan_subdomains=False, threads=args.threads)

        results = scanner.scan_single_target(args.url)

        # Convert OWASP results to vulnerability list
        for category, result in results.items():
            if result.get('findings') and result.get('risk_level') in ['Critical', 'High', 'Medium']:
                for finding in result['findings']:
                    vuln = {
                        'type': category.replace('_', ' '),
                        'risk_level': result['risk_level'],
                        'description': finding,
                        'location': args.url,
                        'recommendation': f"Review and remediate {category}",
                        'cvss_score': VulnerabilityScorer.score_vulnerability(
                            result['risk_level'],
                            len(result['findings'])
                        )
                    }
                    all_vulnerabilities.append(vuln)

    scan_duration = time.time() - start_time

    # Generate report
    print("\n📝 Generating Bug Bounty Report...")

    if args.bounty_report or args.full:
        report_content = BugBountyReportGenerator.generate_submission_report(
            all_vulnerabilities, program, args.url, recon_data
        )

        output_file = args.output or f"bounty_report_{urlparse(args.url).netloc}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        with open(output_file, 'w') as f:
            f.write(report_content)

        print(f"✅ Report saved: {output_file}")

        # Print summary
        print(f"\n{'='*70}")
        print("BUG BOUNTY SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"Scan Duration: {round(scan_duration, 2)} seconds")
        print(f"Vulnerabilities Found: {len(all_vulnerabilities)}")
        print(f"Reconnaissance Data: {len(recon_data.get('technologies', []))} technologies")
        print(f"Directories Found: {len(enum_data)}")
        print(f"{'='*70}\n")

    print("✅ Bug Bounty Hunter scan complete!")
    print(f"Review {output_file if args.bounty_report or args.full else 'findings'} before submission.\n")


if __name__ == "__main__":
    main()
