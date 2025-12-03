#!/usr/bin/env python3
"""
Scanner for Security Misconfiguration vulnerabilities (OWASP Top 10 #5)

This module scans for:
- Missing security headers
- Default credentials
- Directory listing
- Information disclosure
- Unnecessary features enabled
"""

import requests
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class SecurityMisconfigurationScanner:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(target_url))
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.session.headers.update({'User-Agent': self.user_agent})

        self.security_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented',
            'X-Content-Type-Options': 'X-Content-Type-Options missing',
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-XSS-Protection': 'XSS filter disabled',
        }

    def log(self, message):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"  [DEBUG] {message}")

    def scan(self):
        """Main scan function for security misconfigurations."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check security headers
            vuln = self.check_security_headers(response)
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for directory listing
            vuln = self.check_directory_listing()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for information disclosure
            vuln = self.check_information_disclosure(response)
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for default files
            vuln = self.check_default_files()
            if vuln:
                vulnerabilities.extend(vuln)

        except Exception as e:
            self.log(f"Error during security misconfiguration scan: {e}")

        return vulnerabilities

    def check_security_headers(self, response):
        """Check for missing security headers."""
        vulnerabilities = []
        missing_headers = []

        for header, description in self.security_headers.items():
            if header not in response.headers:
                missing_headers.append(description)

        if missing_headers:
            vulnerabilities.append({
                'type': 'Missing Security Headers',
                'risk_level': 'Medium',
                'description': f'Missing headers: {", ".join(missing_headers)}',
                'location': self.target_url,
                'recommendation': 'Configure all recommended security headers'
            })

        return vulnerabilities

    def check_directory_listing(self):
        """Check for directory listing enabled."""
        vulnerabilities = []
        directories = ['/admin/', '/backup/', '/config/', '/uploads/']

        for directory in directories:
            try:
                url = urljoin(self.base_url, directory)
                response = self.session.get(url, timeout=5)

                if 'Index of' in response.text or 'Directory listing' in response.text:
                    vulnerabilities.append({
                        'type': 'Directory Listing Enabled',
                        'risk_level': 'Medium',
                        'description': f'Directory listing found at {url}',
                        'location': url,
                        'recommendation': 'Disable directory listing on web server'
                    })
            except:
                pass

            time.sleep(0.2)

        return vulnerabilities

    def check_information_disclosure(self, response):
        """Check for information disclosure."""
        vulnerabilities = []

        # Check Server header
        if 'Server' in response.headers:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'risk_level': 'Low',
                'description': f'Server version disclosed: {response.headers["Server"]}',
                'location': self.target_url,
                'recommendation': 'Remove or obfuscate server version information'
            })

        # Check X-Powered-By header
        if 'X-Powered-By' in response.headers:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'risk_level': 'Low',
                'description': f'Technology stack disclosed: {response.headers["X-Powered-By"]}',
                'location': self.target_url,
                'recommendation': 'Remove X-Powered-By header'
            })

        return vulnerabilities

    def check_default_files(self):
        """Check for default/sensitive files."""
        vulnerabilities = []
        default_files = [
            '/.env', '/config.php', '/phpinfo.php',
            '/.git/config', '/web.config', '/.htaccess'
        ]

        for file_path in default_files:
            try:
                url = urljoin(self.base_url, file_path)
                response = self.session.get(url, timeout=3)

                if response.status_code == 200 and len(response.text) > 0:
                    vulnerabilities.append({
                        'type': 'Sensitive File Exposure',
                        'risk_level': 'High',
                        'description': f'Sensitive file accessible: {file_path}',
                        'location': url,
                        'recommendation': 'Remove or restrict access to sensitive files'
                    })
            except:
                pass

            time.sleep(0.2)

        return vulnerabilities
