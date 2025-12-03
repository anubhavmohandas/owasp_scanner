#!/usr/bin/env python3
"""
Scanner for Software and Data Integrity Failures (OWASP Top 10:2025 #8)

This module scans for:
- Insecure deserialization
- Missing integrity verification
- Unsigned/unverified updates
- CI/CD pipeline vulnerabilities
- Insecure plugins/libraries
"""

import requests
import re
import base64
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class DataIntegrityFailuresScanner:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(target_url))
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.session.headers.update({'User-Agent': self.user_agent})

    def log(self, message):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"  [DEBUG] {message}")

    def scan(self):
        """Main scan function for data integrity failures."""
        vulnerabilities = []

        try:
            # Check for insecure deserialization
            vuln = self.check_deserialization()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for missing integrity checks on resources
            vuln = self.check_resource_integrity()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for plugin/update mechanisms
            vuln = self.check_update_mechanisms()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for serialized data in cookies/headers
            vuln = self.check_serialized_data()
            if vuln:
                vulnerabilities.extend(vuln)

        except Exception as e:
            self.log(f"Error during data integrity failures scan: {e}")

        return vulnerabilities

    def check_deserialization(self):
        """Check for potential insecure deserialization."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check cookies for serialized data
            for cookie in response.cookies:
                value = cookie.value

                # Check for common serialization formats
                if self.is_serialized(value):
                    vulnerabilities.append({
                        'type': 'Potential Insecure Deserialization',
                        'risk_level': 'High',
                        'description': f'Cookie "{cookie.name}" contains serialized data',
                        'location': self.target_url,
                        'recommendation': 'Avoid deserializing untrusted data. Use JSON with schema validation instead'
                    })
                    break

        except Exception as e:
            self.log(f"Error checking deserialization: {e}")

        return vulnerabilities

    def is_serialized(self, data):
        """Check if data appears to be serialized."""
        # Check for common serialization markers
        serialization_markers = [
            b'__class__',  # Python pickle
            b'java.lang',  # Java serialization
            b'phpserialize',  # PHP serialize
            b'O:',  # PHP object notation
            b'a:',  # PHP array notation
        ]

        try:
            # Try base64 decode
            try:
                decoded = base64.b64decode(data)
                return any(marker in decoded for marker in serialization_markers)
            except:
                pass

            # Check raw data
            data_bytes = data.encode() if isinstance(data, str) else data
            return any(marker in data_bytes for marker in serialization_markers)

        except:
            return False

    def check_resource_integrity(self):
        """Check for missing integrity verification on external resources."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            missing_integrity = []

            # Check scripts from external sources
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src', '')

                # External script
                if src.startswith(('http://', 'https://')) and \
                   not src.startswith(self.base_url):

                    if not script.has_attr('integrity'):
                        missing_integrity.append(f"Script: {src[:60]}")

            # Check stylesheets
            links = soup.find_all('link', {'rel': 'stylesheet', 'href': True})
            for link in links:
                href = link.get('href', '')

                if href.startswith(('http://', 'https://')) and \
                   not href.startswith(self.base_url):

                    if not link.has_attr('integrity'):
                        missing_integrity.append(f"Stylesheet: {href[:60]}")

            if missing_integrity:
                vulnerabilities.append({
                    'type': 'Missing Subresource Integrity',
                    'risk_level': 'Medium',
                    'description': f'{len(missing_integrity)} external resources without integrity verification',
                    'location': self.target_url,
                    'details': missing_integrity[:5],
                    'recommendation': 'Add integrity attributes to all external scripts and stylesheets'
                })

        except Exception as e:
            self.log(f"Error checking resource integrity: {e}")

        return vulnerabilities

    def check_update_mechanisms(self):
        """Check for insecure update mechanisms."""
        vulnerabilities = []

        update_endpoints = [
            '/update', '/api/update', '/upgrade',
            '/install', '/plugin/install', '/api/plugin'
        ]

        for endpoint in update_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)

                if response.status_code in [200, 201]:
                    # Check if it requires authentication
                    if 'login' not in response.text.lower() and \
                       'unauthorized' not in response.text.lower():

                        vulnerabilities.append({
                            'type': 'Insecure Update Mechanism',
                            'risk_level': 'Critical',
                            'description': f'Update endpoint accessible: {endpoint}',
                            'location': url,
                            'recommendation': 'Secure update mechanisms with authentication and integrity verification'
                        })
                        break

            except:
                continue

        return vulnerabilities

    def check_serialized_data(self):
        """Check for serialized data in various locations."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check ViewState (ASP.NET)
            if '__VIEWSTATE' in response.text:
                vulnerabilities.append({
                    'type': 'ViewState Detected',
                    'risk_level': 'Low',
                    'description': 'ASP.NET ViewState found - ensure it\'s encrypted and integrity-protected',
                    'location': self.target_url,
                    'recommendation': 'Enable ViewState encryption and MAC validation'
                })

            # Check for JWT tokens without signature
            auth_header = response.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

                # JWT has 3 parts separated by dots
                if token.count('.') == 2:
                    parts = token.split('.')

                    # Check if signature part is empty or very short
                    if len(parts[2]) < 10:
                        vulnerabilities.append({
                            'type': 'Weak JWT Signature',
                            'risk_level': 'High',
                            'description': 'JWT token has weak or missing signature',
                            'location': self.target_url,
                            'recommendation': 'Use strong signing algorithms (RS256, ES256) for JWT tokens'
                        })

        except Exception as e:
            self.log(f"Error checking serialized data: {e}")

        return vulnerabilities
