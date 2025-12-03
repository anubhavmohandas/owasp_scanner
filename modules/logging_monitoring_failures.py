#!/usr/bin/env python3
"""
Scanner for Logging and Alerting Failures (OWASP Top 10:2025 #9)

This module scans for:
- Missing security event logging
- Verbose error messages
- Missing audit trails
- No log monitoring/alerting
- Log injection vulnerabilities
"""

import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class LoggingMonitoringFailuresScanner:
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
        """Main scan function for logging and monitoring failures."""
        vulnerabilities = []

        try:
            # Check for verbose error messages
            vuln = self.check_error_verbosity()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for missing security headers that indicate monitoring
            vuln = self.check_security_monitoring()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for log injection opportunities
            vuln = self.check_log_injection()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for information disclosure in responses
            vuln = self.check_info_disclosure()
            if vuln:
                vulnerabilities.extend(vuln)

        except Exception as e:
            self.log(f"Error during logging/monitoring failures scan: {e}")

        return vulnerabilities

    def check_error_verbosity(self):
        """Check for overly verbose error messages."""
        vulnerabilities = []

        # Trigger potential errors
        error_triggers = [
            ('?id=', 'SQL error'),
            ('?page=', 'Path error'),
            ('/../', 'Traversal error'),
        ]

        for trigger, error_type in error_triggers:
            try:
                test_url = self.target_url + trigger + 'test'
                response = self.session.get(test_url, timeout=5, verify=False)

                # Check for verbose error patterns
                error_patterns = [
                    r'Fatal\s+error',
                    r'Warning:',
                    r'Notice:',
                    r'Parse\s+error',
                    r'SQL.*error',
                    r'Exception\s+in',
                    r'Traceback',
                    r'Stack\s+trace',
                ]

                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Verbose Error Messages',
                            'risk_level': 'Low',
                            'description': f'Application exposes {error_type} details in error messages',
                            'location': test_url,
                            'recommendation': 'Use generic error messages for users, log details server-side only'
                        })
                        return vulnerabilities  # Found one, that's enough

            except:
                continue

        return vulnerabilities

    def check_security_monitoring(self):
        """Check for indicators of security monitoring."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check for security monitoring headers
            monitoring_headers = [
                'X-Request-ID',
                'X-Correlation-ID',
                'X-Trace-ID',
            ]

            has_monitoring = any(header in response.headers for header in monitoring_headers)

            # Check for CSP reporting
            csp = response.headers.get('Content-Security-Policy', '')
            has_csp_reporting = 'report-uri' in csp or 'report-to' in csp

            if not has_monitoring and not has_csp_reporting:
                vulnerabilities.append({
                    'type': 'Missing Security Monitoring Indicators',
                    'risk_level': 'Low',
                    'description': 'No evidence of request tracking or CSP violation reporting',
                    'location': self.target_url,
                    'recommendation': 'Implement request tracking and security event monitoring/alerting'
                })

        except Exception as e:
            self.log(f"Error checking security monitoring: {e}")

        return vulnerabilities

    def check_log_injection(self):
        """Check for potential log injection vulnerabilities."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for user input fields that might be logged
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all('input')

                # Look for username, email, or search fields
                for input_field in inputs:
                    name = input_field.get('name', '').lower()

                    if any(keyword in name for keyword in
                        ['user', 'name', 'email', 'search', 'query']):

                        # These fields are often logged and could be vulnerable
                        vulnerabilities.append({
                            'type': 'Potential Log Injection',
                            'risk_level': 'Low',
                            'description': f'User input field "{name}" may be logged without sanitization',
                            'location': self.target_url,
                            'recommendation': 'Sanitize all user input before logging, especially newlines and special characters'
                        })
                        return vulnerabilities  # One example is enough

        except Exception as e:
            self.log(f"Error checking log injection: {e}")

        return vulnerabilities

    def check_info_disclosure(self):
        """Check for information disclosure that indicates poor logging practices."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check for debug information
            debug_patterns = [
                r'DEBUG\s*=\s*True',
                r'debug\s*:\s*true',
                r'development\s+mode',
                r'DEV\s+MODE',
            ]

            for pattern in debug_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'Debug Mode Enabled',
                        'risk_level': 'Medium',
                        'description': 'Application appears to be in debug/development mode',
                        'location': self.target_url,
                        'recommendation': 'Disable debug mode in production and ensure proper logging is configured'
                    })
                    break

            # Check for exposed log files
            log_paths = [
                '/logs', '/log', '/error.log', '/access.log',
                '/debug.log', '/application.log'
            ]

            for log_path in log_paths:
                try:
                    url = urljoin(self.base_url, log_path)
                    log_response = self.session.get(url, timeout=3, verify=False)

                    if log_response.status_code == 200 and len(log_response.text) > 100:
                        vulnerabilities.append({
                            'type': 'Exposed Log Files',
                            'risk_level': 'High',
                            'description': f'Log file accessible: {log_path}',
                            'location': url,
                            'recommendation': 'Restrict access to log files and store them outside web root'
                        })
                        break

                except:
                    continue

        except Exception as e:
            self.log(f"Error checking info disclosure: {e}")

        return vulnerabilities
