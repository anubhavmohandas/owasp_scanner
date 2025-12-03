#!/usr/bin/env python3
"""
Scanner for Mishandling of Exceptional Conditions (OWASP Top 10:2025 #10)

This module scans for:
- Improper error handling
- Information disclosure in error messages
- Missing error pages
- Unhandled exceptions
- Stack trace exposure
- Verbose error messages
- Improper status code handling
"""

import requests
import re
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class ExceptionalConditionsScanner:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(target_url))
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.session.headers.update({'User-Agent': self.user_agent})

        # Error patterns that indicate verbose error messages
        self.error_patterns = {
            'stack_traces': [
                r'at\s+[\w\.$]+\([^)]+\.(?:java|py|js|rb|php):\d+\)',
                r'Traceback\s+\(most recent call last\)',
                r'Stack trace:',
                r'Call Stack:',
                r'\bat\s+.*:\d+:\d+',
                r'^\s+at\s+',
                r'File\s+"[^"]+",\s+line\s+\d+'
            ],
            'database_errors': [
                r'SQL\s+syntax.*error',
                r'mysql_fetch',
                r'PostgreSQL.*ERROR',
                r'ORA-\d{5}',
                r'SQLSTATE\[\w+\]',
                r'Microsoft\s+OLE\s+DB\s+Provider',
                r'SQLite3::SQLException',
                r'PG::Error',
                r'com\.mysql\.jdbc',
                r'org\.postgresql'
            ],
            'framework_errors': [
                r'Fatal\s+error:',
                r'Warning:.*in\s+/.*\.php',
                r'Parse\s+error:',
                r'Notice:.*in\s+/',
                r'Undefined\s+variable:',
                r'Call\s+to\s+undefined\s+function',
                r'Django\s+Debug\s+Mode',
                r'Laravel\s+Debug\s+Mode',
                r'Whoops,\s+looks\s+like\s+something\s+went\s+wrong',
                r'RuntimeException',
                r'Application\s+Error',
                r'Internal\s+Server\s+Error.*Debug\s+Mode'
            ],
            'path_disclosure': [
                r'[A-Z]:\\[\w\\]+\.(?:php|asp|aspx|jsp)',
                r'/(?:var/www|home|usr/local)/[\w/]+\.(?:php|py|rb|js)',
                r'C:\\inetpub\\wwwroot',
                r'/opt/[\w/]+',
                r'D:\\[\w\\]+'
            ],
            'version_disclosure': [
                r'PHP/\d+\.\d+\.\d+',
                r'Apache/\d+\.\d+\.\d+',
                r'nginx/\d+\.\d+\.\d+',
                r'ASP\.NET\s+Version:\d+\.\d+',
                r'Powered\s+by.*\d+\.\d+',
                r'IIS/\d+\.\d+'
            ]
        }

        # Payloads to trigger errors
        self.error_triggers = [
            '../../etc/passwd',
            "' OR '1'='1",
            '<script>alert(1)</script>',
            '${7*7}',
            '../../../',
            '%00',
            '/..',
            '999999999999999999999',
            '-1',
            'null',
            'undefined',
            '%0d%0a',
            chr(0),
            '[]',
            '{}',
            '()',
            '!@#$%^&*()'
        ]

    def log(self, message):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"  [DEBUG] {message}")

    def scan(self):
        """Main scan function for exceptional condition handling."""
        vulnerabilities = []

        try:
            # Check for verbose error messages on normal pages
            vuln = self.check_error_pages()
            if vuln:
                vulnerabilities.extend(vuln)

            # Test error triggering
            vuln = self.trigger_errors()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for missing custom error pages
            vuln = self.check_missing_error_pages()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check status code handling
            vuln = self.check_status_codes()
            if vuln:
                vulnerabilities.extend(vuln)

        except Exception as e:
            self.log(f"Error during exceptional conditions scan: {e}")

        return vulnerabilities

    def check_error_pages(self):
        """Check for verbose error messages on existing pages."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check for various error patterns
            for error_type, patterns in self.error_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, response.text, re.MULTILINE | re.IGNORECASE)
                    if matches:
                        risk_level = 'High' if error_type in ['stack_traces', 'database_errors'] else 'Medium'

                        vulnerabilities.append({
                            'type': 'Verbose Error Messages',
                            'risk_level': risk_level,
                            'description': f'{error_type.replace("_", " ").title()} exposed in response',
                            'location': self.target_url,
                            'evidence': matches[0][:100] if matches else '',
                            'recommendation': 'Implement custom error pages and disable debug mode in production. Never expose stack traces, file paths, or database errors to users.'
                        })
                        break

        except Exception as e:
            self.log(f"Error checking error pages: {e}")

        return vulnerabilities

    def trigger_errors(self):
        """Attempt to trigger error conditions."""
        vulnerabilities = []

        # Test various error triggers
        for trigger in self.error_triggers[:5]:  # Limit to avoid excessive requests
            try:
                # Test in URL parameter
                test_url = f"{self.target_url}?test={trigger}"
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)

                # Check if error response contains sensitive information
                if response.status_code >= 500:
                    for error_type, patterns in self.error_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vulnerabilities.append({
                                    'type': 'Improper Exception Handling',
                                    'risk_level': 'High',
                                    'description': f'Server returns verbose {error_type.replace("_", " ")} when processing malformed input',
                                    'location': test_url,
                                    'recommendation': 'Implement proper exception handling and return generic error messages. Log detailed errors server-side only.'
                                })
                                return vulnerabilities  # Found one, no need to continue

                time.sleep(0.2)  # Rate limiting

            except Exception as e:
                self.log(f"Error testing trigger '{trigger}': {e}")
                continue

        return vulnerabilities

    def check_missing_error_pages(self):
        """Check for missing custom error pages."""
        vulnerabilities = []
        missing_pages = []

        error_codes = [400, 401, 403, 404, 500, 502, 503]

        for code in error_codes:
            try:
                # Try to access a non-existent page to trigger specific error
                test_url = urljoin(self.base_url, f'/nonexistent_{code}_test')
                response = self.session.get(test_url, timeout=3, verify=False, allow_redirects=False)

                # Check if default server error page is shown
                default_indicators = [
                    'Apache', 'nginx', 'IIS', 'lighttpd',
                    'Tomcat', 'Jetty', 'WebLogic',
                    'Server at', 'Error report',
                    '<h1>404 Not Found</h1>',
                    'The requested URL was not found'
                ]

                is_default = any(indicator in response.text for indicator in default_indicators)

                if is_default:
                    missing_pages.append(f"HTTP {code}")

                time.sleep(0.2)

            except Exception as e:
                self.log(f"Error checking {code} page: {e}")
                continue

        if missing_pages:
            vulnerabilities.append({
                'type': 'Missing Custom Error Pages',
                'risk_level': 'Low',
                'description': f'Default server error pages detected for: {", ".join(missing_pages)}',
                'location': self.base_url,
                'recommendation': 'Configure custom error pages for all HTTP error codes to prevent information disclosure about server configuration.'
            })

        return vulnerabilities

    def check_status_codes(self):
        """Check for improper status code handling."""
        vulnerabilities = []

        try:
            # Test for common misconfigurations
            test_cases = [
                ('/admin/', 'Administrative area'),
                ('/api/', 'API endpoint'),
                ('/.git/', 'Version control'),
                ('/config/', 'Configuration path')
            ]

            improper_codes = []

            for path, description in test_cases:
                test_url = urljoin(self.base_url, path)
                response = self.session.get(test_url, timeout=3, verify=False, allow_redirects=False)

                # Should return 401/403 for protected resources, not 500
                if response.status_code == 500:
                    improper_codes.append(f"{description} returns 500 instead of proper auth error")
                # Should return 404 for non-existent, not 200
                elif response.status_code == 200 and 'not found' in response.text.lower():
                    improper_codes.append(f"{description} returns 200 with 'not found' message")

                time.sleep(0.2)

            if improper_codes:
                vulnerabilities.append({
                    'type': 'Improper Status Code Handling',
                    'risk_level': 'Low',
                    'description': 'Server returns incorrect HTTP status codes for error conditions',
                    'location': self.base_url,
                    'details': improper_codes,
                    'recommendation': 'Return appropriate HTTP status codes: 401 for authentication required, 403 for forbidden, 404 for not found, etc.'
                })

        except Exception as e:
            self.log(f"Error checking status codes: {e}")

        return vulnerabilities
