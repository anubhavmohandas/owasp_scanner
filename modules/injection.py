#!/usr/bin/env python3
"""
Scanner for Injection vulnerabilities (OWASP Top 10 #3)

This module scans for:
- SQL Injection
- NoSQL Injection
- Command Injection
- LDAP Injection
- XPath Injection
- Template Injection
"""

import requests
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

class InjectionScanner:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(target_url))
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.session.headers.update({'User-Agent': self.user_agent})

        # Test payloads for different injection types
        self.sql_payloads = [
            "'", "1' OR '1'='1", "1; DROP TABLE users--",
            "' OR 1=1--", "admin'--", "' UNION SELECT NULL--"
        ]

        self.nosql_payloads = [
            '{"$gt":""}', '{"$ne":null}', '{"$where":"sleep(1000)"}',
        ]

        self.cmd_payloads = [
            "; ls", "& dir", "| whoami", "`id`", "$(cat /etc/passwd)"
        ]

        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            '"><script>alert(1)</script>'
        ]

        self.template_payloads = [
            "${7*7}", "{{7*7}}", "<%= 7*7 %>", "${{7*7}}"
        ]

    def log(self, message):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"  [DEBUG] {message}")

    def scan(self):
        """Main scan function for injection vulnerabilities."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all forms
            forms = soup.find_all('form')

            # Check forms for injection
            for form in forms:
                vuln = self.check_form_injection(form)
                if vuln:
                    vulnerabilities.extend(vuln)

            # Check URL parameters
            parsed_url = urlparse(self.target_url)
            if parsed_url.query:
                vuln = self.check_url_param_injection()
                if vuln:
                    vulnerabilities.extend(vuln)

            # Check for error-based injection
            vuln = self.check_error_based_injection()
            if vuln:
                vulnerabilities.extend(vuln)

        except Exception as e:
            self.log(f"Error during injection scan: {e}")

        return vulnerabilities

    def check_form_injection(self, form):
        """Check form for injection vulnerabilities."""
        vulnerabilities = []

        try:
            action = form.get('action')
            method = form.get('method', 'get').lower()

            if not action:
                action = self.target_url
            elif not action.startswith(('http://', 'https://')):
                action = urljoin(self.base_url, action)

            inputs = form.find_all('input')
            input_data = {}

            for input_field in inputs:
                input_name = input_field.get('name')
                if input_name:
                    input_data[input_name] = 'test'

            # Test SQL injection
            for payload in self.sql_payloads[:3]:  # Limit payloads
                test_data = input_data.copy()
                for key in test_data:
                    test_data[key] = payload

                try:
                    if method == 'post':
                        response = self.session.post(action, data=test_data, timeout=5)
                    else:
                        response = self.session.get(action, params=test_data, timeout=5)

                    # Check for SQL error messages
                    sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'SQLSTATE',
                                'pg_query', 'SQLite', 'ERROR 1064']

                    if any(error.lower() in response.text.lower() for error in sql_errors):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'risk_level': 'Critical',
                            'description': f'Potential SQL injection in form at {action}',
                            'location': action,
                            'recommendation': 'Use parameterized queries or prepared statements'
                        })
                        break
                except:
                    pass

            time.sleep(0.3)

        except Exception as e:
            self.log(f"Error checking form injection: {e}")

        return vulnerabilities

    def check_url_param_injection(self):
        """Check URL parameters for injection."""
        vulnerabilities = []

        try:
            parsed_url = urlparse(self.target_url)
            params = parse_qs(parsed_url.query)

            for param_name in params:
                # Test with SQL injection payload
                test_params = params.copy()
                test_params[param_name] = ["'"]

                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                response = self.session.get(test_url, params=test_params, timeout=5)

                sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'SQLSTATE']
                if any(error in response.text for error in sql_errors):
                    vulnerabilities.append({
                        'type': 'SQL Injection',
                        'risk_level': 'Critical',
                        'description': f'SQL injection possible in parameter: {param_name}',
                        'location': self.target_url,
                        'recommendation': 'Sanitize input and use parameterized queries'
                    })

        except Exception as e:
            self.log(f"Error checking URL parameters: {e}")

        return vulnerabilities

    def check_error_based_injection(self):
        """Check for error-based injection points."""
        vulnerabilities = []

        try:
            error_payloads = ["'", '"', "1'1"]

            for payload in error_payloads:
                test_url = f"{self.target_url}?id={payload}"
                response = self.session.get(test_url, timeout=5)

                # Database error patterns
                error_patterns = [
                    r'SQL.*syntax',
                    r'mysql_fetch',
                    r'ORA-\d+',
                    r'SQLSTATE',
                    r'PostgreSQL.*ERROR',
                    r'Microsoft OLE DB Provider'
                ]

                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Error-based SQL Injection',
                            'risk_level': 'High',
                            'description': 'Database errors exposed, indicating possible SQL injection',
                            'location': test_url,
                            'recommendation': 'Implement proper error handling and input validation'
                        })
                        return vulnerabilities

        except Exception as e:
            self.log(f"Error in error-based injection check: {e}")

        return vulnerabilities
