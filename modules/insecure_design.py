#!/usr/bin/env python3
"""
Scanner for Insecure Design (OWASP Top 10:2025 #6)

This module scans for:
- Missing rate limiting
- Insufficient anti-automation
- Business logic flaws
- Missing CAPTCHA on sensitive operations
- Insecure workflow design
- Missing step-up authentication
"""

import requests
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class InsecureDesignScanner:
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
        """Main scan function for insecure design issues."""
        vulnerabilities = []

        try:
            # Check for rate limiting
            vuln = self.check_rate_limiting()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for CAPTCHA on forms
            vuln = self.check_captcha()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for business logic issues
            vuln = self.check_business_logic()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for sensitive operations protection
            vuln = self.check_sensitive_operations()
            if vuln:
                vulnerabilities.extend(vuln)

        except Exception as e:
            self.log(f"Error during insecure design scan: {e}")

        return vulnerabilities

    def check_rate_limiting(self):
        """Check for missing rate limiting."""
        vulnerabilities = []

        try:
            # Test with multiple rapid requests
            responses = []
            start_time = time.time()

            for i in range(10):
                response = self.session.get(self.target_url, timeout=3, verify=False)
                responses.append(response.status_code)

            elapsed = time.time() - start_time

            # If all requests succeed quickly, likely no rate limiting
            if all(r == 200 for r in responses) and elapsed < 5:
                vulnerabilities.append({
                    'type': 'Missing Rate Limiting',
                    'risk_level': 'Medium',
                    'description': '10 rapid requests succeeded without rate limiting',
                    'location': self.target_url,
                    'recommendation': 'Implement rate limiting to prevent abuse and automated attacks'
                })

        except Exception as e:
            self.log(f"Error checking rate limiting: {e}")

        return vulnerabilities

    def check_captcha(self):
        """Check for missing CAPTCHA on forms."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            forms = soup.find_all('form')
            forms_without_captcha = []

            for form in forms:
                action = form.get('action', '')

                # Check if form has CAPTCHA
                has_captcha = (
                    soup.find('div', class_=lambda x: x and 'captcha' in x.lower()) or
                    soup.find('div', id=lambda x: x and 'captcha' in x.lower()) or
                    soup.find('input', {'name': lambda x: x and 'captcha' in x.lower()}) or
                    'recaptcha' in response.text.lower() or
                    'hcaptcha' in response.text.lower()
                )

                # Check if it's a sensitive form
                is_sensitive = any(keyword in action.lower() for keyword in
                    ['login', 'register', 'signup', 'password', 'contact', 'submit'])

                if is_sensitive and not has_captcha:
                    forms_without_captcha.append(action or 'form')

            if forms_without_captcha:
                vulnerabilities.append({
                    'type': 'Missing CAPTCHA',
                    'risk_level': 'Medium',
                    'description': f'Sensitive forms without CAPTCHA protection: {", ".join(forms_without_captcha[:3])}',
                    'location': self.target_url,
                    'recommendation': 'Add CAPTCHA (reCAPTCHA, hCaptcha) to prevent automated abuse'
                })

        except Exception as e:
            self.log(f"Error checking CAPTCHA: {e}")

        return vulnerabilities

    def check_business_logic(self):
        """Check for potential business logic flaws."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for price/quantity manipulation possibilities
            forms = soup.find_all('form')

            for form in forms:
                # Look for hidden price fields
                price_fields = form.find_all('input', {'name': lambda x: x and 'price' in x.lower(), 'type': 'hidden'})
                quantity_fields = form.find_all('input', {'name': lambda x: x and 'quantity' in x.lower()})

                if price_fields:
                    vulnerabilities.append({
                        'type': 'Business Logic Flaw',
                        'risk_level': 'High',
                        'description': 'Price values in hidden fields can be manipulated',
                        'location': self.target_url,
                        'recommendation': 'Never trust client-side price values. Validate all prices server-side'
                    })
                    break

                # Check for unrestricted quantity
                if quantity_fields:
                    qty_field = quantity_fields[0]
                    max_qty = qty_field.get('max')

                    if not max_qty:
                        vulnerabilities.append({
                            'type': 'Business Logic Flaw',
                            'risk_level': 'Medium',
                            'description': 'No maximum quantity limit enforced',
                            'location': self.target_url,
                            'recommendation': 'Implement server-side quantity validation and limits'
                        })
                        break

        except Exception as e:
            self.log(f"Error checking business logic: {e}")

        return vulnerabilities

    def check_sensitive_operations(self):
        """Check for missing protections on sensitive operations."""
        vulnerabilities = []

        sensitive_endpoints = [
            '/api/delete', '/api/remove', '/delete', '/remove',
            '/api/update', '/api/change', '/update', '/change',
            '/api/transfer', '/transfer', '/payment', '/checkout'
        ]

        for endpoint in sensitive_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)

                # Try GET request (should not work for sensitive operations)
                response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)

                if response.status_code in [200, 201]:
                    vulnerabilities.append({
                        'type': 'Insecure Design - Sensitive Operation',
                        'risk_level': 'High',
                        'description': f'Sensitive endpoint accepts GET requests: {endpoint}',
                        'location': url,
                        'recommendation': 'Use POST for state-changing operations and require CSRF tokens'
                    })
                    break

            except:
                continue

        return vulnerabilities
