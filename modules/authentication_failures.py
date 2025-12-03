#!/usr/bin/env python3
"""
Scanner for Authentication Failures (OWASP Top 10:2025 #7)

This module scans for:
- Weak password policies
- Missing MFA/2FA
- Session fixation
- Insecure session management
- Credential stuffing vulnerabilities
- Missing account lockout
"""

import requests
import re
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class AuthenticationFailuresScanner:
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
        """Main scan function for authentication failures."""
        vulnerabilities = []

        try:
            # Check for weak session management
            vuln = self.check_session_management()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for account lockout
            vuln = self.check_account_lockout()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for MFA indicators
            vuln = self.check_mfa()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for password policy indicators
            vuln = self.check_password_policy()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check session cookies
            vuln = self.check_session_cookies()
            if vuln:
                vulnerabilities.extend(vuln)

        except Exception as e:
            self.log(f"Error during authentication failures scan: {e}")

        return vulnerabilities

    def check_session_management(self):
        """Check for session management issues."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check for session tokens in URL
            if 'sessionid' in self.target_url.lower() or 'session' in self.target_url.lower():
                vulnerabilities.append({
                    'type': 'Session Token in URL',
                    'risk_level': 'High',
                    'description': 'Session identifier exposed in URL',
                    'location': self.target_url,
                    'recommendation': 'Use cookies for session management, never URL parameters'
                })

            # Check Set-Cookie headers
            set_cookie = response.headers.get('Set-Cookie', '')

            if set_cookie:
                # Check for session cookie without HttpOnly
                if 'session' in set_cookie.lower() and 'httponly' not in set_cookie.lower():
                    vulnerabilities.append({
                        'type': 'Insecure Session Cookie',
                        'risk_level': 'Medium',
                        'description': 'Session cookie missing HttpOnly flag',
                        'location': self.target_url,
                        'recommendation': 'Set HttpOnly flag on all session cookies'
                    })

        except Exception as e:
            self.log(f"Error checking session management: {e}")

        return vulnerabilities

    def check_account_lockout(self):
        """Check for missing account lockout mechanism."""
        vulnerabilities = []

        # Look for login endpoints
        login_endpoints = ['/login', '/signin', '/auth', '/api/login', '/api/auth']

        for endpoint in login_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.get(url, timeout=3, verify=False, allow_redirects=False)

                if response.status_code == 200:
                    # Try multiple failed login attempts
                    failed_attempts = 0

                    for i in range(5):
                        try:
                            post_response = self.session.post(
                                url,
                                data={'username': 'testuser', 'password': 'wrongpass'},
                                timeout=3,
                                verify=False,
                                allow_redirects=False
                            )

                            if post_response.status_code in [200, 401, 403]:
                                failed_attempts += 1

                            time.sleep(0.5)

                        except:
                            break

                    # If 5 attempts succeeded without lockout
                    if failed_attempts >= 5:
                        vulnerabilities.append({
                            'type': 'Missing Account Lockout',
                            'risk_level': 'Medium',
                            'description': '5+ failed login attempts without account lockout',
                            'location': url,
                            'recommendation': 'Implement account lockout after N failed attempts (e.g., 5 attempts)'
                        })

                    break

            except:
                continue

        return vulnerabilities

    def check_mfa(self):
        """Check for MFA/2FA indicators."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            # Check if site has MFA indicators
            has_mfa = any(keyword in response.text.lower() for keyword in
                ['two-factor', '2fa', 'mfa', 'authenticator', 'verification code'])

            if not has_mfa:
                # Check login page specifically
                login_urls = ['/login', '/signin', '/auth']

                for login_url in login_urls:
                    try:
                        url = urljoin(self.base_url, login_url)
                        login_response = self.session.get(url, timeout=5, verify=False)

                        has_mfa = any(keyword in login_response.text.lower() for keyword in
                            ['two-factor', '2fa', 'mfa', 'authenticator'])

                        if has_mfa:
                            break

                    except:
                        continue

                if not has_mfa:
                    vulnerabilities.append({
                        'type': 'Missing Multi-Factor Authentication',
                        'risk_level': 'Medium',
                        'description': 'No evidence of MFA/2FA implementation',
                        'location': self.target_url,
                        'recommendation': 'Implement multi-factor authentication for enhanced security'
                    })

        except Exception as e:
            self.log(f"Error checking MFA: {e}")

        return vulnerabilities

    def check_password_policy(self):
        """Check for password policy indicators."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Look for password fields
            password_fields = soup.find_all('input', {'type': 'password'})

            if password_fields:
                # Check if there's any password policy text
                has_policy = any(keyword in response.text.lower() for keyword in
                    ['password must', 'at least 8 characters', 'uppercase', 'lowercase',
                     'special character', 'password requirements'])

                if not has_policy:
                    vulnerabilities.append({
                        'type': 'Weak Password Policy',
                        'risk_level': 'Low',
                        'description': 'No visible password complexity requirements',
                        'location': self.target_url,
                        'recommendation': 'Enforce strong password policy (min 8 chars, complexity requirements)'
                    })

        except Exception as e:
            self.log(f"Error checking password policy: {e}")

        return vulnerabilities

    def check_session_cookies(self):
        """Check session cookie security."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)

            cookies = response.cookies

            for cookie in cookies:
                # Check if it's a session cookie
                if any(keyword in cookie.name.lower() for keyword in
                    ['session', 'sess', 'auth', 'token']):

                    issues = []

                    if not cookie.secure and self.target_url.startswith('https://'):
                        issues.append('missing Secure flag')

                    if not cookie.has_nonstandard_attr('httponly') and \
                       not cookie.has_nonstandard_attr('HttpOnly'):
                        issues.append('missing HttpOnly flag')

                    if not cookie.has_nonstandard_attr('samesite') and \
                       not cookie.has_nonstandard_attr('SameSite'):
                        issues.append('missing SameSite attribute')

                    if issues:
                        vulnerabilities.append({
                            'type': 'Insecure Session Cookie Configuration',
                            'risk_level': 'Medium',
                            'description': f'Cookie "{cookie.name}" has issues: {", ".join(issues)}',
                            'location': self.target_url,
                            'recommendation': 'Set Secure, HttpOnly, and SameSite=Strict on session cookies'
                        })

        except Exception as e:
            self.log(f"Error checking session cookies: {e}")

        return vulnerabilities
