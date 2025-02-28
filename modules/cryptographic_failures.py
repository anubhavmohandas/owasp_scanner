#!/usr/bin/env python3
"""
Scanner for Cryptographic Failures vulnerabilities (OWASP Top 10 #2)

This module scans a website for potential cryptographic failures, including:
- Insecure SSL/TLS configurations
- Mixed content (HTTP in HTTPS site)
- Insecure cookie attributes
- Sensitive data transmitted in URLs
- Missing security headers
"""

import requests
import re
import socket
import ssl
import time
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

class CryptographicFailuresScanner:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(target_url))
        self.hostname = urlparse(target_url).netloc
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36'
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # Sensitive data patterns
        self.sensitive_patterns = {
            'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'),
            'ssn': re.compile(r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'api_key': re.compile(r'\b(?:api[-_]?key|access[-_]?token|secret[-_]?key)["\']?\s*(?::|=)\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']'),
            'password': re.compile(r'\b(?:password|passwd|pwd)["\']?\s*(?::|=)\s*["\']([^"\']{3,})["\']')
        }
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented',
            'X-Content-Type-Options': 'X-Content-Type-Options header missing',
            'X-Frame-Options': 'X-Frame-Options header missing',
            'X-XSS-Protection': 'X-XSS-Protection header missing',
            'Referrer-Policy': 'Referrer-Policy header missing',
            'Permissions-Policy': 'Permissions-Policy missing'
        }
    
    def log(self, message):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"  [DEBUG] {message}")
    
    def scan(self):
        """Main scan function to check for cryptographic failures."""
        vulnerabilities = []
        self.log(f"Starting cryptographic failures scan on {self.target_url}")
        
        try:
            # Get the main page
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for SSL/TLS issues
            ssl_issues = self.check_ssl_tls()
            if ssl_issues:
                vulnerabilities.extend(ssl_issues)
            
            # Check for mixed content
            mixed_content = self.check_mixed_content(soup)
            if mixed_content:
                vulnerabilities.extend(mixed_content)
            
            # Check for insecure cookies
            cookie_issues = self.check_cookies(response)
            if cookie_issues:
                vulnerabilities.extend(cookie_issues)
            
            # Check for sensitive data in URLs
            url_issues = self.check_sensitive_url_params()
            if url_issues:
                vulnerabilities.extend(url_issues)
            
            # Check for missing security headers
            header_issues = self.check_security_headers(response)
            if header_issues:
                vulnerabilities.extend(header_issues)
            
            # Check for sensitive data in response
            data_exposure = self.check_sensitive_data_exposure(response.text)
            if data_exposure:
                vulnerabilities.extend(data_exposure)
            
        except Exception as e:
            self.log(f"Error during scan: {e}")
        
        return vulnerabilities
    
    def check_ssl_tls(self):
        """Check for SSL/TLS configuration issues."""
        vulnerabilities = []
        
        try:
            hostname = self.hostname
            self.log(f"Checking SSL/TLS configuration for {hostname}")
            
            # Check if site uses HTTPS
            if not self.target_url.startswith('https://'):
                vulnerabilities.append({
                    'type': 'Cryptographic Failure',
                    'risk_level': 'High',
                    'description': 'Website is not using HTTPS encryption',
                    'location': self.target_url,
                    'recommendation': 'Implement HTTPS across the entire site'
                })
                return vulnerabilities
            
            # Attempt to connect using older protocol versions
            context = ssl.create_default_context()
            
            # Check SSL v2 and v3 (should be disabled)
            for protocol in [ssl.PROTOCOL_SSLv23]:
                try:
                    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    conn.settimeout(5)
                    conn.connect((hostname.split(':')[0], 443))
                    
                    # Try to use an older TLS protocol
                    ssl_sock = ssl.wrap_socket(conn, ssl_version=protocol)
                    if ssl_sock:
                        vulnerabilities.append({
                            'type': 'Cryptographic Failure',
                            'risk_level': 'High',
                            'description': 'Server supports outdated SSL/TLS protocols',
                            'location': f"https://{hostname}",
                            'recommendation': 'Disable support for SSL v2/v3 and TLS 1.0/1.1, and use only TLS 1.2 or higher'
                        })
                    ssl_sock.close()
                except:
                    pass
                finally:
                    conn.close()
            
        except Exception as e:
            self.log(f"Error checking SSL/TLS: {e}")
        
        return vulnerabilities
    
    def check_mixed_content(self, soup):
        """Check for mixed content (HTTP resources on HTTPS pages)."""
        vulnerabilities = []
        
        if not self.target_url.startswith('https://'):
            return vulnerabilities
        
        try:
            self.log("Checking for mixed content")
            
            # Find all resources loaded via HTTP
            mixed_content_count = 0
            
            # Check script sources
            for script in soup.find_all('script', src=True):
                if script['src'].startswith('http://'):
                    mixed_content_count += 1
                    self.log(f"Found mixed content: {script['src']}")
            
            # Check stylesheet links
            for link in soup.find_all('link', href=True):
                if link.get('rel') == ['stylesheet'] and link['href'].startswith('http://'):
                    mixed_content_count += 1
                    self.log(f"Found mixed content: {link['href']}")
            
            # Check images
            for img in soup.find_all('img', src=True):
                if img['src'].startswith('http://'):
                    mixed_content_count += 1
                    self.log(f"Found mixed content: {img['src']}")
            
            if mixed_content_count > 0:
                vulnerabilities.append({
                    'type': 'Mixed Content',
                    'risk_level': 'Medium',
                    'description': f'Found {mixed_content_count} HTTP resources loaded on an HTTPS page',
                    'location': self.target_url,
                    'recommendation': 'Ensure all content is loaded via HTTPS'
                })
        except Exception as e:
            self.log(f"Error checking mixed content: {e}")
        
        return vulnerabilities
    
    def check_cookies(self, response):
        """Check for insecure cookie configurations."""
        vulnerabilities = []
        
        try:
            self.log("Checking cookie security")
            
            cookies = response.cookies
            if not cookies:
                return vulnerabilities
            
            insecure_cookies = []
            
            for cookie in cookies:
                # Check for secure flag
                if not cookie.secure and self.target_url.startswith('https://'):
                    insecure_cookies.append(f"{cookie.name} (missing Secure flag)")
                
                # Check for httpOnly flag
                if not cookie.has_nonstandard_attr('httpOnly') and not cookie.has_nonstandard_attr('HttpOnly'):
                    insecure_cookies.append(f"{cookie.name} (missing HttpOnly flag)")
                
                # Check for SameSite attribute
                if not cookie.has_nonstandard_attr('SameSite') and not cookie.has_nonstandard_attr('samesite'):
                    insecure_cookies.append(f"{cookie.name} (missing SameSite attribute)")
            
            if insecure_cookies:
                vulnerabilities.append({
                    'type': 'Insecure Cookies',
                    'risk_level': 'Medium',
                    'description': f'Found insecure cookie configurations: {", ".join(insecure_cookies)}',
                    'location': self.target_url,
                    'recommendation': 'Set Secure, HttpOnly, and SameSite attributes for all cookies'
                })
        except Exception as e:
            self.log(f"Error checking cookies: {e}")
        
        return vulnerabilities
    
    def check_sensitive_url_params(self):
        """Check for sensitive data in URL parameters."""
        vulnerabilities = []
        
        try:
            self.log("Checking URL parameters for sensitive data")
            
            # Get URL parameters
            parsed_url = urlparse(self.target_url)
            params = parse_qs(parsed_url.query)
            
            sensitive_params = []
            
            # List of parameter names that might contain sensitive data
            sensitive_param_names = [
                'password', 'passwd', 'pwd', 'pass', 'secret',
                'token', 'api_key', 'apikey', 'key', 'credit_card',
                'cc', 'ssn', 'social', 'secret', 'private'
            ]
            
            for param in params:
                if param.lower() in sensitive_param_names:
                    sensitive_params.append(param)
            
            if sensitive_params:
                vulnerabilities.append({
                    'type': 'Sensitive Data in URL',
                    'risk_level': 'High',
                    'description': f'URL contains potentially sensitive parameters: {", ".join(sensitive_params)}',
                    'location': self.target_url,
                    'recommendation': 'Never pass sensitive data via URL parameters. Use POST requests with HTTPS instead.'
                })
        except Exception as e:
            self.log(f"Error checking URL parameters: {e}")
        
        return vulnerabilities
    
    def check_security_headers(self, response):
        """Check for missing security headers."""
        vulnerabilities = []
        
        try:
            self.log("Checking security headers")
            
            headers = response.headers
            missing_headers = []
            
            for header, description in self.security_headers.items():
                if header not in headers:
                    missing_headers.append(description)
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'risk_level': 'Medium',
                    'description': f'Missing important security headers: {", ".join(missing_headers[:3])}{"..." if len(missing_headers) > 3 else ""}',
                    'location': self.target_url,
                    'recommendation': 'Implement all recommended security headers'
                })
        except Exception as e:
            self.log(f"Error checking security headers: {e}")
        
        return vulnerabilities
    
    def check_sensitive_data_exposure(self, content):
        """Check for sensitive data exposure in page content."""
        vulnerabilities = []
        
        try:
            self.log("Checking for sensitive data exposure")
            
            exposures = []
            
            for data_type, pattern in self.sensitive_patterns.items():
                matches = pattern.findall(content)
                if matches:
                    exposures.append(f"{data_type} ({len(matches)} instances)")
            
            if exposures:
                vulnerabilities.append({
                    'type': 'Sensitive Data Exposure',
                    'risk_level': 'High',
                    'description': f'Possible sensitive data exposed in page content: {", ".join(exposures)}',
                    'location': self.target_url,
                    'recommendation': 'Never expose sensitive data in page content, and ensure proper encryption for transmission and storage'
                })
        except Exception as e:
            self.log(f"Error checking sensitive data exposure: {e}")
        
        return vulnerabilities