#!/usr/bin/env python3
"""
Scanner for Broken Access Control vulnerabilities (OWASP Top 10 #1)

This module scans a website for potential broken access control issues, including:
- Insecure direct object references (IDOR)
- Missing function level access controls
- Bypassing access controls through URL tampering
- Directory traversal possibilities
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
import re
import random
import time
from bs4 import BeautifulSoup

class BrokenAccessControlScanner:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(target_url))
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36'
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # Endpoints likely to have access control issues
        self.sensitive_endpoints = [
            '/admin', '/dashboard', '/profile', '/account',
            '/user', '/settings', '/config', '/manage',
            '/api', '/private', '/admin_panel', '/moderator',
            '/staff', '/superuser', '/control', '/root'
        ]
        
        # Common parameters that might be vulnerable to IDOR
        self.idor_params = ['id', 'user_id', 'account_id', 'profile_id', 'uid', 'uuid']
        
        # Pattern to find potential values for manipulation
        self.id_pattern = re.compile(r'\/(\d+|[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12})\/?$')
        
    def log(self, message):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"  [DEBUG] {message}")
    
    def scan(self):
        """Main scan function to check for broken access control vulnerabilities."""
        vulnerabilities = []
        self.log(f"Starting broken access control scan on {self.target_url}")
        
        try:
            # Get the main page and extract links
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = self.extract_links(soup)
            
            # Check for sensitive endpoints
            vuln = self.check_sensitive_endpoints()
            if vuln:
                vulnerabilities.extend(vuln)
            
            # Check for direct enumeration vulnerabilities
            vuln = self.check_id_enumeration(links)
            if vuln:
                vulnerabilities.extend(vuln)
            
            # Check for forced browsing vulnerabilities
            vuln = self.check_forced_browsing()
            if vuln:
                vulnerabilities.extend(vuln)
            
            # Check for HTTP method vulnerabilities
            vuln = self.check_http_methods()
            if vuln:
                vulnerabilities.extend(vuln)
            
            # Looking for potential authorization headers in responses
            vuln = self.check_for_auth_headers(response)
            if vuln:
                vulnerabilities.extend(vuln)
            
        except Exception as e:
            self.log(f"Error during scan: {e}")
        
        return vulnerabilities
    
    def extract_links(self, soup):
        """Extract all links from the page."""
        links = []
        try:
            for a_tag in soup.find_all('a', href=True):
                href = a_tag.get('href')
                if href.startswith('/') or href.startswith(self.base_url):
                    full_url = urljoin(self.base_url, href)
                    links.append(full_url)
                    self.log(f"Found link: {full_url}")
        except Exception as e:
            self.log(f"Error extracting links: {e}")
        
        return links
    
    def check_sensitive_endpoints(self):
        """Check if sensitive endpoints are accessible without authentication."""
        vulnerabilities = []
        
        for endpoint in self.sensitive_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                self.log(f"Checking sensitive endpoint: {url}")
                
                response = self.session.get(url, allow_redirects=False, timeout=5)
                
                # If we get a 200 OK status for admin pages without proper authentication,
                # it might indicate broken access control
                if 200 <= response.status_code < 300 and any(keyword in response.text.lower() for keyword in ['admin', 'dashboard', 'control panel']):
                    vulnerabilities.append({
                        'type': 'Broken Access Control',
                        'risk_level': 'High',
                        'description': f'Potentially sensitive endpoint accessible without authentication',
                        'location': url,
                        'recommendation': 'Implement proper access controls and authentication checks for sensitive endpoints'
                    })
                    self.log(f"Potential vulnerability found: {url} returned status {response.status_code}")
            except requests.exceptions.RequestException:
                continue
            
            # Delay to prevent overwhelming the server
            time.sleep(0.5)
        
        return vulnerabilities
    
    def check_id_enumeration(self, links):
        """Check for direct object reference vulnerabilities."""
        vulnerabilities = []
        
        # Extract URLs containing potential IDs
        id_urls = []
        for link in links:
            match = self.id_pattern.search(link)
            if match:
                id_urls.append(link)
        
        for url in id_urls[:5]:  # Limit to 5 to avoid excessive scanning
            try:
                match = self.id_pattern.search(url)
                if match:
                    original_id = match.group(1)
                    self.log(f"Testing IDOR on URL with ID: {url}")
                    
                    # Try accessing the original URL to establish baseline
                    original_response = self.session.get(url, timeout=5)
                    
                    # Try a different ID
                    if original_id.isdigit():
                        new_id = str(int(original_id) + random.randint(1, 10))
                    else:
                        # For UUIDs or other formats, just change the first character
                        new_id = chr(ord(original_id[0]) + 1) + original_id[1:]
                    
                    new_url = url.replace(original_id, new_id)
                    new_response = self.session.get(new_url, timeout=5)
                    
                    # If we can access another user's data with similar status code and response size,
                    # it might indicate an IDOR vulnerability
                    if (new_response.status_code == original_response.status_code == 200 and
                        abs(len(new_response.text) - len(original_response.text)) < len(original_response.text) * 0.3):
                        vulnerabilities.append({
                            'type': 'Insecure Direct Object Reference (IDOR)',
                            'risk_level': 'High',
                            'description': f'Possible IDOR vulnerability where changing ID in URL provides access to other resources',
                            'location': url,
                            'recommendation': 'Implement proper authorization checks to ensure users can only access their own resources'
                        })
                        self.log(f"Potential IDOR vulnerability found: {url}")
            except requests.exceptions.RequestException:
                continue
            
            # Delay to prevent overwhelming the server
            time.sleep(0.5)
        
        return vulnerabilities
    
    def check_forced_browsing(self):
        """Check for forced browsing vulnerabilities."""
        vulnerabilities = []
        
        # Common paths that might be accessible through forced browsing
        paths_to_check = [
            '/backup', '/old', '/dev', '/test', '/temp',
            '/.git', '/.svn', '/.env', '/wp-config.php',
            '/config.php', '/database.yml', '/settings.py'
        ]
        
        for path in paths_to_check:
            try:
                url = urljoin(self.base_url, path)
                self.log(f"Checking for forced browsing: {url}")
                
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200 and "404" not in response.text:
                    vulnerabilities.append({
                        'type': 'Forced Browsing / Information Disclosure',
                        'risk_level': 'Medium',
                        'description': f'Potentially sensitive file or directory accessible through direct URL access',
                        'location': url,
                        'recommendation': 'Restrict access to sensitive files and directories, and remove unused files from production servers'
                    })
                    self.log(f"Potential forced browsing vulnerability found: {url}")
            except requests.exceptions.RequestException:
                continue
            
            # Delay to prevent overwhelming the server
            time.sleep(0.5)
        
        return vulnerabilities
    
    def check_http_methods(self):
        """Check for unauthorized HTTP methods."""
        vulnerabilities = []
        
        try:
            url = self.target_url
            self.log(f"Checking HTTP methods on: {url}")
            
            # Try OPTIONS method to discover allowed methods
            response = self.session.options(url, timeout=5)
            allowed_methods = response.headers.get('Allow', '').split(', ')
            
            if 'PUT' in allowed_methods or 'DELETE' in allowed_methods:
                vulnerabilities.append({
                    'type': 'Insecure HTTP Method',
                    'risk_level': 'Medium',
                    'description': f'Potentially dangerous HTTP methods are enabled: {", ".join([m for m in allowed_methods if m in ["PUT", "DELETE"]])}',
                    'location': url,
                    'recommendation': 'Disable unnecessary HTTP methods or implement proper authentication for them'
                })
                self.log(f"Potentially dangerous HTTP methods allowed: {allowed_methods}")
        except requests.exceptions.RequestException as e:
            self.log(f"Error checking HTTP methods: {e}")
        
        return vulnerabilities
    
    def check_for_auth_headers(self, response):
        """Check response for authorization headers or tokens."""
        vulnerabilities = []
        
        auth_patterns = [
            r'auth[-_]?token\s*[=:]\s*["\'](.*?)["\']',
            r'api[-_]?key\s*[=:]\s*["\'](.*?)["\']',
            r'access[-_]?token\s*[=:]\s*["\'](.*?)["\']',
            r'jwt\s*[=:]\s*["\'](.*?)["\']',
            r'bearer\s+["\']?(.*?)["\']?[,\s}]'
        ]
        
        try:
            for pattern in auth_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'risk_level': 'High',
                        'description': 'Authentication tokens or API keys might be exposed in the response',
                        'location': self.target_url,
                        'recommendation': 'Ensure that authentication tokens are not exposed in responses or JavaScript code'
                    })
                    self.log(f"Potential authentication information disclosure found")
                    break
        except Exception as e:
            self.log(f"Error checking for auth headers: {e}")
        
        return vulnerabilities