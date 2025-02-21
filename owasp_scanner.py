#!/usr/bin/env python3
import argparse
import requests
import json
import re
import time
import subprocess
import concurrent.futures
import socket
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class OWASPScanner:
    def __init__(self, target_url, output_file=None, scan_subdomains=False, threads=5, max_subdomains=50):
        self.target_url = self.normalize_url(target_url)
        self.base_domain = self.extract_base_domain(target_url)
        self.output_file = output_file
        self.scan_subdomains = scan_subdomains
        self.max_subdomains = max_subdomains
        self.subdomains = []
        self.threads = threads
        self.results = {}
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
        }

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def extract_base_domain(self, url):
        parsed_url = urlparse(self.normalize_url(url))
        hostname = parsed_url.hostname
        
        # Extract the base domain (example.com from sub.example.com)
        domain_parts = hostname.split('.')
        if len(domain_parts) > 2:
            return '.'.join(domain_parts[-2:])
        return hostname

    def discover_subdomains(self):
        """Built-in subdomain discovery using assetfinder"""
        print(f"[+] Discovering subdomains for {self.base_domain}...")
        discovered = set()
        
        print("[*] Running assetfinder...")
        try:
            # Run assetfinder command and capture output
            cmd = f"assetfinder --subs-only {self.base_domain}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                # Process successful results
                subdomains = stdout.strip().split('\n')
                for subdomain in subdomains:
                    if subdomain and subdomain.endswith(self.base_domain):
                        discovered.add(subdomain)
                        print(f"[+] Found subdomain: {subdomain}")
                        if len(discovered) >= self.max_subdomains:
                            print(f"[*] Reached maximum subdomain limit ({self.max_subdomains})")
                            break
                
                print(f"[+] Assetfinder found {len(discovered)} subdomains")
            else:
                print(f"[-] Assetfinder error: {stderr}")
                # Fallback to other methods if assetfinder fails
                print("[*] Falling back to certificate transparency logs...")
                self._check_cert_transparency(discovered)
        except FileNotFoundError:
            print("[-] Assetfinder not found in PATH. Please install it or check the path.")
            print("[*] Falling back to certificate transparency logs...")
            self._check_cert_transparency(discovered)
        except Exception as e:
            print(f"[-] Error running assetfinder: {e}")
            print("[*] Falling back to certificate transparency logs...")
            self._check_cert_transparency(discovered)
        
        # Convert discovered subdomains to URLs
        self.subdomains = ['https://' + sub for sub in discovered]
        print(f"[+] Total discovered subdomains: {len(self.subdomains)}")
        return self.subdomains

    def _check_cert_transparency(self, discovered):
        """Helper method to check certificate transparency logs"""
        try:
            ct_url = f"https://crt.sh/?q=%.{self.base_domain}&output=json"
            response = requests.get(ct_url, timeout=10)
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        if 'name_value' in entry:
                            domains = entry['name_value'].split('\n')
                            for domain in domains:
                                # Filter out wildcard entries
                                if '*' not in domain and domain.endswith(self.base_domain):
                                    discovered.add(domain)
                                    if len(discovered) >= self.max_subdomains:
                                        return
                    print(f"[+] Found {len(discovered)} subdomains via cert transparency")
                except json.JSONDecodeError:
                    print("[-] Failed to parse crt.sh JSON response")
            else:
                print(f"[-] Failed to query crt.sh: HTTP {response.status_code}")
        except Exception as e:
            print(f"[-] Error querying certificate transparency logs: {e}")
        
    def check_with_retry(self, url, check_function, max_retries=3):
        """Wrapper function to add reliability to checks with built-in retry mechanism"""
        for attempt in range(max_retries):
            try:
                return check_function(url)
            except (requests.exceptions.RequestException, socket.timeout) as e:
                if attempt == max_retries - 1:
                    return {"findings": [f"Connection error: {str(e)}"], "risk_level": "Unknown"}
                time.sleep(1) 

    def verify_subdomain_connectivity(self, subdomain_url):
        """Verify that subdomain is reachable"""
        try:
            response = self.session.get(subdomain_url, timeout=5, verify=False, allow_redirects=True)
            if response.status_code < 400:
                return subdomain_url
            return None
        except Exception:
            return None
    def scan_single_target(self, target):
        """Scan a single target for all vulnerabilities"""
        self.logger.info(f"Scanning {target}")
        target_results = {}
        
        # OWASP Top 10 2021 checks
        target_results["A01:2021-Broken_Access_Control"] = self.check_with_retry(
            target, self.check_broken_access_control)
        target_results["A02:2021-Cryptographic_Failures"] = self.check_with_retry(
            target, self.check_cryptographic_failures)
        target_results["A03:2021-Injection"] = self.check_with_retry(
            target, self.check_injection)
        target_results["A04:2021-Insecure_Design"] = self.check_with_retry(
            target, self.check_insecure_design)
        target_results["A05:2021-Security_Misconfiguration"] = self.check_with_retry(
            target, self.check_security_misconfiguration)
        target_results["A06:2021-Vulnerable_Components"] = self.check_with_retry(
            target, self.check_vulnerable_components)
        target_results["A07:2021-Auth_Failures"] = self.check_with_retry(
            target, self.check_auth_failures)
        target_results["A08:2021-Software_Data_Integrity_Failures"] = self.check_with_retry(
            target, self.check_software_data_integrity_failures)
        target_results["A09:2021-Logging_Monitoring_Failures"] = self.check_with_retry(
            target, self.check_logging_monitoring_failures)
        target_results["A10:2021-SSRF"] = self.check_with_retry(
            target, self.check_ssrf)
            
        return target_results

    def scan_targets(self):
        """Scan all targets with parallel execution and retry mechanism for consistency"""
        targets = [self.target_url]
        
        # Discover and verify subdomains if enabled
        if self.scan_subdomains:
            discovered = self.discover_subdomains()
            if discovered:
                self.logger.info("Verifying subdomain connectivity...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    verified = list(filter(None, executor.map(self.verify_subdomain_connectivity, discovered)))
                self.logger.info(f"Verified {len(verified)} reachable subdomains")
                targets.extend(verified)
                
        self.logger.info(f"Starting scan against {len(targets)} targets")
        
        # Scan all targets in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            target_results = list(executor.map(self.scan_single_target, targets))
            
        # Aggregate results
        for target, result in zip(targets, target_results):
            self.results[target] = result
            
        self.output_results()
        return self.results


    def check_broken_access_control(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        # Check for directory listing
        try:
            common_dirs = ['/admin/', '/backup/', '/config/', '/dashboard/', '/uploads/', 
                          '/includes/', '/private/', '/users/', '/tmp/', '/old/']
            for directory in common_dirs:
                test_url = urljoin(url, directory)
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    # Check if it's a directory listing
                    if ('Index of' in response.text or 'Directory listing' in response.text or
                        '<title>Index of /' in response.text):
                        results["findings"].append(f"Directory listing enabled at {test_url}")
                        results["risk_level"] = "High"
            
            # Check for direct access to restricted files
            sensitive_files = [
                '/wp-config.php', '/config.php', '/configuration.php', '/database.yml',
                '/settings.py', '/.env', '/.git/config', '/storage/logs/laravel.log',
                '/web.config', '/httpd.conf', '/.htaccess', '/server-status',
                '/login.json', '/api/users', '/actuator/env', '/api/v1/users'
            ]
            
            for file_path in sensitive_files:
                test_url = urljoin(url, file_path)
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                # Check if file might be accessible
                if response.status_code == 200 and len(response.text) > 0:
                    # Check if it looks like configuration data
                    if any(x in response.text.lower() for x in ['password', 'user', 'config', 'database', 'key', 'token']):
                        results["findings"].append(f"Potentially sensitive file accessible: {test_url}")
                        results["risk_level"] = "Critical"
            
            # Check for robots.txt
            robots_url = urljoin(url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5, verify=False)
            if response.status_code == 200:
                sensitive_paths = ['admin', 'backup', 'config', 'dashboard', 'internal', 'private', 'user']
                for path in sensitive_paths:
                    if path in response.text:
                        results["findings"].append(f"Sensitive path '{path}' found in robots.txt")
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "Medium"
            
            # Check for CORS misconfiguration
            headers = {
                'Origin': 'https://malicious-site.com'
            }
            
            response = self.session.get(url, headers=headers, timeout=5, verify=False)
            if 'Access-Control-Allow-Origin' in response.headers:
                acao = response.headers['Access-Control-Allow-Origin']
                if acao == '*' or acao == 'https://malicious-site.com':
                    results["findings"].append(f"CORS misconfiguration: Access-Control-Allow-Origin: {acao}")
                    results["risk_level"] = "Medium"
            
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["risk_level"] = "Low"
            
        return results

    def check_cryptographic_failures(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        parsed_url = urlparse(url)
        
        # Check if HTTPS is used
        if parsed_url.scheme != 'https':
            results["findings"].append("Site not using HTTPS")
            results["risk_level"] = "High"
        else:
            try:
                response = self.session.get(url, timeout=5, verify=False)
                
                # Check for secure cookies
                if 'Set-Cookie' in response.headers:
                    cookies = response.headers.get('Set-Cookie')
                    if 'secure' not in cookies.lower():
                        results["findings"].append("Cookies without Secure flag")
                        results["risk_level"] = "Medium"
                    if 'httponly' not in cookies.lower():
                        results["findings"].append("Cookies without HttpOnly flag")
                        results["risk_level"] = "Medium"
                    if 'samesite' not in cookies.lower():
                        results["findings"].append("Cookies without SameSite attribute")
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "Low"
                
                # Check for security headers
                sec_headers = {
                    'Strict-Transport-Security': 'Missing HSTS header',
                    'Content-Security-Policy': 'Missing CSP header',
                    'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                    'Referrer-Policy': 'Missing Referrer-Policy header',
                    'Permissions-Policy': 'Missing Permissions-Policy header'
                }
                
                for header, message in sec_headers.items():
                    if header not in response.headers:
                        results["findings"].append(message)
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "Medium"
                
                # Check for weak SSL/TLS configuration using socket
                hostname = parsed_url.netloc.split(':')[0]
                try:
                    context = socket.create_connection((hostname, 443), timeout=5)
                    if context:
                        # TLS 1.0 check
                        import ssl
                        try:
                            # Try to establish connection
                            tls_context = ssl.create_default_context()
                            tls_context.check_hostname = False
                            tls_context.verify_mode = ssl.CERT_NONE
                            tls_socket = tls_context.wrap_socket(socket.socket(), server_hostname=hostname)
                            tls_socket.connect((hostname, 443))
                            results["findings"].append("Server supports TLS 1.0 (deprecated)")
                            results["risk_level"] = "Medium"
                            tls_socket.close()
                        except:
                            pass
                except:
                    results["findings"].append("Unable to check TLS version (connection failed)")
            
            except Exception as e:
                results["error"] = str(e)
        
        if not results["findings"]:
            results["risk_level"] = "Low"
            
        return results

    def check_injection_vulnerabilities(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        try:
            # Get all forms from the page
            response = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            # Basic test vectors for common injection types
            test_vectors = {
                "SQL Injection": ["'", "1' OR '1'='1", "1; --", "' OR 1=1;--"],
                "XSS": ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "javascript:alert(1)"],
                "Command Injection": ["; ls -la", "& dir", "| cat /etc/passwd"],
                "LDAP Injection": ["*)(|(objectClass=*", "*)(uid=*))(|(uid=*"],
                "NoSQL Injection": ['{"$gt":""}', '{"$ne":null}'],
                "Template Injection": ["${7*7}", "{{7*7}}", "<%= 7*7 %>"]
            }
            
            if forms:
                results["findings"].append(f"Found {len(forms)} forms that could be tested for injection")
                
                for i, form in enumerate(forms, 1):
                    action = form.get('action')
                    if not action:
                        action = url
                    elif not action.startswith(('http://', 'https://')):
                        action = urljoin(url, action)
                    
                    method = form.get('method', 'get').lower()
                    inputs = form.find_all('input')
                    
                    # Check for CSRF protection
                    has_csrf_token = False
                    for input_field in inputs:
                        input_name = input_field.get('name', '').lower()
                        if any(token_name in input_name for token_name in ['csrf', 'token', '_token', 'xsrf']):
                            has_csrf_token = True
                            break
                    
                    if not has_csrf_token:
                        results["findings"].append(f"Form #{i} at {action} lacks CSRF protection")
                        results["risk_level"] = "Medium"
                    
                    # Check for input validation attributes
                    for input_field in inputs:
                        input_type = input_field.get('type', '').lower()
                        input_name = input_field.get('name', '').lower()
                        
                        # Check for potential injection points
                        if input_type in ['text', 'search', 'url', 'hidden'] or not input_type:
                            # Check for suspicious parameter names
                            suspicious_names = ['q', 'query', 'search', 'id', 'page', 'file', 'path', 'url', 'load']
                            if any(sus_name in input_name for sus_name in suspicious_names):
                                results["findings"].append(f"Form #{i} has potentially injectable parameter: {input_name}")
                                if results["risk_level"] == "Unknown":
                                    results["risk_level"] = "Medium"
                                
                            # Check for missing validation attributes
                            has_validation = False
                            validation_attrs = ['pattern', 'maxlength', 'minlength']
                            for attr in validation_attrs:
                                if input_field.has_attr(attr):
                                    has_validation = True
                                    break
                                    
                            if not has_validation and input_type == 'text':
                                results["findings"].append(f"Form #{i} field '{input_name}' lacks input validation constraints")
            else:
                results["findings"].append("No forms found for basic injection testing")
                
            # Check URL parameters in the current page
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parsed_url.query.split('&')
                for param in query_params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        results["findings"].append(f"URL parameter '{param_name}' could be tested for injection")
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "Medium"
            
            # Check for common API endpoints
            api_endpoints = ['/api/', '/graphql', '/v1/', '/rest/', '/query', '/data']
            for endpoint in api_endpoints:
                test_url = urljoin(url, endpoint)
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 201, 401, 403]:
                    # Check if response is JSON
                    is_json = False
                    try:
                        if 'application/json' in response.headers.get('Content-Type', ''):
                            json_data = response.json()
                            is_json = True
                    except:
                        pass
                        
                    if is_json or response.status_code in [401, 403]:
                        results["findings"].append(f"Potential API endpoint found at {test_url}")
                        results["risk_level"] = "Medium"
            
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["risk_level"] = "Low"
            
        return results

    def check_insecure_design(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        try:
            # Check for common insecure design patterns
            
            # 1. Check for user enumeration in login/registration
            user_endpoints = ['/login', '/register', '/signup', '/forgot-password', '/reset-password']
            for endpoint in user_endpoints:
                test_url = urljoin(url, endpoint)
                response = self.session.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    # Test for user enumeration
                    test_data = {'username': 'nonexistentuser12345', 'email': 'nonexistent12345@example.com'}
                    response = self.session.post(test_url, data=test_data, allow_redirects=False, verify=False, timeout=5)
                    
                    # Look for error messages that might reveal user existence
                    if response.status_code == 200:
                        indicators = ['user not found', 'email not found', 'account does not exist', 'not registered']
                        for indicator in indicators:
                            if indicator in response.text.lower():
                                results["findings"].append(f"Potential user enumeration at {test_url} - reveals non-existent accounts")
                                results["risk_level"] = "Medium"
                                break
            
            # 2. Check for absence of rate limiting
            auth_endpoints = ['/login', '/api/login', '/auth', '/api/auth', '/token']
            for endpoint in auth_endpoints:
                test_url = urljoin(url, endpoint)
                
                # Send multiple requests in quick succession
                responses = []
                for _ in range(5):
                    response = self.session.get(test_url, timeout=2, verify=False, allow_redirects=False)
                    responses.append(response)
                
                # If all responses are successful and none indicate rate limiting
                if all(r.status_code < 400 for r in responses) and \
                   not any('rate' in r.text.lower() or 'limit' in r.text.lower() for r in responses) and \
                   not any('Retry-After' in r.headers for r in responses) and \
                   not any('X-RateLimit' in key for r in responses for key in r.headers):
                    results["findings"].append(f"Potential lack of rate limiting at {test_url}")
                    if results["risk_level"] == "Unknown":
                        results["risk_level"] = "Medium"
            
            # 3. Check for default credentials
            admin_endpoints = ['/admin', '/administrator', '/wp-admin', '/cpanel', '/dashboard']
            default_credentials = [
                {'username': 'admin', 'password': 'admin'},
                {'username': 'admin', 'password': 'password'},
                {'username': 'root', 'password': 'root'}
            ]
            
            for endpoint in admin_endpoints:
                test_url = urljoin(url, endpoint)
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=True)
                
                if response.status_code == 200 and ('login' in response.text.lower() or 'password' in response.text.lower()):
                    results["findings"].append(f"Admin login page found at {test_url} - could be tested for default credentials")
                    if results["risk_level"] == "Unknown":
                        results["risk_level"] = "Medium"
            
            # 4. Check for predictable resource locations
            common_resources = ['/backup.zip', '/backup.sql', '/database.sql', '/www.zip', '/2023.zip', '/old.zip']
            for resource in common_resources:
                test_url = urljoin(url, resource)
                response = self.session.head(test_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    results["findings"].append(f"Potentially exposed backup/resource file: {test_url}")
                    results["risk_level"] = "High"
            
            # 5. Check for information disclosure in error messages
            error_triggers = ['/error', '/?error=1', '/undefined', '/null', "/'"]
            for trigger in error_triggers:
                test_url = urljoin(url, trigger)
                response = self.session.get(test_url, timeout=3, verify=False)
                
                if response.status_code >= 400:
                    error_indicators = ['exception', 'stacktrace', 'syntax error', 'failed query']
                    for indicator in error_indicators:
                        if indicator in response.text.lower():
                            results["findings"].append(f"Detailed technical error messages revealed at {test_url}")
                            results["risk_level"] = "Medium"
                            break
            
        except Exception as e:
            results["error"] = str(e)
            
        if not results["findings"]:
            results["risk_level"] = "Unknown"
            results["findings"].append("Insecure design assessment requires deeper testing and design review")
            
        return results

    def check_security_misconfiguration(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        try:
            # Check for default error pages that leak information
            error_paths = ['/error', '/doesnotexist_' + str(int(time.time())), '/api/invalid']
            for path in error_paths:
                test_url = urljoin(url, path)
                response = self.session.get(test_url, timeout=5, verify=False)
                
                # Look for common error signatures
                error_signatures = [
                    'Exception:', 'Error:', 'Stack trace:', 'at java.', 
                    'at javax.', 'at org.apache', 'SQLException', 'ORA-',
                    'mysql_', 'Fatal error:', 'Warning:', 'DEBUG', 'syntax error',
                    'Traceback', 'Django', 'Rails', 'PHP Fatal error', 'Node.js',
                    'SQLSTATE[', 'Microsoft OLE DB Provider'
                ]
                
                for signature in error_signatures:
                    if signature in response.text:
                        results["findings"].append(f"Information leakage through errors at {test_url} - contains '{signature}'")
                        results["risk_level"] = "High"
                        break
            
            # Check for common development files
            dev_files = [
                '.git/HEAD', '.env', '.env.backup', '.env.local', 'config.json', 'config.php.bak', 
                'config.js.bak', 'package.json', 'composer.json', 'wp-config.php.bak',
                'Dockerfile', 'docker-compose.yml', '.htaccess.bak', '.svn/entries',
                'web.config.bak', 'phpinfo.php', 'info.php', 'test.php', 'database.yml',
                'credentials.xml', 'settings.py.bak', '.DS_Store', '.idea/workspace.xml',
                'node_modules/.package-lock.json'
            ]
            
            for file in dev_files:
                test_url = urljoin(url, file)
                response = self.session.get(test_url, timeout=3, verify=False, allow_redirects=False)
                
                if response.status_code == 200 and len(response.text) > 0:
                    # Check if it's not a generic 404 page disguised as 200
                    if not any(x in response.text.lower() for x in ['not found', 'error 404', 'page not found', '404']):
                        # For git repository detection, look for specific content
                        if file == '.git/HEAD' and 'ref:' in response.text:
                            results["findings"].append(f"Git repository exposure at {test_url}")
                            results["risk_level"] = "Critical"
                        # For environment files, check for key patterns
                        elif file == '.env' and ('=' in response.text or 'KEY' in response.text or 'SECRET' in response.text):
                            results["findings"].append(f"Environment file exposure at {test_url}")
                            results["risk_level"] = "Critical"
                        # For other files, general detection
                        else:
                            results["findings"].append(f"Potential sensitive file exposure: {test_url}")
                            if results["risk_level"] == "Unknown":
                                results["risk_level"] = "High"
                        
            # Check HTTP methods
            try:
                response = self.session.options(url, timeout=5, verify=False)
                if 'Allow' in response.headers:
                    allowed_methods = response.headers['Allow']
                    dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                    
                    for method in dangerous_methods:
                        if method in allowed_methods:
                            results["findings"].append(f"Potentially dangerous HTTP method enabled: {method}")
                            if results["risk_level"] == "Unknown":
                                results["risk_level"] = "Medium"
                            
                    # Test TRACE method for cross-site tracing (XST)
                    if 'TRACE' in allowed_methods:
                        trace_headers = {'X-Custom-Header': 'test-xst-vulnerability'}
                        trace_response = requests.request('TRACE', url, headers=trace_headers, timeout=5, verify=False)
                        if 'X-Custom-Header' in trace_response.text:
                            results["findings"].append("Cross-Site Tracing (XST) vulnerability detected")
                            results["risk_level"] = "Medium"
            except:
                pass
            
            # Check for unnecessary features/ports
            try:
                common_ports = {
                    2082: 'cPanel',
                    2083: 'cPanel SSL',
                    2086: 'WHM',
                    2087: 'WHM SSL',
                    2095: 'Webmail',
                    2096: 'Webmail SSL',
                    8080: 'Alternative HTTP',
                    8443: 'Alternative HTTPS',
                    3000: 'Development server',
                    4000: 'Development server',
                    5000: 'Development server',
                    8000: 'Development server',
                    8888: 'Development server',
                    9000: 'PHP-FPM',
                    9090: 'WebSphere Admin',
                    10000: 'Webmin'
                }
                
                parsed_url = urlparse(url)
                hostname = parsed_url.netloc.split(':')[0]
                
                for port, service in common_ports.items():
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((hostname, port))
                        if result == 0:
                            results["findings"].append(f"Open port detected: {port} ({service})")
                            results["risk_level"] = "Medium"
                        sock.close()
                    except:
                        pass
            except:
                pass
                
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["risk_level"] = "Low"
            
        return results

    def check_vulnerable_components(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers = response.headers
            
            # Check for server software disclosure
            server_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime', 
                            'X-Version', 'X-Generator', 'X-Drupal-Cache', 'X-Varnish']
            
            for header in server_headers:
                if header in headers:
                    results["findings"].append(f"Server component disclosure: {header}: {headers[header]}")
                    if results["risk_level"] == "Unknown":
                        results["risk_level"] = "Medium"
            
            # Check for common JavaScript libraries
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script')
            
            vulnerable_libraries = {
                'jquery-1.': 'jQuery 1.x',
                'jquery-2.0': 'jQuery 2.0.x',
                'jquery-2.1': 'jQuery 2.1.x',
                'jquery-2.2.0': 'jQuery 2.2.0',
                'jquery-2.2.1': 'jQuery 2.2.1',
                'jquery-2.2.2': 'jQuery 2.2.2',
                'jquery-2.2.3': 'jQuery 2.2.3',
                'jquery.min.js': 'jQuery (potentially outdated)',
                'angular.js': 'AngularJS (potentially outdated)',
                'angular.min.js': 'AngularJS (potentially outdated)',
                'bootstrap.min.js': 'Bootstrap (potentially outdated)',
                'react-0.': 'React 0.x',
                'react.min.js': 'React (potentially outdated)',
                'vue.min.js': 'Vue.js (potentially outdated)',
                'lodash.min.js': 'Lodash (potentially outdated)',
                'moment.min.js': 'Moment.js (potentially outdated)',
                'prototype.js': 'Prototype.js (potentially outdated)',
            }
            
            found_libs = set()
            for script in scripts:
                src = script.get('src', '')
                if src:
                    for lib_sig, lib_name in vulnerable_libraries.items():
                        if lib_sig in src:
                            found_libs.add(f"{lib_name} (from {src})")
                            
                # Also check inline scripts
                if script.string:
                    for lib_sig, lib_name in vulnerable_libraries.items():
                        if lib_sig in script.string:
                            found_libs.add(f"{lib_name} (inline script)")
            
            for lib in found_libs:
                results["findings"].append(f"Potentially vulnerable library detected: {lib}")
                if results["risk_level"] == "Unknown":
                    results["risk_level"] = "Medium"
            
            # Look for common CMS signatures
            cms_signatures = {
                'WordPress': ['/wp-content/', '/wp-includes/', 'wp-login', 'WordPress'],
                'Joomla': ['/administrator/', 'Joomla!', '/com_content/'],
                'Drupal': ['/sites/default/', 'Drupal.settings', '/node/'],
                'Magento': ['/skin/frontend/', 'Mage.', '/magento/'],
                'Shopify': ['Shopify.theme', 'shopify.', '/cdn.shopify.com/'],
                'WooCommerce': ['woocommerce', 'WooCommerce'],
                'PrestaShop': ['prestashop', 'PrestaShop'],
                'TYPO3': ['typo3', 'TYPO3'],
                'DotNetNuke': ['DotNetNuke', 'dnn.js'],
                'SharePoint': ['SharePoint', '_layouts/15/'],
            }
            
            for cms, patterns in cms_signatures.items():
                for pattern in patterns:
                    if pattern in response.text:
                        results["findings"].append(f"CMS detected: {cms} - check for known vulnerabilities")
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "Medium"
                        break
            
            # Check for outdated TLS
            parsed_url = urlparse(url)
            if parsed_url.scheme == 'https':
                hostname = parsed_url.netloc.split(':')[0]
                try:
                    # Check for outdated TLS protocols
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            version = ssock.version()
                            if 'TLSv1.0' in version or 'TLSv1.1' in version:
                                results["findings"].append(f"Outdated TLS version: {version}")
                                results["risk_level"] = "Medium"
                except:
                    pass
            
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["risk_level"] = "Low"
            
        return results

    def check_authentication_failures(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        try:
            # Look for login pages
            login_paths = ['/login', '/admin/login', '/user/login', '/signin', '/wp-login.php', 
                          '/admin', '/user', '/dashboard', '/account/login', '/auth/login']
            
            login_page = None
            for path in login_paths:
                test_url = urljoin(url, path)
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=True)
                
                # Simple heuristic to identify login pages
                login_indicators = ['login', 'password', 'username', 'sign in', 'log in', 'email', 'authentication']
                password_field = False
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Check for password input fields
                    password_inputs = soup.find_all('input', {'type': 'password'})
                    if password_inputs:
                        password_field = True
                    
                    # Check for login indicators in the text
                    page_text = soup.get_text().lower()
                    if password_field and any(indicator in page_text for indicator in login_indicators):
                        login_page = test_url
                        break
            
            if login_page:
                results["findings"].append(f"Login page found at {login_page}")
                
                # Check for HTTPS
                if not login_page.startswith('https://'):
                    results["findings"].append("Login page not using HTTPS")
                    results["risk_level"] = "High"
                
                # Check for brute force protection
                attempts = 0
                max_attempts = 3
                for i in range(max_attempts):
                    test_data = {
                        'username': f'test_user_{int(time.time())}',
                        'password': 'invalid_password_123',
                        'email': f'test_{int(time.time())}@example.com'
                    }
                    
                    response = self.session.post(login_page, data=test_data, allow_redirects=True, verify=False)
                    
                    # Check for indicators of rate limiting or lockout
                    rate_limit_indicators = ['rate limit', 'too many attempts', 'blocked', 'lockout', 'try again later']
                    if any(indicator in response.text.lower() for indicator in rate_limit_indicators):
                        break
                    attempts += 1
                
                if attempts == max_attempts:
                    results["findings"].append("No evidence of brute force protection")
                    results["risk_level"] = "High"
                
                # Check for account enumeration
                test_users = ['admin', 'administrator', 'user', 'test']
                enumeration_detected = False
                
                for user in test_users:
                    # Try a request with potentially valid username but wrong password
                    test_data = {'username': user, 'password': 'wrong_password_123'}
                    response = self.session.post(login_page, data=test_data, allow_redirects=True, verify=False)
                    
                    # Check for username-specific responses
                    enum_indicators = [
                        'user not found', 'username not found', 'invalid username',
                        'incorrect password', 'wrong password', 'valid username'
                    ]
                    
                    for indicator in enum_indicators:
                        if indicator in response.text.lower():
                            results["findings"].append(f"Account enumeration possible: '{indicator}' message revealed")
                            enumeration_detected = True
                            if results["risk_level"] == "Unknown":
                                results["risk_level"] = "Medium"
                            break
                    
                    if enumeration_detected:
                        break
                
                # Check for "remember me" functionality
                soup = BeautifulSoup(response.text, 'html.parser')
                remember_elements = soup.find_all(['input', 'checkbox'], string=lambda t: t and 'remember' in t.lower())
                remember_labels = soup.find_all('label', string=lambda t: t and 'remember' in t.lower())
                
                if remember_elements or remember_labels:
                    results["findings"].append("'Remember me' functionality detected - ensure proper implementation")
                    if results["risk_level"] == "Unknown":
                        results["risk_level"] = "Low"
                
                # Check for password reset functionality
                reset_links = soup.find_all('a', string=lambda t: t and ('forgot' in t.lower() or 'reset' in t.lower()))
                if reset_links:
                    reset_url = reset_links[0].get('href')
                    if reset_url and not reset_url.startswith(('http://', 'https://')):
                        reset_url = urljoin(url, reset_url)
                    
                    results["findings"].append(f"Password reset functionality found at {reset_url} - ensure proper implementation")
                    if results["risk_level"] == "Unknown":
                        results["risk_level"] = "Low"
            else:
                results["findings"].append("No login page found for authentication testing")
        
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["risk_level"] = "Unknown"
            
        return results

    def check_data_integrity(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        try:
            # Check for dependencies and supply chain
            response = self.session.get(url, timeout=5, verify=False)
            
            # Check for package manifests
            package_files = ['/package.json', '/composer.json', '/requirements.txt', '/Gemfile', '/pom.xml']
            for pkg_file in package_files:
                test_url = urljoin(url, pkg_file)
                pkg_response = self.session.get(test_url, timeout=3, verify=False)
                
                if pkg_response.status_code == 200 and len(pkg_response.text) > 0:
                    try:
                        # Check if it's a valid package file
                        if pkg_file in ['/package.json', '/composer.json']:
                            if '{' in pkg_response.text and '}' in pkg_response.text:
                                results["findings"].append(f"Exposed package manifest: {test_url}")
                                results["risk_level"] = "Medium"
                        elif pkg_file == '/requirements.txt':
                            if '==' in pkg_response.text or '>=' in pkg_response.text:
                                results["findings"].append(f"Exposed Python requirements: {test_url}")
                                results["risk_level"] = "Medium"
                        elif pkg_file == '/Gemfile':
                            if 'gem ' in pkg_response.text:
                                results["findings"].append(f"Exposed Ruby Gemfile: {test_url}")
                                results["risk_level"] = "Medium"
                        elif pkg_file == '/pom.xml':
                            if '<project' in pkg_response.text and '<dependencies' in pkg_response.text:
                                results["findings"].append(f"Exposed Maven POM: {test_url}")
                                results["risk_level"] = "Medium"
                    except:
                        pass
            
            # Check for content integrity protection
            if 'Content-Security-Policy' not in response.headers:
                results["findings"].append("No Content Security Policy (CSP) header")
                results["risk_level"] = "Medium"
            else:
                csp = response.headers['Content-Security-Policy']
                if "script-src 'unsafe-inline'" in csp or "script-src 'unsafe-eval'" in csp:
                    results["findings"].append("CSP allows unsafe JavaScript execution")
                    results["risk_level"] = "Medium"
            
            # Check for Subresource Integrity (SRI)
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            styles = soup.find_all('link', {'rel': 'stylesheet', 'href': True})
            
            external_resources = []
            for script in scripts:
                if script.get('src', '').startswith(('http://', 'https://')):
                    external_resources.append(script)
            
            for style in styles:
                if style.get('href', '').startswith(('http://', 'https://')):
                    external_resources.append(style)
            
            missing_integrity = []
            for resource in external_resources:
                if not resource.has_attr('integrity'):
                    resource_url = resource.get('src') if resource.name == 'script' else resource.get('href')
                    missing_integrity.append(resource_url)
            
            if missing_integrity:
                results["findings"].append(f"Missing Subresource Integrity (SRI) for {len(missing_integrity)} external resources")
                if results["risk_level"] == "Unknown":
                    results["risk_level"] = "Medium"
            
            # Check for cache poisoning vectors
            cache_headers = ['Cache-Control', 'ETag', 'Last-Modified', 'Expires', 'Pragma']
            missing_cache_headers = [header for header in cache_headers if header not in response.headers]
            
            if missing_cache_headers:
                results["findings"].append(f"Missing cache control headers: {', '.join(missing_cache_headers)}")
                if results["risk_level"] == "Unknown":
                    results["risk_level"] = "Low"
            
            # Check for unsigned redirects
            redirect_params = ['return', 'redirect', 'redir', 'next', 'url', 'target', 'destination', 'to']
            parsed_url = urlparse(url)
            query_params = parsed_url.query.split('&') if parsed_url.query else []
            
            for param in query_params:
                param_name = param.split('=')[0] if '=' in param else param
                if param_name.lower() in redirect_params:
                    results["findings"].append(f"Potential unsigned redirect parameter: {param_name}")
                    if results["risk_level"] == "Unknown":
                        results["risk_level"] = "Medium"
        
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["risk_level"] = "Low"
            
        return results

    def check_logging_monitoring(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        try:
            # This check is limited by its nature - we can only infer from external signals
            
            # 1. Check for server response headers that might indicate logging
            response = self.session.get(url, timeout=5, verify=False)
            
            # Check for headers that might indicate tracing/logging
            trace_headers = ['X-Request-ID', 'X-Correlation-ID', 'X-Trace-ID', 'X-Ray', 
                           'X-B3-TraceId', 'X-Amzn-Trace-Id', 'traceparent', 'X-Cloud-Trace-Context']
            
            found_trace_headers = []
            for header in trace_headers:
                if header in response.headers:
                    found_trace_headers.append(header)
            
            if found_trace_headers:
                results["findings"].append(f"Request tracing headers detected: {', '.join(found_trace_headers)}")
                results["risk_level"] = "Low"
            else:
                results["findings"].append("No request tracing headers detected - might indicate insufficient logging")
                results["risk_level"] = "Medium"
            
            # 2. Check for common log files
            log_files = ['/logs/', '/log/', '/debug/', '/error.log', '/debug.log', '/application.log', 
                       '/app.log', '/errors/', '/traces/', '/server-status']
            
            for log_path in log_files:
                log_url = urljoin(url, log_path)
                log_response = self.session.get(log_url, timeout=3, verify=False, allow_redirects=False)
                
                if log_response.status_code == 200 and len(log_response.text) > 0:
                    # Check if it looks like a log file
                    log_indicators = ['error', 'info', 'debug', 'warn', 'trace', 'exception', 'log', 'timestamp']
                    if any(indicator in log_response.text.lower() for indicator in log_indicators):
                        results["findings"].append(f"Potential log file exposure at {log_url}")
                        results["risk_level"] = "Critical"
            
            # 3. Test for log injection
            test_vectors = [
                '"><script>alert(1)</script>',
                '\n\r\nSYSTEM ERROR\r\n',
                '$(cat /etc/passwd)',
                '"; DROP TABLE users; --',
                '%0d%0aLocation: https://evil.com'
            ]
            
            # Prepare a random parameter value for injection
            random_param = f"param_{int(time.time())}"
            
            for vector in test_vectors:
                test_url = f"{url}?{random_param}={vector}"
                try:
                    error_response = self.session.get(test_url, timeout=3, verify=False, allow_redirects=True)
                    
                    # If we get a 500 error, it might indicate log processing issues
                    if error_response.status_code == 500:
                        results["findings"].append(f"Potential log injection: server error with payload {vector}")
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "High"
                except:
                    pass
            
            # 4. Look for monitoring endpoints
            monitoring_endpoints = [
                '/metrics', '/actuator/metrics', '/probe', '/health', '/status',
                '/actuator/health', '/api/health', '/admin/metrics', '/monitoring'
            ]
            
            for endpoint in monitoring_endpoints:
                mon_url = urljoin(url, endpoint)
                try:
                    mon_response = self.session.get(mon_url, timeout=3, verify=False, allow_redirects=False)
                    
                    if mon_response.status_code == 200:
                        # Check if it might be a metrics endpoint
                        if 'application/json' in mon_response.headers.get('Content-Type', ''):
                            try:
                                metrics = mon_response.json()
                                results["findings"].append(f"Exposed metrics endpoint: {mon_url}")
                                results["risk_level"] = "Medium"
                            except:
                                pass
                except:
                    pass
            
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["findings"].append("Logging and monitoring assessment requires internal access")
            results["risk_level"] = "Unknown"
            
        return results

    def check_ssrf_vulnerability(self, url):
        results = {"findings": [], "risk_level": "Unknown"}
        
        try:
            # Look for potential SSRF vulnerable parameters
            ssrf_param_names = ['url', 'uri', 'link', 'src', 'href', 'path', 'dest', 'redirect',
                              'return_url', 'next', 'site', 'html', 'file', 'reference', 'feed',
                              'host', 'port', 'connect', 'callback']
            
            # Check URL parameters
            parsed_url = urlparse(url)
            query_params = parsed_url.query.split('&') if parsed_url.query else []
            
            for param in query_params:
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    
                    if param_name.lower() in ssrf_param_names:
                        results["findings"].append(f"Potential SSRF parameter in URL: {param_name}")
                        results["risk_level"] = "Medium"
                    
                    # Check if value is a URL itself
                    if param_value.startswith(('http://', 'https://')):
                        results["findings"].append(f"URL parameter value could be tested for SSRF: {param_name}={param_value}")
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "Medium"
            
            # Check for forms with potential SSRF vectors
            response = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                inputs = form.find_all('input')
                
                for input_field in inputs:
                    input_name = input_field.get('name', '').lower()
                    
                    if input_name in ssrf_param_names:
                        results["findings"].append(f"Potential SSRF parameter in form: {input_name}")
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "Medium"
            
            # Look for SSRF vectors in HTTP Headers
            headers = {
                'Referer': 'https://internal.service.local', 
                'X-Forwarded-For': '127.0.0.1',
                'X-Forwarded-Host': 'internal.local',
                'X-Original-URL': '/admin'
            }
            
            try:
                header_response = self.session.get(url, headers=headers, timeout=5, verify=False)
                
                # Check for unusual status codes or responses
                if header_response.status_code in [301, 302, 307, 308]:
                    redirect_url = header_response.headers.get('Location', '')
                    if 'internal' in redirect_url or '127.0.0.1' in redirect_url or 'localhost' in redirect_url:
                        results["findings"].append(f"Potential SSRF via header redirection: {redirect_url}")
                        results["risk_level"] = "High"
            except:
                pass
            
            # Check for webhooks or API integrations
            api_patterns = ['/api/', '/hook/', '/webhook/', '/callback/', '/integration/', '/connect/']
            
            for pattern in api_patterns:
                api_url = urljoin(url, pattern)
                try:
                    api_response = self.session.get(api_url, timeout=3, verify=False, allow_redirects=False)
                    
                    if api_response.status_code != 404:
                        results["findings"].append(f"Potential API endpoint that could be tested for SSRF: {api_url}")
                        if results["risk_level"] == "Unknown":
                            results["risk_level"] = "Low"
                except:
                    pass
            
        except Exception as e:
            results["error"] = str(e)
        
        if not results["findings"]:
            results["risk_level"] = "Low"
            
        return results

    def output_results(self):
        """Output scan results to file or console"""
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"[+] Results saved to {self.output_file}")
        
        # Print summary to console
        print("\n===== SCAN SUMMARY =====")
        for target, target_results in self.results.items():
            print(f"\nTarget: {target}")
            print("-------------------")
            
            # Summarize issues by risk level
            risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
            finding_counts = {}
            
            for category, result in target_results.items():
                risk_level = result.get("risk_level", "Unknown")
                finding_count = len(result.get("findings", []))
                
                if risk_level in risk_counts:
                    risk_counts[risk_level] += 1
                
                finding_counts[category] = {
                    "count": finding_count,
                    "risk_level": risk_level
                }
            
            # Print risk summary
            print("Risk summary:")
            for risk, count in risk_counts.items():
                print(f"- {risk}: {count}")
            
            # Print top issues
            print("\nTop issues:")
            sorted_findings = sorted(finding_counts.items(), 
                                    key=lambda x: (["Critical", "High", "Medium", "Low", "Unknown"].index(x[1]["risk_level"]), -x[1]["count"]))
            
            for category, info in sorted_findings[:5]:
                if info["count"] > 0:
                    print(f"- {category}: {info['count']} finding(s), Risk: {info['risk_level']}")
            
            print("\nUse the JSON output for full details.")

def print_banner():
    banner = """
                /$$$$$$  /$$      /$$  /$$$$$$   /$$$$$$  /$$$$$$$  
               /$$__  $$| $$  /$ | $$ /$$__  $$ /$$__  $$| $$__  $$ 
              | $$  \ $$| $$ /$$$| $$| $$  \ $$| $$  \__/| $$  \ $$ 
              | $$  | $$| $$/$$ $$ $$| $$$$$$$$|  $$$$$$ | $$$$$$$/ 
              | $$  | $$| $$$$_  $$$$| $$__  $$ \____  $$| $$____/  
              | $$  | $$| $$$/ \  $$$| $$  | $$ /$$  \ $$| $$       
              |  $$$$$$/| $$/   \  $$| $$  | $$|  $$$$$$/| $$       
               \______/ |__/     \__/|__/  |__/ \______/ |__/       
                                                                
    ╔═══════════════════════════════════════════════════════════════════╗
    ║  \033[38;5;196mS\033[38;5;202mE\033[38;5;208mC\033[38;5;214mU\033[38;5;220mR\033[38;5;226mI\033[38;5;118mT\033[38;5;46mY\033[0m  \033[38;5;39mS\033[38;5;45mC\033[38;5;51mA\033[38;5;87mN\033[38;5;123mN\033[38;5;159mE\033[38;5;195mR\033[0m  \033[38;5;201mB\033[38;5;207mY\033[0m  \033[38;5;226mA\033[38;5;220mN\033[38;5;214mU\033[38;5;208mB\033[38;5;202mH\033[38;5;196mA\033[38;5;162mV\033[0m  \033[38;5;135mM\033[38;5;141mO\033[38;5;147mH\033[38;5;153mA\033[38;5;159mN\033[38;5;165mD\033[38;5;171mA\033[38;5;177mS\033[0m  ║
    ╚═══════════════════════════════════════════════════════════════════╝

    ⚡ \033[38;5;39m█▓▒░\033[0m \033[1;31mVulnerability\033[0m \033[1;33mDetection\033[0m \033[1;32mEngine\033[0m \033[38;5;39m░▒▓█\033[0m ⚡
         \033[38;5;196m◢\033[38;5;202m◤\033[38;5;214m◢\033[38;5;226m◤\033[0m \033[1;36mVersion 2.0 Security Shield\033[0m \033[38;5;226m◢\033[38;5;214m◤\033[38;5;202m◢\033[38;5;196m◤\033[0m
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(description='OWASP Top 10 Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output JSON file for detailed results')
    parser.add_argument('-s', '--subdomains', action='store_true', help='Discover and scan subdomains')
    parser.add_argument('-m', '--max-subdomains', type=int, default=50, help='Maximum number of subdomains to scan (default: 50)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    
    args = parser.parse_args()
    
    print("====================================")
    print("OWASP Top 10 Web Vulnerability Scanner")
    print("====================================")
    print(f"Target: {args.url}")
    print(f"Subdomain discovery: {'Enabled' if args.subdomains else 'Disabled'}")
    print(f"Threads: {args.threads}")
    print("====================================")
    
    scanner = OWASPScanner(
        args.url, 
        output_file=args.output,
        scan_subdomains=args.subdomains,
        threads=args.threads,
        max_subdomains=args.max_subdomains
    )
    
    scanner.scan_targets()
    
    print("\n[+] Scan completed!")

if __name__ == "__main__":
    print_banner()
    main()
