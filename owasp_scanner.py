#!/usr/bin/env python3
import argparse
import requests
import json
import re
import time
import ssl
import subprocess
import concurrent.futures
import socket
import dns.resolver
import datetime
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
        print(f"[+] Discovering subdomains for {self.base_domain} using assetfinder...")
        discovered = set()
    
        try:
            # Run assetfinder command
            cmd = ["assetfinder", "--subs-only", self.base_domain]
            print(f"[*] Executing: {' '.join(cmd)}")
            
            # Use subprocess to run assetfinder and capture output
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                print(f"[-] Error running assetfinder: {stderr}")
                return []
            
            # Process the output
            if stdout:
                subdomains = [line.strip() for line in stdout.splitlines() if line.strip()]
                for subdomain in subdomains:
                    if subdomain.endswith(self.base_domain):
                        discovered.add(subdomain)
                        print(f"[+] Found subdomain: {subdomain}")
                        if len(discovered) >= self.max_subdomains:
                            break
            
            print(f"[+] Found {len(discovered)} subdomains via assetfinder")
                
        except FileNotFoundError:
            print("[-] Error: assetfinder not found. Please install it with: 'go install github.com/tomnomnom/assetfinder@latest'")
        except Exception as e:
            print(f"[-] Error while running assetfinder: {e}")
        
        # Convert discovered subdomains to URLs
        self.subdomains = ['https://' + sub for sub in discovered]
        print(f"[+] Total discovered subdomains: {len(self.subdomains)}")
        
        return self.subdomains

    def verify_subdomain_connectivity(self, subdomain_url):
        """Verify that subdomain is reachable"""
        try:
            response = self.session.get(subdomain_url, timeout=5, verify=False, allow_redirects=True)
            if response.status_code < 400:
                return subdomain_url
            return None
        except Exception:
            return None

    def scan_targets(self):
        targets = [self.target_url]
        if self.scan_subdomains:
            discovered = self.discover_subdomains()
            if discovered:
                # Verify connectivity to discovered subdomains
                print("[*] Verifying subdomain connectivity...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    verified = list(filter(None, executor.map(self.verify_subdomain_connectivity, discovered)))
                
                print(f"[+] Verified {len(verified)} reachable subdomains")
                targets.extend(verified)
        
        print(f"[+] Starting scan against {len(targets)} targets")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            target_results = list(executor.map(self.scan_single_target, targets))
        
        # Aggregate results
        for target, result in zip(targets, target_results):
            self.results[target] = result
        
        self.output_results()
        return self.results
    
    def output_results(self):
        """Output scan results (could be printed or saved to file)"""
        if self.output_file:
            with open(self.output_file, 'w') as f:
                for target, result in self.results.items():
                    f.write(f"Target: {target}\n")
                    f.write(f"Status: {result['status']}\n")
                    f.write(f"Vulnerabilities: {result['vulnerabilities']}\n\n")
        else:
            for target, result in self.results.items():
                print(f"Target: {target}")
                print(f"Status: {result['status']}")
                print(f"Vulnerabilities: {result['vulnerabilities']}")

    def scan_single_target(self, url):
        print(f"[*] Scanning {url}")
        target_results = {
            "A01:2021-Broken_Access_Control": self.check_broken_access_control(url),
            "A02:2021-Cryptographic_Failures": self.check_cryptographic_failures(url),
            "A03:2021-Injection": self.check_injection_vulnerabilities(url),
            "A04:2021-Insecure_Design": self.check_insecure_design(url),
            "A05:2021-Security_Misconfiguration": self.check_security_misconfiguration(url),
            "A06:2021-Vulnerable_Components": self.check_vulnerable_components(url),
            "A07:2021-Auth_Failures": self.check_authentication_failures(url),
            "A08:2021-Software_Data_Integrity_Failures": self.check_data_integrity(url),
            "A09:2021-Logging_Monitoring_Failures": self.check_logging_monitoring(url),
            "A10:2021-SSRF": self.check_ssrf_vulnerability(url),
        }
        return target_results

    def check_broken_access_control(self, url):
        results = {"findings": [], "risk_level": "Unknown", "details": {}}
        
        try:
            # Track vulnerabilities by category for detailed reporting
            vuln_categories = {
                "directory_listing": [],
                "sensitive_files": [],
                "robots_txt_exposure": [],
                "cors_misconfig": [],
                "missing_access_control": [],
                "idor_vuln": [],
                "jwt_issues": [],
                "http_method_issues": [],
                "authentication_bypass": []
            }
            
            # 1. DIRECTORY LISTING CHECKS
            # Enhanced directory list including cloud-specific and framework directories
            common_dirs = [
                '/admin/', '/backup/', '/config/', '/dashboard/', '/uploads/', '/includes/', 
                '/private/', '/users/', '/tmp/', '/old/', '/assets/', '/logs/', '/api/', 
                '/internal/', '/dev/', '/.aws/', '/.github/', '/app/', '/dist/', '/src/',
                '/content/', '/media/', '/static/', '/cgi-bin/', '/vendor/', '/node_modules/',
                '/composer/', '/wp-admin/', '/wp-content/', '/wp-includes/', '/administrator/',
                '/panel/', '/portal/', '/manager/', '/management/', '/backend/', '/filemanager/',
                '/examples/', '/install/', '/setup/', '/test/', '/testing/'
            ]
            
            for directory in common_dirs:
                test_url = urljoin(url, directory)
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 301, 302]:
                    # Check if it's a directory listing
                    dir_indicators = [
                        'Index of', 'Directory listing', '<title>Index of /', 
                        'Parent Directory', '[To Parent Directory]', 
                        '<!-- indexing -->', 'Directory: /', '<h1>Index of'
                    ]
                    
                    if any(indicator in response.text for indicator in dir_indicators):
                        finding = {
                            "url": test_url,
                            "status_code": response.status_code,
                            "evidence": "Directory listing detected",
                            "remediation": "Disable directory listing in web server configuration"
                        }
                        vuln_categories["directory_listing"].append(finding)
            
            # 2. SENSITIVE FILE CHECKS
            sensitive_files = {
                "config_files": [
                    '/wp-config.php', '/config.php', '/configuration.php', '/database.yml',
                    '/settings.py', '/.env', '/app.config', '/appsettings.json', 
                    '/config.json', '/connection.config', '/default.conf', 
                    '/config/database.yml', '/application.properties', '/application.yml'
                ],
                "log_files": [
                    '/storage/logs/laravel.log', '/error.log', '/debug.log', '/access.log',
                    '/logs/app.log', '/var/log/apache2.log', '/var/log/nginx.log',
                    '/app.log', '/audit.log', '/system.log'
                ],
                "backup_files": [
                    '/backup.sql', '/dump.sql', '/website.bak', '/db.bak', '/www.zip',
                    '/site.tar.gz', '/backup.tar.gz', '/public_html.zip', '/old.zip',
                    '/.git/config', '/.svn/entries', '/.hg/store'
                ],
                "server_info": [
                    '/server-status', '/server-info', '/status', '/phpinfo.php', '/info.php',
                    '/apc.php', '/opcache.php', '/system_status', '/monitor.php'
                ],
                "admin_interfaces": [
                    '/adminer.php', '/phpmyadmin/', '/sqladmin/', '/webadmin/',
                    '/cpanel', '/plesk', '/whmcs', '/webmail/', '/roundcube/'
                ],
                "api_docs": [
                    '/swagger-ui.html', '/api-docs', '/swagger/', '/graphql',
                    '/api/documentation', '/openapi.json', '/actuator/mappings'
                ],
                "monitoring": [
                    '/prometheus', '/metrics', '/actuator/health', '/actuator/env',
                    '/actuator/httptrace', '/actuator/heapdump', '/actuator/loggers',
                    '/nagios/', '/zabbix/', '/munin/'
                ]
            }
            
            for category, files in sensitive_files.items():
                for file_path in files:
                    test_url = urljoin(url, file_path)
                    response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    
                    if response.status_code == 200 and len(response.text) > 0:
                        sensitive_keywords = [
                            'password', 'user', 'config', 'database', 'key', 'token', 
                            'secret', 'admin', 'credentials', 'pass', 'pwd', 'auth',
                            'api_key', 'apikey', 'access_key', 'db_', 'connection', 'private',
                            'certificate', 'bearer', 'passwd', 'root', 'administrator'
                        ]
                        
                        # More sophisticated content checking based on file type
                        is_sensitive = False
                        evidence = ""
                        
                        if category == "config_files" and any(keyword in response.text.lower() for keyword in sensitive_keywords):
                            is_sensitive = True
                            evidence = "Configuration file with sensitive data"
                        elif category == "log_files" and (len(response.text) > 1000 or any(kw in response.text.lower() for kw in ['error', 'exception', 'stack trace', 'warning'])):
                            is_sensitive = True
                            evidence = "Log file with potential sensitive information"
                        elif category == "backup_files" and (len(response.text) > 5000 or any(kw in response.text.lower() for kw in ['insert into', 'create table', 'dump', 'backup'])):
                            is_sensitive = True
                            evidence = "Backup file with database or site data"
                        elif category == "server_info" and any(kw in response.text.lower() for kw in ['php version', 'server at', 'system', 'build date', 'server version']):
                            is_sensitive = True
                            evidence = "Server information disclosure"
                        elif category == "admin_interfaces" and any(kw in response.text.lower() for kw in ['login', 'admin', 'dashboard', 'panel']):
                            is_sensitive = True
                            evidence = "Admin interface accessible"
                        elif category == "api_docs" and any(kw in response.text.lower() for kw in ['api', 'swagger', 'endpoint', 'request', 'response']):
                            is_sensitive = True
                            evidence = "API documentation exposed"
                        elif category == "monitoring" and any(kw in response.text.lower() for kw in ['metrics', 'health', 'status', 'memory', 'uptime']):
                            is_sensitive = True
                            evidence = "Monitoring endpoint exposed"
                        
                        if is_sensitive:
                            finding = {
                                "url": test_url,
                                "category": category,
                                "status_code": response.status_code,
                                "evidence": evidence,
                                "remediation": f"Restrict access to {category} or move to non-public location"
                            }
                            vuln_categories["sensitive_files"].append(finding)
            
            # 3. ROBOTS.TXT ANALYSIS 
            robots_url = urljoin(url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5, verify=False)
            if response.status_code == 200:
                sensitive_paths = [
                    'admin', 'backup', 'config', 'dashboard', 'internal', 'private', 'user',
                    'login', 'management', 'secret', 'secure', 'security', 'staff',
                    'portal', 'console', 'exchange', 'auth', 'account', 'administrator',
                    'sensitive', 'restricted', 'settings', 'system', 'control'
                ]
                
                found_paths = []
                for path in sensitive_paths:
                    if path in response.text.lower():
                        found_paths.append(path)
                        
                        # Also try accessing the path to verify it exists
                        test_url = urljoin(url, f'/{path}/')
                        try:
                            path_response = self.session.get(test_url, timeout=3, verify=False, allow_redirects=False)
                            if path_response.status_code in [200, 301, 302, 401, 403]:
                                finding = {
                                    "path": path,
                                    "url": test_url,
                                    "status_code": path_response.status_code,
                                    "exists": True,
                                    "evidence": f"Path mentioned in robots.txt and appears to exist",
                                    "remediation": "Consider removing sensitive paths from robots.txt"
                                }
                            else:
                                finding = {
                                    "path": path,
                                    "url": test_url,
                                    "status_code": path_response.status_code,
                                    "exists": False,
                                    "evidence": f"Path mentioned in robots.txt but may not exist",
                                    "remediation": "Remove unnecessary entries from robots.txt"
                                }
                            vuln_categories["robots_txt_exposure"].append(finding)
                        except Exception:
                            # If connection fails, still record the finding
                            finding = {
                                "path": path,
                                "evidence": f"Path mentioned in robots.txt but couldn't verify existence",
                                "remediation": "Review and clean up robots.txt file"
                            }
                            vuln_categories["robots_txt_exposure"].append(finding)
            
            # 4. COMPREHENSIVE CORS TESTS
            origins_to_test = [
                'https://malicious-site.com',
                'https://attacker.com',
                'null',
                url.replace('https://', 'https://evil-').replace('http://', 'http://evil-'),
                url + '.attacker.com',
                url.replace('://', '://subdomain.'),
                '*'
            ]
            
            for test_origin in origins_to_test:
                headers = {'Origin': test_origin}
                response = self.session.get(url, headers=headers, timeout=5, verify=False)
                
                cors_issues = []
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    acao = response.headers['Access-Control-Allow-Origin']
                    
                    # Check for various CORS issues
                    if acao == '*':
                        cors_issues.append("Wildcard (*) origin allowed")
                    elif acao == 'null':
                        cors_issues.append("'null' origin allowed - sandboxed iframes can access")
                    elif test_origin == acao:
                        cors_issues.append(f"Server reflects arbitrary origin: {test_origin}")
                    elif acao.endswith(test_origin.split('://')[-1]):
                        cors_issues.append(f"Possible origin reflection vulnerability with suffix matching")
                    
                    # Check for credentials with permissive CORS
                    if 'Access-Control-Allow-Credentials' in response.headers:
                        if response.headers['Access-Control-Allow-Credentials'].lower() == 'true':
                            if acao == '*' or test_origin == acao or acao == 'null':
                                cors_issues.append(f"Critical: Credentials allowed with permissive origin: {acao}")
                    
                    if cors_issues:
                        finding = {
                            "origin_tested": test_origin,
                            "acao_value": acao,
                            "credentials_allowed": 'Access-Control-Allow-Credentials' in response.headers and response.headers['Access-Control-Allow-Credentials'].lower() == 'true',
                            "issues": cors_issues,
                            "remediation": "Implement strict CORS policy with specific trusted origins and avoid credentials with permissive origins"
                        }
                        vuln_categories["cors_misconfig"].append(finding)
            
            # 5. FUNCTION LEVEL ACCESS CONTROL TESTS
            # Test authenticated-only endpoints with varying permissions
            admin_endpoints = [
                '/admin/users', '/api/admin', '/dashboard/settings', '/manage/config',
                '/admin/settings', '/admin/system', '/administrator/index.php',
                '/wp-admin/options.php', '/api/v1/admin', '/control/site',
                '/management/users', '/console/settings', '/settings/global',
                '/api/internal', '/api/private', '/api/restricted'
            ]
            
            user_endpoints = [
                '/api/user/profile', '/account/settings', '/profile/edit',
                '/api/v1/users/me', '/dashboard', '/my-account', '/preferences',
                '/api/documents', '/api/v1/orders', '/api/v1/transactions'
            ]
            
            # Expanded checking for function level access control
            for endpoint in admin_endpoints:
                test_url = urljoin(url, endpoint)
                
                # Try without authentication
                try:
                    no_auth_response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    
                    # If status code is 200 and doesn't seem to be a login page, potential issue
                    if no_auth_response.status_code == 200 and not any(kw in no_auth_response.text.lower() for kw in ['login', 'sign in', 'authenticate']):
                        finding = {
                            "url": test_url,
                            "status_code": no_auth_response.status_code,
                            "auth_required": False,
                            "evidence": "Admin endpoint accessible without authentication",
                            "severity": "Critical",
                            "remediation": "Implement proper authentication checks for all admin endpoints"
                        }
                        vuln_categories["missing_access_control"].append(finding)
                    
                    # Try with fake authorization header - some implementations only check presence, not validity
                    headers = {'Authorization': 'Bearer FAKE_TOKEN_FOR_TESTING1234567890'}
                    fake_auth_response = self.session.get(test_url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                    
                    if fake_auth_response.status_code == 200 and fake_auth_response.text != no_auth_response.text:
                        finding = {
                            "url": test_url,
                            "status_code": fake_auth_response.status_code,
                            "auth_bypass": True,
                            "evidence": "Endpoint may accept invalid tokens or have improper token validation",
                            "severity": "Critical",
                            "remediation": "Implement proper JWT/token validation"
                        }
                        vuln_categories["authentication_bypass"].append(finding)
                except Exception:
                    pass  # Continue with next endpoint if this one fails
            
            # 6. INSECURE DIRECT OBJECT REFERENCE (IDOR) TESTS
            idor_endpoints = [
                '/api/users/', '/api/documents/', '/api/orders/', '/api/transactions/',
                '/api/invoices/', '/api/files/', '/api/records/', '/api/items/',
                '/user/profile/', '/account/', '/document/', '/order/'
            ]
            
            for endpoint in idor_endpoints:
                for i in range(1, 5):  # Try a few sequential IDs
                    test_url = urljoin(url, f'{endpoint}{i}')
                    try:
                        response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                        
                        if response.status_code == 200:
                            # Check if response contains user/personal data
                            data_indicators = ['email', 'username', 'user_id', 'firstname', 'lastname',
                                            'address', 'phone', 'ssn', 'birth', 'credit', 'payment',
                                            'order_id', 'document_id', 'account']
                            
                            if any(indicator in response.text.lower() for indicator in data_indicators):
                                # Try to extract a sample of the potential exposed data (safely)
                                data_snippet = ""
                                try:
                                    # See if it's JSON data
                                    if response.headers.get('Content-Type', '').startswith('application/json'):
                                        data = response.json()
                                        # Get first few keys as evidence
                                        data_snippet = "Fields exposed: " + ", ".join(list(data.keys())[:5])
                                except:
                                    # Not JSON or couldn't parse, take a safe text sample
                                    data_snippet = "Data may contain personal information"
                                
                                finding = {
                                    "url": test_url,
                                    "endpoint_type": endpoint,
                                    "status_code": response.status_code,
                                    "evidence": data_snippet,
                                    "remediation": "Implement proper authorization checks for all object references"
                                }
                                vuln_categories["idor_vuln"].append(finding)
                                break  # Found one instance, no need to check more IDs for this endpoint
                    except Exception:
                        continue  # Skip to next ID or endpoint
            
            # 7. HTTP METHOD TESTING
            methods_to_test = ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'DEBUG']
            
            for method in methods_to_test:
                try:
                    response = self.session.request(method, url, timeout=5, verify=False)
                    
                    # Check for concerning responses
                    if method == 'TRACE' and 'TRACE /' in response.text:
                        finding = {
                            "method": method,
                            "status_code": response.status_code,
                            "evidence": "HTTP TRACE method enabled - potential for Cross-Site Tracing (XST)",
                            "remediation": "Disable TRACE method on your web server"
                        }
                        vuln_categories["http_method_issues"].append(finding)
                    
                    elif method in ['PUT', 'DELETE'] and response.status_code in [200, 201, 202, 204]:
                        finding = {
                            "method": method,
                            "status_code": response.status_code,
                            "evidence": f"HTTP {method} method appears to be allowed without authentication",
                            "remediation": f"Restrict {method} method or implement proper authentication"
                        }
                        vuln_categories["http_method_issues"].append(finding)
                    
                    elif method == 'OPTIONS' and response.status_code == 200:
                        if 'Allow' in response.headers:
                            allowed_methods = response.headers['Allow']
                            if any(m in allowed_methods for m in ['PUT', 'DELETE']):
                                finding = {
                                    "method": "OPTIONS",
                                    "status_code": response.status_code,
                                    "allowed_methods": allowed_methods,
                                    "evidence": "Potentially dangerous HTTP methods allowed",
                                    "remediation": "Restrict HTTP methods to only those required"
                                }
                                vuln_categories["http_method_issues"].append(finding)
                except Exception:
                    continue  # Skip to next method
            
            # 8. JWT TOKEN TESTING
            auth_endpoints = ['/api/login', '/api/token', '/api/auth', '/oauth/token', '/login']
            
            for endpoint in auth_endpoints:
                test_url = urljoin(url, endpoint)
                try:
                    # Look for JWT in cookies or response body
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    # Check for JWT in cookies
                    for cookie in response.cookies:
                        cookie_value = cookie.value
                        if cookie_value.count('.') == 2 and all(part.strip() for part in cookie_value.split('.')):
                            # Likely a JWT token, test for none algorithm vulnerability
                            finding = {
                                "url": test_url,
                                "cookie_name": cookie.name,
                                "evidence": "Potential JWT token found in cookies",
                                "recommended_tests": "Test for algorithm switching (none/HS256), weak signature verification, missing exp/nbf claims"
                            }
                            vuln_categories["jwt_issues"].append(finding)
                except Exception:
                    continue  # Skip to next endpoint
            
            # Process all findings and determine risk level
            for category, findings in vuln_categories.items():
                if findings:
                    results["details"][category] = findings
                    results["findings"].extend([f"{category.replace('_', ' ').title()}: {len(findings)} issue(s) found"])
            
            # Determine overall risk level based on findings
            if any(len(findings) > 0 for category, findings in vuln_categories.items() 
                if category in ["sensitive_files", "missing_access_control", "authentication_bypass"]):
                results["risk_level"] = "Critical"
            elif any(len(findings) > 0 for category, findings in vuln_categories.items() 
                    if category in ["idor_vuln", "directory_listing", "jwt_issues"]):
                results["risk_level"] = "High"
            elif any(len(findings) > 0 for category, findings in vuln_categories.items()):
                results["risk_level"] = "Medium"
            elif not results["findings"]:
                results["risk_level"] = "Low"
                results["findings"].append("No broken access control issues detected.")
            
        except Exception as e:
            results["error"] = str(e)
            results["findings"].append(f"Error during testing: {str(e)}")
        
        finally:
            # Add test metadata
            results["test_timestamp"] = datetime.datetime.now().isoformat()
            results["test_coverage"] = {
                "directories_tested": len(common_dirs),
                "files_tested": sum(len(files) for files in sensitive_files.values()),
                "endpoints_tested": len(admin_endpoints) + len(user_endpoints) + len(idor_endpoints)
            }
        
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
                            # Try to establish connection with TLS 1.0
                            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
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
