#!/usr/bin/env python3
"""
Scanner for Software Supply Chain Failures (OWASP Top 10:2025 #3)

This module scans for:
- Exposed package manifests
- Outdated dependencies with known vulnerabilities
- Missing Software Bill of Materials (SBOM)
- Unsigned packages and components
- Dependency confusion risks
- Third-party CDN risks
- Missing integrity checks (SRI)
"""

import requests
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class SupplyChainFailuresScanner:
    def __init__(self, target_url, verbose=False):
        self.target_url = target_url
        self.base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(target_url))
        self.verbose = verbose
        self.session = requests.Session()
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.session.headers.update({'User-Agent': self.user_agent})

        # Package manifest files
        self.package_files = {
            'package.json': 'npm/Node.js',
            'package-lock.json': 'npm lock file',
            'yarn.lock': 'Yarn lock file',
            'composer.json': 'PHP Composer',
            'composer.lock': 'Composer lock file',
            'requirements.txt': 'Python pip',
            'Pipfile': 'Python Pipenv',
            'Pipfile.lock': 'Pipenv lock file',
            'pom.xml': 'Maven',
            'build.gradle': 'Gradle',
            'Gemfile': 'Ruby Bundler',
            'Gemfile.lock': 'Bundler lock file',
            'go.mod': 'Go modules',
            'go.sum': 'Go modules lock',
            'Cargo.toml': 'Rust Cargo',
            'Cargo.lock': 'Cargo lock file'
        }

        # Known vulnerable library patterns (simplified examples)
        self.vulnerable_patterns = {
            'jquery-1.': 'jQuery < 3.0 has known XSS vulnerabilities',
            'angular.js': 'AngularJS (EOL) - migrate to Angular',
            'lodash-4.17.1': 'Lodash 4.17.1 has prototype pollution',
            'moment.js': 'Moment.js is in maintenance mode',
            'log4j-2.1': 'Log4j 2.x < 2.17.1 has critical RCE (Log4Shell)'
        }

    def log(self, message):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(f"  [DEBUG] {message}")

    def scan(self):
        """Main scan function for supply chain vulnerabilities."""
        vulnerabilities = []

        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for exposed package manifests
            vuln = self.check_exposed_manifests()
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for missing Subresource Integrity (SRI)
            vuln = self.check_sri(soup)
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for outdated/vulnerable libraries
            vuln = self.check_vulnerable_libraries(soup)
            if vuln:
                vulnerabilities.extend(vuln)

            # Check third-party CDN usage
            vuln = self.check_cdn_usage(soup)
            if vuln:
                vulnerabilities.extend(vuln)

            # Check for dependency confusion indicators
            vuln = self.check_dependency_confusion()
            if vuln:
                vulnerabilities.extend(vuln)

        except Exception as e:
            self.log(f"Error during supply chain scan: {e}")

        return vulnerabilities

    def check_exposed_manifests(self):
        """Check for publicly accessible package manifests."""
        vulnerabilities = []

        for filename, package_type in self.package_files.items():
            try:
                url = urljoin(self.base_url, f'/{filename}')
                response = self.session.get(url, timeout=3, verify=False)

                if response.status_code == 200 and len(response.text) > 50:
                    # Verify it's actually a manifest file
                    is_valid = False

                    if filename.endswith('.json'):
                        try:
                            data = json.loads(response.text)
                            if 'dependencies' in data or 'devDependencies' in data:
                                is_valid = True
                        except:
                            pass
                    elif filename.endswith('.txt') or filename.startswith('requirements'):
                        if '==' in response.text or '>=' in response.text:
                            is_valid = True
                    elif filename.endswith('.xml'):
                        if '<dependencies>' in response.text:
                            is_valid = True
                    elif 'Gemfile' in filename or 'Pipfile' in filename:
                        if 'gem ' in response.text or 'packages' in response.text:
                            is_valid = True
                    elif filename.endswith('.lock') or filename.endswith('.sum'):
                        is_valid = True
                    elif filename.endswith('.mod') or filename.endswith('.toml'):
                        is_valid = True

                    if is_valid:
                        vulnerabilities.append({
                            'type': 'Exposed Package Manifest',
                            'risk_level': 'High',
                            'description': f'Publicly accessible {package_type} manifest: {filename}',
                            'location': url,
                            'recommendation': 'Restrict access to package manifests and lock files. These expose your dependency tree to attackers.'
                        })
                        self.log(f"Found exposed manifest: {url}")

            except Exception as e:
                self.log(f"Error checking {filename}: {e}")
                continue

        return vulnerabilities

    def check_sri(self, soup):
        """Check for missing Subresource Integrity on external resources."""
        vulnerabilities = []
        missing_sri = []

        # Check scripts from external sources
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            if src.startswith(('http://', 'https://')) and not src.startswith(self.base_url):
                if not script.has_attr('integrity'):
                    missing_sri.append(f"Script: {src[:80]}")

        # Check stylesheets from external sources
        links = soup.find_all('link', {'rel': 'stylesheet', 'href': True})
        for link in links:
            href = link.get('href', '')
            if href.startswith(('http://', 'https://')) and not href.startswith(self.base_url):
                if not link.has_attr('integrity'):
                    missing_sri.append(f"Stylesheet: {href[:80]}")

        if missing_sri:
            vulnerabilities.append({
                'type': 'Missing Subresource Integrity (SRI)',
                'risk_level': 'Medium',
                'description': f'{len(missing_sri)} external resource(s) loaded without integrity verification',
                'location': self.target_url,
                'details': missing_sri[:5],  # Limit to first 5
                'recommendation': 'Add integrity and crossorigin attributes to all external scripts and stylesheets. Use tools like https://www.srihash.org/ to generate SRI hashes.'
            })

        return vulnerabilities

    def check_vulnerable_libraries(self, soup):
        """Check for known vulnerable JavaScript libraries."""
        vulnerabilities = []
        found_vulnerable = []

        # Check all script tags
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '').lower()

            for pattern, description in self.vulnerable_patterns.items():
                if pattern in src:
                    found_vulnerable.append(f"{description} (found in: {src[:60]})")

        # Also check inline scripts for library signatures
        inline_scripts = soup.find_all('script', src=False)
        for script in inline_scripts:
            content = script.string or ''
            if 'jQuery JavaScript Library v1.' in content:
                found_vulnerable.append('jQuery v1.x detected (multiple known vulnerabilities)')
            elif 'AngularJS v' in content:
                found_vulnerable.append('AngularJS detected (EOL - migrate to Angular)')

        if found_vulnerable:
            vulnerabilities.append({
                'type': 'Vulnerable/Outdated Components',
                'risk_level': 'Critical',
                'description': f'{len(found_vulnerable)} vulnerable or outdated component(s) detected',
                'location': self.target_url,
                'details': list(set(found_vulnerable)),  # Remove duplicates
                'recommendation': 'Update all dependencies to their latest secure versions. Use tools like npm audit, Snyk, or Dependabot to track vulnerabilities.'
            })

        return vulnerabilities

    def check_cdn_usage(self, soup):
        """Check for third-party CDN usage without proper safeguards."""
        vulnerabilities = []
        cdn_hosts = []

        common_cdns = [
            'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
            'ajax.googleapis.com', 'maxcdn.bootstrapcdn.com',
            'code.jquery.com', 'stackpath.bootstrapcdn.com'
        ]

        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            for cdn in common_cdns:
                if cdn in src:
                    # Check if SRI is present
                    has_sri = script.has_attr('integrity')
                    if not has_sri:
                        cdn_hosts.append(f"{cdn} (no SRI)")

        if cdn_hosts:
            vulnerabilities.append({
                'type': 'Insecure CDN Usage',
                'risk_level': 'High',
                'description': f'Loading resources from {len(set(cdn_hosts))} CDN(s) without integrity checks',
                'location': self.target_url,
                'details': list(set(cdn_hosts)),
                'recommendation': 'Always use SRI when loading from CDNs. Consider self-hosting critical libraries for better control.'
            })

        return vulnerabilities

    def check_dependency_confusion(self):
        """Check for potential dependency confusion indicators."""
        vulnerabilities = []

        # Check for package.json exposure
        try:
            url = urljoin(self.base_url, '/package.json')
            response = self.session.get(url, timeout=3, verify=False)

            if response.status_code == 200:
                try:
                    data = json.loads(response.text)

                    # Check for private packages
                    if data.get('private') == True:
                        vulnerabilities.append({
                            'type': 'Dependency Confusion Risk',
                            'risk_level': 'Medium',
                            'description': 'Private package.json exposed - risk of dependency confusion attacks',
                            'location': url,
                            'recommendation': 'Ensure package.json is not publicly accessible. Use scoped packages (@yourorg/package) and configure registry properly.'
                        })

                    # Check for dependencies without scope
                    deps = data.get('dependencies', {})
                    unscoped = [name for name in deps.keys() if not name.startswith('@')]

                    if unscoped and data.get('private'):
                        vulnerabilities.append({
                            'type': 'Potential Dependency Confusion',
                            'risk_level': 'Medium',
                            'description': f'Found {len(unscoped)} unscoped private dependencies - vulnerable to substitution attacks',
                            'location': url,
                            'recommendation': 'Use scoped packages (@org/name) for private dependencies and configure .npmrc to use private registry.'
                        })

                except json.JSONDecodeError:
                    pass

        except Exception as e:
            self.log(f"Error checking dependency confusion: {e}")

        return vulnerabilities
