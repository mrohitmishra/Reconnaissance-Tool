#!/usr/bin/env python3
"""
Bug Bounty Reconnaissance Tool
A comprehensive tool for authorized security testing and bug bounty research

Author: [Rohit Mishra]
License: MIT
GitHub: [github.com/mrohitmishra]

This tool performs reconnaissance and vulnerability analysis for authorized targets only.
Use only on systems you own or have explicit written permission to test.
"""

import requests
import socket
import ssl
import json
import threading
import time
import subprocess
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime
import argparse
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    """Color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class ReconTool:
    def __init__(self, target):
        self.target = target
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'ports': {},
            'technologies': {},
            'directories': [],
            'vulnerabilities': [],
            'ssl_info': {},
            'headers': {},
            'manual_testing_suggestions': []
        }
        # Load API keys from environment variables
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.securitytrails_api_key = os.getenv("SECURITYTRAILS_API_KEY")
        
        # Common directories for discovery
        self.common_dirs = [
            'admin', 'login', 'dashboard', 'api', 'v1', 'v2', 'test',
            'dev', 'staging', 'backup', 'config', 'upload', 'uploads',
            'files', 'docs', 'documentation', 'phpmyadmin', 'wp-admin',
            'wp-content', 'wp-includes', '.git', '.env', 'robots.txt',
            'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml'
        ]

    def banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                    Bug Bounty Recon Tool                     ║
║                   For Authorized Testing Only                 ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
Target: {Colors.GREEN}{self.target}{Colors.END}
Started: {Colors.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}
        """
        print(banner)

    def print_status(self, message, status="INFO"):
        """Print formatted status messages"""
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "CRITICAL": Colors.PURPLE
        }
        color = colors.get(status, Colors.WHITE)
        print(f"[{color}{status}{Colors.END}] {message}")

    def subdomain_discovery(self):
        """
        Subdomain Discovery Module
        
        Methods used:
        1. Certificate Transparency Logs (crt.sh)
        2. DNS enumeration
        3. Third-party APIs (if available)
        
        APIs Required:
        - crt.sh (Free, no API key needed)
        - SecurityTrails API (Optional, requires key)
        - VirusTotal API (Optional, requires key)
        """
        self.print_status("Starting subdomain discovery...")
        
        # Method 1: Certificate Transparency Logs
        try:
            self.print_status("Checking Certificate Transparency logs...")
            ct_url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(ct_url, timeout=10)
            
            if response.status_code == 200:
                ct_data = response.json()
                subdomains = set()
                
                for entry in ct_data:
                    name = entry.get('name_value', '')
                    # Clean up the subdomain names
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(f'.{self.target}'):
                            subdomains.add(subdomain)
                
                self.results['subdomains'].extend(list(subdomains))
                self.print_status(f"Found {len(subdomains)} subdomains from CT logs", "SUCCESS")
                
        except Exception as e:
            self.print_status(f"CT log search failed: {str(e)}", "ERROR")

        # Method 2: DNS enumeration (common subdomains)
        self.print_status("Performing DNS enumeration...")
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'app', 'mobile', 'secure', 'vpn', 'ssh', 'remote',
            'blog', 'shop', 'store', 'support', 'help', 'docs'
        ]
        
        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{self.target}"
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subs]
            for future in as_completed(futures):
                result = future.result()
                if result and result not in self.results['subdomains']:
                    self.results['subdomains'].append(result)
        
        self.print_status(f"Total subdomains found: {len(self.results['subdomains'])}", "SUCCESS")

    def port_scanning(self, target_host):
        """
        Port Scanning Module
        
        Scans common ports to identify running services
        Uses Python's socket library for basic TCP scanning
        
        No external APIs required
        """
        self.print_status(f"Scanning ports for {target_host}...")
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5984, 6379, 8080,
            8443, 9200, 9300, 27017, 27018, 27019
        ]
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target_host, port))
                sock.close()
                
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, port) for port in common_ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        self.results['ports'][target_host] = sorted(open_ports)
        if open_ports:
            self.print_status(f"Open ports on {target_host}: {open_ports}", "SUCCESS")

    def technology_detection(self, url):
        """
        Technology Stack Detection
        
        Identifies:
        - Web servers
        - Frameworks
        - CMS platforms
        - Programming languages
        - Security headers
        
        Uses HTTP headers and response analysis
        No external APIs required (but can integrate with Wappalyzer API)
        """
        self.print_status(f"Detecting technologies for {url}...")
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            content = response.text[:5000]  # First 5KB for analysis
            
            # Store security headers
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Powered-By': headers.get('X-Powered-By'),
                'Server': headers.get('Server')
            }
            
            self.results['headers'][url] = security_headers
            
            # Technology detection patterns
            tech_patterns = {
                'WordPress': [r'wp-content', r'wp-includes', r'WordPress'],
                'Drupal': [r'Drupal', r'sites/default/files'],
                'Joomla': [r'Joomla', r'components/com_'],
                'Laravel': [r'laravel_session', r'Laravel'],
                'Django': [r'django', r'csrfmiddlewaretoken'],
                'React': [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                'Angular': [r'angular', r'ng-version'],
                'Vue.js': [r'vue', r'Vue.js'],
                'jQuery': [r'jquery', r'jQuery'],
                'Bootstrap': [r'bootstrap', r'Bootstrap']
            }
            
            detected_tech = []
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        detected_tech.append(tech)
                        break
            
            self.results['technologies'][url] = {
                'detected': detected_tech,
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown')
            }
            
            self.print_status(f"Technologies detected: {detected_tech}", "SUCCESS")
            
        except Exception as e:
            self.print_status(f"Technology detection failed for {url}: {str(e)}", "ERROR")

    def directory_discovery(self, url):
        """
        Directory and File Discovery
        
        Discovers common directories and files that might contain
        sensitive information or admin panels
        
        No external APIs required
        """
        self.print_status(f"Discovering directories for {url}...")
        
        found_dirs = []
        
        def check_directory(directory):
            try:
                test_url = urljoin(url, directory)
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                
                # Consider various status codes as "interesting"
                if response.status_code in [200, 301, 302, 403]:
                    return {
                        'path': directory,
                        'status': response.status_code,
                        'size': len(response.content)
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_directory, dir_path) for dir_path in self.common_dirs]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_dirs.append(result)
        
        self.results['directories'].extend(found_dirs)
        if found_dirs:
            self.print_status(f"Found {len(found_dirs)} interesting directories", "SUCCESS")

    def ssl_analysis(self, hostname):
        """
        SSL/TLS Certificate Analysis
        
        Analyzes SSL certificates for:
        - Certificate details
        - Expiration dates
        - Weak ciphers
        - Certificate chain issues
        
        No external APIs required
        """
        self.print_status(f"Analyzing SSL certificate for {hostname}...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    self.results['ssl_info'][hostname] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'cipher_suite': cipher[0] if cipher else 'Unknown',
                        'tls_version': cipher[1] if cipher else 'Unknown'
                    }
                    
                    self.print_status(f"SSL certificate analyzed successfully", "SUCCESS")
                    
        except Exception as e:
            self.print_status(f"SSL analysis failed: {str(e)}", "ERROR")

    def vulnerability_assessment(self):
        """
        Basic Vulnerability Assessment
        
        Checks for common security issues:
        - Missing security headers
        - Weak SSL configuration
        - Information disclosure
        - Common vulnerabilities
        
        Generates manual testing suggestions
        """
        self.print_status("Performing vulnerability assessment...")
        
        vulnerabilities = []
        suggestions = []
        
        # Check security headers
        for url, headers in self.results['headers'].items():
            if not headers.get('X-Frame-Options'):
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'description': 'X-Frame-Options header is missing',
                    'url': url,
                    'severity': 'Medium',
                    'manual_test': 'Test for clickjacking by embedding the page in an iframe'
                })
            
            if not headers.get('Content-Security-Policy'):
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'description': 'Content-Security-Policy header is missing',
                    'url': url,
                    'severity': 'Medium',
                    'manual_test': 'Test for XSS vulnerabilities and inline script execution'
                })
            
            if headers.get('X-Powered-By'):
                vulnerabilities.append({
                    'type': 'Information Disclosure',
                    'description': f'X-Powered-By header reveals: {headers["X-Powered-By"]}',
                    'url': url,
                    'severity': 'Low',
                    'manual_test': 'Research known vulnerabilities for the disclosed technology'
                })
        
        # Generate manual testing suggestions based on findings
        for url, tech_info in self.results['technologies'].items():
            for tech in tech_info['detected']:
                if tech == 'WordPress':
                    suggestions.append({
                        'target': url,
                        'test_type': 'WordPress Security',
                        'manual_steps': [
                            'Check wp-admin login page for weak credentials',
                            'Enumerate users via /?author=1',
                            'Test for plugin vulnerabilities',
                            'Check wp-config.php backup files',
                            'Test XML-RPC endpoint for brute force'
                        ]
                    })
                elif tech == 'Laravel':
                    suggestions.append({
                        'target': url,
                        'test_type': 'Laravel Security',
                        'manual_steps': [
                            'Check for .env file exposure',
                            'Test debug mode information disclosure',
                            'Look for unprotected Artisan routes',
                            'Test for mass assignment vulnerabilities'
                        ]
                    })
        
        # Add directory-based suggestions
        for dir_info in self.results['directories']:
            if 'admin' in dir_info['path']:
                suggestions.append({
                    'target': dir_info['path'],
                    'test_type': 'Admin Panel Testing',
                    'manual_steps': [
                        'Test for default credentials',
                        'Check for brute force protection',
                        'Look for privilege escalation',
                        'Test session management'
                    ]
                })
        
        self.results['vulnerabilities'] = vulnerabilities
        self.results['manual_testing_suggestions'] = suggestions
        
        self.print_status(f"Found {len(vulnerabilities)} potential vulnerabilities", "SUCCESS")
        self.print_status(f"Generated {len(suggestions)} manual testing suggestions", "SUCCESS")

    def run_external_tool(self, command, description):
        """
        Run an external security tool and capture its output.
        Example: nmap, wpscan, etc.
        """
        self.print_status(f"Running {description}...", "INFO")
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            output = result.stdout
            self.print_status(f"{description} completed.", "SUCCESS")
            return output
        except Exception as e:
            self.print_status(f"{description} failed: {str(e)}", "ERROR")
            return None

    def kali_tools_scan(self, target):
        """
        Example integration with Kali Linux tools (Linux version, no Nikto).
        """
        # Nmap scan
        nmap_cmd = ["nmap", "-sV", "-O", target]
        nmap_output = self.run_external_tool(nmap_cmd, "Nmap Service & OS Scan")
        if nmap_output:
            self.results.setdefault('external_scans', {})['nmap'] = nmap_output

        # WPScan (WordPress vulnerability scan, if WordPress detected)
        if any('WordPress' in tech['detected'] for tech in self.results['technologies'].values()):
            wpscan_cmd = ["wpscan", "--url", f"https://{target}"]
            wpscan_output = self.run_external_tool(wpscan_cmd, "WPScan WordPress Scan")
            if wpscan_output:
                self.results['external_scans']['wpscan'] = wpscan_output

    def owasp_top_20_checks(self):
        """
        Basic automated checks and manual suggestions for OWASP Top 20 web vulnerabilities.
        """
        self.print_status("Performing OWASP Top 20 checks...", "INFO")
        owasp_findings = []
        owasp_suggestions = []

        # 1. Injection (SQL, Command, etc.)
        for dir_info in self.results['directories']:
            if 'login' in dir_info['path'] or 'admin' in dir_info['path']:
                owasp_suggestions.append({
                    'target': dir_info['path'],
                    'test_type': 'Injection',
                    'manual_steps': [
                        'Test login forms for SQL injection using payloads like \' OR 1=1--',
                        'Check for command injection in upload or admin panels'
                    ]
                })

        # 2. Broken Authentication
        for dir_info in self.results['directories']:
            if 'login' in dir_info['path'] or 'admin' in dir_info['path']:
                owasp_suggestions.append({
                    'target': dir_info['path'],
                    'test_type': 'Broken Authentication',
                    'manual_steps': [
                        'Test for weak/default credentials',
                        'Check for missing account lockout after failed attempts'
                    ]
                })

        # 3. Sensitive Data Exposure
        for url, headers in self.results['headers'].items():
            if not headers.get('Strict-Transport-Security'):
                owasp_findings.append({
                    'type': 'Sensitive Data Exposure',
                    'description': 'Missing Strict-Transport-Security header',
                    'url': url,
                    'severity': 'Medium'
                })

        # 4. XML External Entities (XXE)
        for tech_info in self.results['technologies'].values():
            if 'XML' in tech_info['detected']:
                owasp_suggestions.append({
                    'target': 'XML endpoint',
                    'test_type': 'XXE',
                    'manual_steps': [
                        'Test XML parsers for external entity injection'
                    ]
                })

        # 5. Broken Access Control
        for dir_info in self.results['directories']:
            if dir_info['status'] == 403:
                owasp_suggestions.append({
                    'target': dir_info['path'],
                    'test_type': 'Broken Access Control',
                    'manual_steps': [
                        'Test for privilege escalation by bypassing 403 restrictions'
                    ]
                })

        # 6. Security Misconfiguration
        for url, headers in self.results['headers'].items():
            if headers.get('X-Powered-By'):
                owasp_findings.append({
                    'type': 'Security Misconfiguration',
                    'description': f'X-Powered-By header reveals: {headers["X-Powered-By"]}',
                    'url': url,
                    'severity': 'Low'
                })

        # 7. Cross-Site Scripting (XSS)
        for url, headers in self.results['headers'].items():
            if not headers.get('Content-Security-Policy'):
                owasp_suggestions.append({
                    'target': url,
                    'test_type': 'Cross-Site Scripting (XSS)',
                    'manual_steps': [
                        'Test input fields for reflected and stored XSS',
                        'Check for missing CSP header'
                    ]
                })

        # 8. Insecure Deserialization
        for tech_info in self.results['technologies'].values():
            if 'PHP' in tech_info['detected'] or 'Java' in tech_info['detected']:
                owasp_suggestions.append({
                    'target': 'Application',
                    'test_type': 'Insecure Deserialization',
                    'manual_steps': [
                        'Test for insecure object deserialization in API endpoints'
                    ]
                })

        # 9. Using Components with Known Vulnerabilities
        for url, tech_info in self.results['technologies'].items():
            for tech in tech_info['detected']:
                owasp_suggestions.append({
                    'target': url,
                    'test_type': 'Known Vulnerabilities',
                    'manual_steps': [
                        f'Research CVEs for {tech} and its plugins/modules'
                    ]
                })

        # 10. Insufficient Logging & Monitoring
        owasp_suggestions.append({
            'target': 'Application',
            'test_type': 'Logging & Monitoring',
            'manual_steps': [
                'Check for logging of authentication and access control events',
                'Test for alerting on suspicious activities'
            ]
        })

        # Add more checks for remaining OWASP Top 20 as needed...

        # Store results
        self.results.setdefault('owasp_findings', []).extend(owasp_findings)
        self.results.setdefault('owasp_suggestions', []).extend(owasp_suggestions)
        self.print_status(f"OWASP Top 20 checks completed: {len(owasp_findings)} findings, {len(owasp_suggestions)} suggestions", "SUCCESS")

    def owasp_top_20_tool_checks(self):
        """
        Run applicable Kali Linux tools for OWASP Top 20 categories.
        """
        self.print_status("Running OWASP Top 20 tool-based checks...", "INFO")
        owasp_tool_results = {}

        # 1. Injection (SQL)
        for dir_info in self.results['directories']:
            if 'login' in dir_info['path'] or 'admin' in dir_info['path']:
                # Try sqlmap on login/admin pages
                url = f"https://{self.target}/{dir_info['path']}"
                sqlmap_cmd = ["sqlmap", "-u", url, "--batch", "--crawl=1"]
                owasp_tool_results['Injection'] = self.run_external_tool(sqlmap_cmd, "SQL Injection Test (sqlmap)")

        # 2. Broken Authentication
        for dir_info in self.results['directories']:
            if 'login' in dir_info['path']:
                # Try hydra for brute force (example with common user)
                hydra_cmd = ["hydra", "-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", self.target, "http-post-form", f"/{dir_info['path']}:username=^USER^&password=^PASS^:F=incorrect"]
                owasp_tool_results['Broken Authentication'] = self.run_external_tool(hydra_cmd, "Brute Force Test (hydra)")

        # 3. Sensitive Data Exposure
        sslscan_cmd = ["sslscan", self.target]
        owasp_tool_results['Sensitive Data Exposure'] = self.run_external_tool(sslscan_cmd, "SSL Scan (sslscan)")

        # 6. Security Misconfiguration
        nmap_cmd = ["nmap", "-sV", "-O", self.target]
        owasp_tool_results['Security Misconfiguration'] = self.run_external_tool(nmap_cmd, "Service & OS Scan (nmap)")

        # 7. Cross-Site Scripting (XSS)
        for dir_info in self.results['directories']:
            url = f"https://{self.target}/{dir_info['path']}"
            xsser_cmd = ["xsser", "--url", url]
            owasp_tool_results['XSS'] = self.run_external_tool(xsser_cmd, "XSS Test (xsser)")

        # 9. Known Vulnerabilities (WordPress)
        if any('WordPress' in tech['detected'] for tech in self.results['technologies'].values()):
            wpscan_cmd = ["wpscan", "--url", f"https://{self.target}"]
            owasp_tool_results['Known Vulnerabilities'] = self.run_external_tool(wpscan_cmd, "WordPress Scan (wpscan)")

        # ...add more tool mappings for other OWASP categories as needed...

        # Store results
        self.results['owasp_tool_results'] = owasp_tool_results
        self.print_status("OWASP Top 20 tool-based checks completed.", "SUCCESS")

    def generate_report(self):
        """Generate comprehensive report"""
        self.print_status("Generating comprehensive report...")
        
        report = f"""
{Colors.BOLD}Bug Bounty Reconnaissance Report{Colors.END}
Target: {self.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{Colors.BOLD}SUMMARY{Colors.END}
- Subdomains found: {len(self.results['subdomains'])}
- Technologies detected: {sum(len(tech['detected']) for tech in self.results['technologies'].values())}
- Potential vulnerabilities: {len(self.results['vulnerabilities'])}
- Manual testing suggestions: {len(self.results['manual_testing_suggestions'])}
- OWASP findings: {len(self.results.get('owasp_findings', []))}
- OWASP suggestions: {len(self.results.get('owasp_suggestions', []))}

{Colors.BOLD}SUBDOMAINS{Colors.END}
"""
        for subdomain in self.results['subdomains']:
            report += f"  • {subdomain}\n"
        
        report += f"\n{Colors.BOLD}OPEN PORTS{Colors.END}\n"
        for host, ports in self.results['ports'].items():
            if ports:
                report += f"  • {host}: {', '.join(map(str, ports))}\n"
        
        report += f"\n{Colors.BOLD}TECHNOLOGIES DETECTED{Colors.END}\n"
        for url, tech_info in self.results['technologies'].items():
            if tech_info['detected']:
                report += f"  • {url}: {', '.join(tech_info['detected'])}\n"
        
        report += f"\n{Colors.BOLD}SECURITY HEADERS ANALYSIS{Colors.END}\n"
        for url, headers in self.results['headers'].items():
            report += f"  • {url}:\n"
            for header, value in headers.items():
                status = "✓" if value else "✗"
                report += f"    {status} {header}: {value or 'Missing'}\n"
        
        report += f"\n{Colors.BOLD}POTENTIAL VULNERABILITIES{Colors.END}\n"
        for vuln in self.results['vulnerabilities']:
            report += f"  • [{vuln['severity']}] {vuln['type']}: {vuln['description']}\n"
            report += f"    Manual Test: {vuln['manual_test']}\n\n"
        
        report += f"\n{Colors.BOLD}MANUAL TESTING SUGGESTIONS{Colors.END}\n"
        for suggestion in self.results['manual_testing_suggestions']:
            report += f"  • {suggestion['test_type']} ({suggestion['target']}):\n"
            for step in suggestion['manual_steps']:
                report += f"    - {step}\n"
            report += "\n"

        report += f"\n{Colors.BOLD}OWASP TOP 20 FINDINGS{Colors.END}\n"
        for finding in self.results.get('owasp_findings', []):
            report += f"  • [{finding['severity']}] {finding['type']}: {finding['description']} ({finding.get('url', '')})\n"
        report += f"\n{Colors.BOLD}OWASP TOP 20 SUGGESTIONS{Colors.END}\n"
        for suggestion in self.results.get('owasp_suggestions', []):
            report += f"  • {suggestion['test_type']} ({suggestion['target']}):\n"
            for step in suggestion['manual_steps']:
                report += f"    - {step}\n"
            report += "\n"

        print(report)
        
        # Save to file
        filename = f"recon_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.print_status(f"Report saved to {filename}", "SUCCESS")

    def run_full_recon(self):
        """Run complete reconnaissance process"""
        self.banner()
        
        # Step 1: Subdomain discovery
        self.subdomain_discovery()
        
        # Step 2: Port scanning (limit to first few subdomains for demo)
        targets_to_scan = [self.target] + self.results['subdomains'][:3]
        for target in targets_to_scan:
            try:
                ip = socket.gethostbyname(target.replace('https://', '').replace('http://', ''))
                self.port_scanning(ip)
            except:
                continue
        
        # Step 3: Technology detection
        urls_to_test = [f"https://{self.target}"]
        if self.results['subdomains']:
            urls_to_test.extend([f"https://{sub}" for sub in self.results['subdomains'][:2]])
        
        for url in urls_to_test:
            self.technology_detection(url)
            self.directory_discovery(url)
        
        # Step 4: SSL analysis
        self.ssl_analysis(self.target)
        
        # Step 5: Vulnerability assessment
        self.vulnerability_assessment()

        # Step 6: OWASP Top 20 checks
        self.owasp_top_20_checks()
        
        # Step 7: Generate report
        self.generate_report()

        # Step 8: Optional - Run Kali Linux tools
        self.kali_tools_scan(self.target)

def main():
    parser = argparse.ArgumentParser(description='Bug Bounty Reconnaissance Tool')
    parser.add_argument('target', help='Target domain (e.g., example.com)')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--threads', '-t', type=int, default=50, help='Number of threads to use')
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target:
        print("Please provide a target domain")
        sys.exit(1)
    
    # Legal disclaimer
    print(f"""
{Colors.RED}{Colors.BOLD}LEGAL DISCLAIMER{Colors.END}
This tool is for authorized security testing only.
Only use this tool on:
- Domains you own
- Systems with explicit written permission to test
- Official bug bounty programs where testing is authorized

Unauthorized testing is illegal and unethical.
By using this tool, you agree to use it responsibly and legally.

Press Enter to continue or Ctrl+C to exit...
""")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    
    # Run reconnaissance
    recon = ReconTool(args.target)
    recon.run_full_recon()

if __name__ == "__main__":
    main()
