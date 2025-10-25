#!/usr/bin/env python3

import socket
import sys
import argparse
import threading
from queue import Queue
from datetime import datetime
import json
from urllib.parse import urlparse
import ssl
import re

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class PortScanner:
    def __init__(self, host, port_range=(1, 1024), threads=100, timeout=1):
        self.host = host
        self.port_range = port_range
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.port_lock = threading.Lock()
        self.target_ip = None
        
    def resolve_host(self):
        try:
            self.target_ip = socket.gethostbyname(self.host)
            return True
        except socket.gaierror:
            print(f"{Colors.FAIL}[ERROR] Cannot resolve hostname: {self.host}{Colors.ENDC}")
            return False
    
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:
                service = self.get_service_name(port)
                banner = self.grab_banner(port)
                
                with self.port_lock:
                    self.open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner
                    })
                    print(f"{Colors.OKGREEN}[+] Port {port}: OPEN - {service}{Colors.ENDC}")
                    if banner:
                        print(f"    {Colors.OKCYAN}Banner: {banner[:100]}{Colors.ENDC}")
            
            sock.close()
        except Exception as e:
            pass
    
    def get_service_name(self, port):
        common_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        return common_ports.get(port, 'Unknown')
    
    def grab_banner(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target_ip, port))
            
            if port in [80, 8080, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return None
    
    def worker(self, queue):
        while True:
            port = queue.get()
            if port is None:
                break
            self.scan_port(port)
            queue.task_done()
    
    def scan(self):
        if not self.resolve_host():
            return False
        
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}Port Scanner Started{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"Target: {self.host} ({self.target_ip})")
        print(f"Port Range: {self.port_range[0]}-{self.port_range[1]}")
        print(f"Threads: {self.threads}")
        print(f"Started: {datetime.now()}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        queue = Queue()
        threads = []
        
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, args=(queue,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        for port in range(self.port_range[0], self.port_range[1] + 1):
            queue.put(port)
        
        queue.join()
        
        for _ in range(self.threads):
            queue.put(None)
        for t in threads:
            t.join()
        
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"Scan Complete: {datetime.now()}")
        print(f"Open Ports Found: {len(self.open_ports)}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        return True

class VulnerabilityScanner:
    def __init__(self, host, open_ports):
        self.host = host
        self.open_ports = open_ports
        self.vulnerabilities = []
        self.target_ip = socket.gethostbyname(host)
    
    def scan_all(self):
        print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}OWASP Top 10 Vulnerability Scan{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")
        
        self.check_broken_access_control()
        self.check_cryptographic_failures()
        self.check_injection_vulnerabilities()
        self.check_insecure_design()
        self.check_security_misconfiguration()
        self.check_vulnerable_components()
        self.check_authentication_failures()
        self.check_integrity_failures()
        self.check_logging_monitoring()
        self.check_ssrf()
        
        return self.vulnerabilities
    
    def add_vulnerability(self, category, severity, description, port=None):
        vuln = {
            'category': category,
            'severity': severity,
            'description': description,
            'port': port,
            'timestamp': str(datetime.now())
        }
        self.vulnerabilities.append(vuln)
        
        color = Colors.FAIL if severity == 'HIGH' else Colors.WARNING if severity == 'MEDIUM' else Colors.OKBLUE
        print(f"{color}[{severity}] {category}: {description}{Colors.ENDC}")
        if port:
            print(f"       Port: {port}")
    
    def check_broken_access_control(self):
        print(f"{Colors.BOLD}[A01:2021] Checking Broken Access Control...{Colors.ENDC}")
        
        for port_info in self.open_ports:
            port = port_info['port']
            
            if port in [21, 23, 3389, 5900]:
                self.add_vulnerability(
                    "A01:2021 - Broken Access Control",
                    "MEDIUM",
                    f"Potentially insecure remote access service detected: {port_info['service']}",
                    port
                )
            
            if port == 6379:
                self.add_vulnerability(
                    "A01:2021 - Broken Access Control",
                    "HIGH",
                    "Redis port exposed - often configured without authentication by default",
                    port
                )
            
            if port == 27017:
                self.add_vulnerability(
                    "A01:2021 - Broken Access Control",
                    "HIGH",
                    "MongoDB port exposed - check if authentication is enabled",
                    port
                )
    
    def check_cryptographic_failures(self):
        print(f"{Colors.BOLD}[A02:2021] Checking Cryptographic Failures...{Colors.ENDC}")
        
        http_ports = [p for p in self.open_ports if p['port'] in [80, 8080, 8000]]
        https_ports = [p for p in self.open_ports if p['port'] in [443, 8443]]
        
        if http_ports and not https_ports:
            for port_info in http_ports:
                self.add_vulnerability(
                    "A02:2021 - Cryptographic Failures",
                    "HIGH",
                    "HTTP service detected without HTTPS - data transmitted in cleartext",
                    port_info['port']
                )
        
        for port_info in self.open_ports:
            if port_info['port'] == 443:
                if not self.check_ssl_security(port_info['port']):
                    self.add_vulnerability(
                        "A02:2021 - Cryptographic Failures",
                        "MEDIUM",
                        "HTTPS service may have weak SSL/TLS configuration",
                        port_info['port']
                    )
            
            if port_info['port'] in [21, 23, 110, 143]:
                self.add_vulnerability(
                    "A02:2021 - Cryptographic Failures",
                    "MEDIUM",
                    f"Unencrypted protocol detected: {port_info['service']}",
                    port_info['port']
                )
    
    def check_ssl_security(self, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target_ip, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    return True
        except ssl.SSLError:
            return False
        except:
            return True
    
    def check_injection_vulnerabilities(self):
        print(f"{Colors.BOLD}[A03:2021] Checking Injection Vulnerabilities...{Colors.ENDC}")
        
        db_ports = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            27017: 'MongoDB',
            6379: 'Redis'
        }
        
        for port_info in self.open_ports:
            if port_info['port'] in db_ports:
                self.add_vulnerability(
                    "A03:2021 - Injection",
                    "HIGH",
                    f"{db_ports[port_info['port']]} database exposed - potential SQL/NoSQL injection target",
                    port_info['port']
                )
        
        web_ports = [p for p in self.open_ports if p['port'] in [80, 443, 8080, 8443]]
        if web_ports:
            self.add_vulnerability(
                "A03:2021 - Injection",
                "MEDIUM",
                "Web service detected - verify input validation and parameterized queries are used",
                web_ports[0]['port']
            )
    
    def check_insecure_design(self):
        print(f"{Colors.BOLD}[A04:2021] Checking Insecure Design...{Colors.ENDC}")
        
        if len(self.open_ports) > 10:
            self.add_vulnerability(
                "A04:2021 - Insecure Design",
                "MEDIUM",
                f"Large attack surface detected - {len(self.open_ports)} open ports found. Consider reducing exposed services."
            )
    
    def check_security_misconfiguration(self):
        print(f"{Colors.BOLD}[A05:2021] Checking Security Misconfiguration...{Colors.ENDC}")
        
        for port_info in self.open_ports:
            banner = port_info.get('banner', '')
            if banner:
                version_pattern = r'\d+\.\d+(\.\d+)?'
                if re.search(version_pattern, banner):
                    self.add_vulnerability(
                        "A05:2021 - Security Misconfiguration",
                        "LOW",
                        "Server version information exposed in banner - consider hiding version details",
                        port_info['port']
                    )
            
            if port_info['service'] == 'FTP' and port_info['port'] == 21:
                if banner and 'anonymous' in banner.lower():
                    self.add_vulnerability(
                        "A05:2021 - Security Misconfiguration",
                        "HIGH",
                        "Anonymous FTP access may be enabled",
                        port_info['port']
                    )
            
            if port_info['port'] in [8080, 8888, 9000]:
                self.add_vulnerability(
                    "A05:2021 - Security Misconfiguration",
                    "MEDIUM",
                    f"Development/admin port exposed: {port_info['port']}",
                    port_info['port']
                )
    
    def check_vulnerable_components(self):
        print(f"{Colors.BOLD}[A06:2021] Checking Vulnerable and Outdated Components...{Colors.ENDC}")
        
        for port_info in self.open_ports:
            banner = port_info.get('banner', '')
            if banner:
                old_versions = [
                    ('Apache/2.2', 'Apache 2.2 is end-of-life'),
                    ('Apache/2.4.1', 'Outdated Apache version'),
                    ('nginx/1.0', 'Outdated nginx version'),
                    ('PHP/5.', 'PHP 5.x is end-of-life'),
                    ('OpenSSH/6.', 'Outdated OpenSSH version'),
                ]
                
                for pattern, message in old_versions:
                    if pattern in banner:
                        self.add_vulnerability(
                            "A06:2021 - Vulnerable and Outdated Components",
                            "HIGH",
                            message,
                            port_info['port']
                        )
    
    def check_authentication_failures(self):
        print(f"{Colors.BOLD}[A07:2021] Checking Authentication Failures...{Colors.ENDC}")
        
        for port_info in self.open_ports:
            if port_info['port'] in [22, 3389, 5900]:
                self.add_vulnerability(
                    "A07:2021 - Identification and Authentication Failures",
                    "MEDIUM",
                    f"Remote access service exposed - ensure strong password policies and MFA: {port_info['service']}",
                    port_info['port']
                )
    
    def check_integrity_failures(self):
        print(f"{Colors.BOLD}[A08:2021] Checking Software and Data Integrity Failures...{Colors.ENDC}")
        
        web_ports = [p for p in self.open_ports if p['port'] in [80, 443, 8080, 8443]]
        if web_ports:
            self.add_vulnerability(
                "A08:2021 - Software and Data Integrity Failures",
                "LOW",
                "Web application detected - verify integrity of assets, updates, and dependencies",
                web_ports[0]['port']
            )
    
    def check_logging_monitoring(self):
        print(f"{Colors.BOLD}[A09:2021] Checking Security Logging and Monitoring...{Colors.ENDC}")
        
        if self.open_ports:
            self.add_vulnerability(
                "A09:2021 - Security Logging and Monitoring Failures",
                "LOW",
                "Verify logging and monitoring are configured for all exposed services"
            )
    
    def check_ssrf(self):
        print(f"{Colors.BOLD}[A10:2021] Checking Server-Side Request Forgery (SSRF)...{Colors.ENDC}")
        
        web_ports = [p for p in self.open_ports if p['port'] in [80, 443, 8080, 8443]]
        if web_ports:
            self.add_vulnerability(
                "A10:2021 - Server-Side Request Forgery",
                "MEDIUM",
                "Web application detected - ensure URL validation for user-supplied URLs",
                web_ports[0]['port']
            )

def generate_report(host, scan_results, vulnerabilities, output_file='report.html'):
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {host}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .info {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .vulnerability {{ padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid; }}
        .high {{ background: #ffe6e6; border-color: #e74c3c; }}
        .medium {{ background: #fff3cd; border-color: #f39c12; }}
        .low {{ background: #d1ecf1; border-color: #3498db; }}
        .severity {{ font-weight: bold; padding: 3px 8px; border-radius: 3px; color: white; }}
        .sev-high {{ background: #e74c3c; }}
        .sev-medium {{ background: #f39c12; }}
        .sev-low {{ background: #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Scan Report</h1>
        <div class="info">
            <strong>Target:</strong> {host}<br>
            <strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Open Ports:</strong> {len(scan_results)}<br>
            <strong>Vulnerabilities Found:</strong> {len(vulnerabilities)}
        </div>
        
        <h2>Open Ports</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Banner</th>
            </tr>
"""
    
    for port_info in scan_results:
        banner = port_info.get('banner', 'N/A')
        if banner:
            banner = banner[:100] + '...' if len(banner) > 100 else banner
        else:
            banner = 'N/A'
        html_content += f"""
            <tr>
                <td>{port_info['port']}</td>
                <td>{port_info['service']}</td>
                <td>{banner}</td>
            </tr>
"""
    
    html_content += """
        </table>
        
        <h2>OWASP Top 10 Vulnerability Assessment</h2>
"""
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            severity_class = vuln['severity'].lower()
            html_content += f"""
        <div class="vulnerability {severity_class}">
            <span class="severity sev-{severity_class}">{vuln['severity']}</span>
            <strong>{vuln['category']}</strong><br>
            {vuln['description']}
            {f"<br><strong>Port:</strong> {vuln['port']}" if vuln['port'] else ""}
        </div>
"""
    else:
        html_content += "<p>No vulnerabilities detected.</p>"
    
    html_content += f"""
        <div class="footer">
            <p><strong>Disclaimer:</strong> This is an automated security scan. Results should be verified manually. 
            This tool should only be used on systems you own or have explicit permission to test.</p>
            <p>Based on OWASP Top 10 2021</p>
        </div>
    </div>
</body>
</html>
"""
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"\n{Colors.OKGREEN}[+] Report saved to: {output_file}{Colors.ENDC}")

def print_banner():
    banner = f"""{Colors.HEADER}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║           OWASP Top 10 Port Scanner & Analyzer           ║
    ║                                                           ║
    ║               Educational Security Tool v1.0              ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    {Colors.ENDC}"""
    print(banner)

def print_legal_warning():
    warning = f"""{Colors.WARNING}
    ⚠️  LEGAL WARNING AND DISCLAIMER ⚠️
    
    This tool is provided for educational and authorized security testing 
    purposes ONLY. Unauthorized port scanning and vulnerability testing 
    may be ILLEGAL in your jurisdiction.
    
    YOU MUST HAVE EXPLICIT WRITTEN PERMISSION to scan any system you 
    do not own. Unauthorized scanning may violate:
    
    • Computer Fraud and Abuse Act (CFAA) in the US
    • Computer Misuse Act in the UK
    • Similar legislation in other countries
    
    By using this tool, you agree that you:
    1. Have authorization to scan the target system
    2. Will not use this tool for malicious purposes
    3. Assume all responsibility for your actions
    
    The authors assume NO LIABILITY for misuse of this tool.
    
    Safe testing targets:
    • localhost / 127.0.0.1 (your own machine)
    • scanme.nmap.org (authorized test server)
    • Your own infrastructure with proper authorization
     Made By AgamSandhu and team with love and a little bit of arrogance. Because we know it works.
    {Colors.ENDC}"""
    print(warning)

def main():
    print_banner()
    print_legal_warning()
    
    parser = argparse.ArgumentParser(
        description='OWASP Top 10 Port Scanner and Vulnerability Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py localhost
  python scanner.py 192.168.1.1 -p 1-65535
  python scanner.py scanme.nmap.org -p 1-1000 -t 200
  python scanner.py example.com -p 80,443,8080 --report scan_report.html
        """
    )
    
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', default='1-1024',
                       help='Port range (e.g., 1-1024) or specific ports (e.g., 80,443,8080)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds (default: 1.0)')
    parser.add_argument('--report', type=str, default='security_report.html',
                       help='HTML report filename (default: security_report.html)')
    parser.add_argument('--skip-vuln-scan', action='store_true',
                       help='Skip vulnerability scanning (port scan only)')
    parser.add_argument('-y', '--yes', action='store_true',
                       help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    if not args.yes:
        print(f"\n{Colors.BOLD}You are about to scan: {args.host}{Colors.ENDC}")
        confirmation = input(f"{Colors.WARNING}Do you have authorization to scan this target? (yes/no): {Colors.ENDC}")
        if confirmation.lower() not in ['yes', 'y']:
            print(f"{Colors.FAIL}Scan cancelled.{Colors.ENDC}")
            sys.exit(0)
    
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        port_range = (start, end)
    else:
        ports = [int(p.strip()) for p in args.ports.split(',')]
        port_range = (min(ports), max(ports))
    
    try:
        scanner = PortScanner(args.host, port_range, args.threads, args.timeout)
        
        if not scanner.scan():
            sys.exit(1)
        
        if not scanner.open_ports:
            print(f"{Colors.WARNING}No open ports found.{Colors.ENDC}")
            sys.exit(0)
        
        vulnerabilities = []
        if not args.skip_vuln_scan:
            vuln_scanner = VulnerabilityScanner(args.host, scanner.open_ports)
            vulnerabilities = vuln_scanner.scan_all()
        
        generate_report(args.host, scanner.open_ports, vulnerabilities, args.report)
        
        print(f"\n{Colors.OKGREEN}{'='*60}")
        print(f"Summary:")
        print(f"  Open Ports: {len(scanner.open_ports)}")
        print(f"  Vulnerabilities: {len(vulnerabilities)}")
        print(f"  Report: {args.report}")
        print(f"{'='*60}{Colors.ENDC}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[ERROR] {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
