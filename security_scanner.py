import hashlib
import os
import socket
import subprocess
import requests
import json
import dns.resolver
from datetime import datetime
import magic

class SecurityScanner:
    def __init__(self):
        self.virus_total_api_key = os.getenv('VIRUSTOTAL_API_KEY', 'demo-key')
        self.shodan_api_key = os.getenv('SHODAN_API_KEY', 'demo-key')
        
    def scan_file(self, file_path):
        """Comprehensive file security scan"""
        result = {
            'file_path': file_path,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'result': 'clean',
            'threat_level': 0,
            'details': {}
        }
        
        try:
            # Get file info
            file_size = os.path.getsize(file_path)
            
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()
            
            # Detect file type
            file_type = magic.from_file(file_path) if hasattr(magic, 'from_file') else 'unknown'
            
            result['details'].update({
                'file_size': file_size,
                'file_hash': file_hash,
                'file_type': file_type
            })
            
            # Check file extension
            _, ext = os.path.splitext(file_path)
            suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js']
            
            if ext.lower() in suspicious_extensions:
                result['threat_level'] += 3
                result['details']['suspicious_extension'] = True
            
            # Check file size (very small or very large files can be suspicious)
            if file_size < 1024:  # Less than 1KB
                result['threat_level'] += 2
                result['details']['suspicious_size'] = 'too_small'
            elif file_size > 100 * 1024 * 1024:  # Larger than 100MB
                result['threat_level'] += 1
                result['details']['suspicious_size'] = 'too_large'
            
            # Simple pattern matching for suspicious content
            suspicious_patterns = [
                b'keylogger', b'rootkit', b'backdoor', b'trojan',
                b'malware', b'virus', b'encrypt', b'ransom'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in file_content:
                    result['threat_level'] += 5
                    result['details']['suspicious_patterns'] = result['details'].get('suspicious_patterns', [])
                    result['details']['suspicious_patterns'].append(pattern.decode('utf-8', errors='ignore'))
            
            # Determine final result
            if result['threat_level'] >= 8:
                result['result'] = 'malicious'
            elif result['threat_level'] >= 4:
                result['result'] = 'suspicious'
            else:
                result['result'] = 'clean'
            
        except Exception as e:
            result['error'] = str(e)
            result['result'] = 'error'
        
        return result
    
    def enumerate_subdomains(self, domain):
        """Enumerate subdomains for a given domain"""
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'secure', 'vpn', 'remote', 'portal', 'app'
        ]
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                subdomains.append(full_domain)
            except socket.gaierror:
                continue
        
        return {
            'domain': domain,
            'subdomains': subdomains,
            'count': len(subdomains),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def port_scan(self, target, ports=None):
        """Perform port scan on target"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        open_ports = []
        closed_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                
                sock.close()
            except Exception:
                closed_ports.append(port)
        
        return {
            'target': target,
            'open_ports': open_ports,
            'closed_ports': closed_ports,
            'total_scanned': len(ports),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def dns_lookup(self, domain):
        """Perform DNS lookup"""
        result = {
            'domain': domain,
            'records': {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result['records'][record_type] = [str(answer) for answer in answers]
            except Exception:
                result['records'][record_type] = []
        
        return result
    
    def virus_total_check(self, file_hash):
        """Check file hash against VirusTotal API"""
        if self.virus_total_api_key == 'demo-key':
            return {
                'hash': file_hash,
                'status': 'demo_mode',
                'message': 'VirusTotal API key not configured',
                'demo_result': 'clean'
            }
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.virus_total_api_key,
                'resource': file_hash
            }
            
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
            
            return {
                'hash': file_hash,
                'status': 'success',
                'data': data,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            return {
                'hash': file_hash,
                'status': 'error',
                'error': str(e)
            }
    
    def whois_lookup(self, domain):
        """Perform WHOIS lookup"""
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=10)
            return {
                'domain': domain,
                'status': 'success',
                'data': result.stdout,
                'timestamp': datetime.utcnow().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {
                'domain': domain,
                'status': 'timeout',
                'error': 'WHOIS lookup timed out'
            }
        except FileNotFoundError:
            return {
                'domain': domain,
                'status': 'error',
                'error': 'WHOIS command not found'
            }
        except Exception as e:
            return {
                'domain': domain,
                'status': 'error',
                'error': str(e)
            }
    
    def analyze_url_security(self, url):
        """Analyze URL for security threats"""
        security_score = 100
        risk_factors = []
        
        # Check for HTTPS
        if not url.startswith('https://'):
            security_score -= 20
            risk_factors.append('No HTTPS encryption')
        
        # Check for suspicious URL patterns
        suspicious_patterns = [
            'bit.ly', 'tinyurl', 'shortened', 'phishing',
            'malware', 'virus', 'trojan', 'download'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in url.lower():
                security_score -= 15
                risk_factors.append(f'Suspicious pattern: {pattern}')
        
        # Check domain reputation (simplified)
        try:
            domain = url.split('/')[2]
            if len(domain.split('.')) > 3:  # Subdomain depth
                security_score -= 10
                risk_factors.append('Deep subdomain structure')
        except IndexError:
            security_score -= 30
            risk_factors.append('Invalid URL format')
        
        return {
            'url': url,
            'security_score': max(security_score, 0),
            'risk_factors': risk_factors,
            'timestamp': datetime.utcnow().isoformat()
        }
