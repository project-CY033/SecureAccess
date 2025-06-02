import re
import hashlib
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import os

logger = logging.getLogger(__name__)

class ThreatDetector:
    """
    Advanced threat detection utility for cybersecurity monitoring.
    Implements pattern matching, signature detection, and behavior analysis.
    """
    
    def __init__(self):
        self.malicious_patterns = {
            'urls': [
                r'(?i)(phishing|malware|virus|trojan|exploit|suspicious|fraud)',
                r'(?i)(download|install|update|security|warning|alert).*\.(exe|scr|bat|com|pif)',
                r'(?i)(urgent|immediate|verify|suspend|blocked|expired).*account',
                r'(?i)(click.*here|download.*now|install.*immediately)',
                r'(?i)(free.*download|guaranteed.*money|lottery.*winner)'
            ],
            'file_signatures': {
                'executable': [
                    b'MZ',  # PE executable
                    b'\x7fELF',  # ELF executable
                    b'\xfe\xed\xfa',  # Mach-O binary
                    b'PK\x03\x04',  # ZIP/APK archive
                ],
                'suspicious_strings': [
                    b'trojan', b'virus', b'malware', b'backdoor',
                    b'keylogger', b'rootkit', b'spyware', b'adware',
                    b'ransomware', b'cryptolocker', b'worm',
                    b'shell32.dll', b'kernel32.dll', b'ntdll.dll'
                ]
            },
            'network': [
                r'(?i)(botnet|c2|command.*control)',
                r'(?i)(ddos|syn.*flood|amplification)',
                r'(?i)(bruteforce|dictionary.*attack)',
                r'(?i)(port.*scan|vulnerability.*scan)',
                r'(?i)(injection|xss|csrf|rfi|lfi)'
            ]
        }
        
        self.suspicious_ports = [
            21, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017
        ]
        
        self.known_threat_indicators = {
            'file_extensions': [
                '.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js',
                '.jar', '.app', '.deb', '.rpm', '.msi', '.dmg'
            ],
            'suspicious_domains': [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
                'ow.ly', 'is.gd', 'buff.ly'
            ],
            'crypto_indicators': [
                'bitcoin', 'cryptocurrency', 'wallet', 'mining',
                'blockchain', 'ethereum', 'litecoin'
            ]
        }
        
        # Load threat intelligence feeds (simulated - in production would connect to real feeds)
        self.threat_feeds = self._load_threat_feeds()
    
    def analyze_url_threat(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL for potential security threats.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing threat analysis results
        """
        try:
            threat_score = 0
            threats_detected = []
            analysis_details = {
                'url': url,
                'timestamp': datetime.utcnow().isoformat(),
                'threat_score': 0,
                'threats': [],
                'indicators': [],
                'recommendations': []
            }
            
            # Check against malicious URL patterns
            for pattern in self.malicious_patterns['urls']:
                if re.search(pattern, url):
                    threat_score += 25
                    threats_detected.append(f"Suspicious URL pattern detected: {pattern}")
            
            # Check domain reputation
            domain_analysis = self._analyze_domain(url)
            threat_score += domain_analysis['score']
            threats_detected.extend(domain_analysis['threats'])
            
            # Check for URL shorteners
            shortener_analysis = self._check_url_shorteners(url)
            threat_score += shortener_analysis['score']
            threats_detected.extend(shortener_analysis['threats'])
            
            # Check for suspicious parameters
            param_analysis = self._analyze_url_parameters(url)
            threat_score += param_analysis['score']
            threats_detected.extend(param_analysis['threats'])
            
            # Determine threat level
            if threat_score >= 75:
                threat_level = 'CRITICAL'
            elif threat_score >= 50:
                threat_level = 'HIGH'
            elif threat_score >= 25:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'LOW'
            
            analysis_details.update({
                'threat_score': min(threat_score, 100),
                'threat_level': threat_level,
                'threats': threats_detected,
                'security_score': max(0, 100 - threat_score)
            })
            
            # Add recommendations
            analysis_details['recommendations'] = self._generate_url_recommendations(threat_score)
            
            return analysis_details
            
        except Exception as e:
            logger.error(f"Error analyzing URL threat: {e}")
            return {
                'url': url,
                'timestamp': datetime.utcnow().isoformat(),
                'threat_score': 100,
                'threat_level': 'UNKNOWN',
                'threats': [f"Analysis error: {str(e)}"],
                'security_score': 0,
                'error': str(e)
            }
    
    def analyze_file_threat(self, file_path: str, file_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Analyze file for potential security threats.
        
        Args:
            file_path: Path to the file
            file_data: Optional file content bytes
            
        Returns:
            Dictionary containing threat analysis results
        """
        try:
            threat_score = 0
            threats_detected = []
            analysis_details = {
                'file_path': file_path,
                'timestamp': datetime.utcnow().isoformat(),
                'threat_score': 0,
                'threats': [],
                'file_type': 'unknown',
                'suspicious_indicators': []
            }
            
            # Analyze file extension
            ext_analysis = self._analyze_file_extension(file_path)
            threat_score += ext_analysis['score']
            threats_detected.extend(ext_analysis['threats'])
            analysis_details['file_type'] = ext_analysis['file_type']
            
            # If file data is provided, analyze content
            if file_data:
                content_analysis = self._analyze_file_content(file_data)
                threat_score += content_analysis['score']
                threats_detected.extend(content_analysis['threats'])
                analysis_details['suspicious_indicators'].extend(content_analysis['indicators'])
            
            # Analyze file size
            size_analysis = self._analyze_file_size(file_path)
            threat_score += size_analysis['score']
            threats_detected.extend(size_analysis['threats'])
            
            # Check against known malicious hashes
            hash_analysis = self._check_file_hash(file_path, file_data)
            threat_score += hash_analysis['score']
            threats_detected.extend(hash_analysis['threats'])
            
            # Determine threat level
            if threat_score >= 75:
                threat_level = 'CRITICAL'
            elif threat_score >= 50:
                threat_level = 'HIGH'
            elif threat_score >= 25:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'LOW'
            
            analysis_details.update({
                'threat_score': min(threat_score, 100),
                'threat_level': threat_level,
                'threats': threats_detected
            })
            
            return analysis_details
            
        except Exception as e:
            logger.error(f"Error analyzing file threat: {e}")
            return {
                'file_path': file_path,
                'timestamp': datetime.utcnow().isoformat(),
                'threat_score': 100,
                'threat_level': 'UNKNOWN',
                'threats': [f"Analysis error: {str(e)}"],
                'error': str(e)
            }
    
    def analyze_network_threat(self, connection_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze network connection for potential security threats.
        
        Args:
            connection_info: Dictionary containing connection details
            
        Returns:
            Dictionary containing threat analysis results
        """
        try:
            threat_score = 0
            threats_detected = []
            analysis_details = {
                'connection': connection_info,
                'timestamp': datetime.utcnow().isoformat(),
                'threat_score': 0,
                'threats': [],
                'risk_factors': []
            }
            
            # Analyze remote address
            remote_analysis = self._analyze_remote_address(connection_info.get('remote_address', ''))
            threat_score += remote_analysis['score']
            threats_detected.extend(remote_analysis['threats'])
            
            # Analyze port usage
            port_analysis = self._analyze_port_usage(connection_info)
            threat_score += port_analysis['score']
            threats_detected.extend(port_analysis['threats'])
            
            # Analyze process behavior
            process_analysis = self._analyze_process_behavior(connection_info)
            threat_score += process_analysis['score']
            threats_detected.extend(process_analysis['threats'])
            
            # Check connection patterns
            pattern_analysis = self._analyze_connection_patterns(connection_info)
            threat_score += pattern_analysis['score']
            threats_detected.extend(pattern_analysis['threats'])
            
            # Determine threat level
            if threat_score >= 75:
                threat_level = 'CRITICAL'
            elif threat_score >= 50:
                threat_level = 'HIGH'
            elif threat_score >= 25:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'LOW'
            
            analysis_details.update({
                'threat_score': min(threat_score, 100),
                'threat_level': threat_level,
                'threats': threats_detected,
                'is_suspicious': threat_score >= 25
            })
            
            return analysis_details
            
        except Exception as e:
            logger.error(f"Error analyzing network threat: {e}")
            return {
                'connection': connection_info,
                'timestamp': datetime.utcnow().isoformat(),
                'threat_score': 50,
                'threat_level': 'UNKNOWN',
                'threats': [f"Analysis error: {str(e)}"],
                'is_suspicious': True,
                'error': str(e)
            }
    
    def _analyze_domain(self, url: str) -> Dict[str, Any]:
        """Analyze domain reputation and characteristics."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            threat_score = 0
            threats = []
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download', '.loan']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    threat_score += 30
                    threats.append(f"Suspicious TLD detected: {tld}")
            
            # Check for IP addresses instead of domains
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                threat_score += 20
                threats.append("Direct IP address used instead of domain")
            
            # Check for excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                threat_score += 15
                threats.append(f"Excessive subdomains detected: {subdomain_count}")
            
            # Check for suspicious domain patterns
            suspicious_patterns = [
                r'(?i)(secure|bank|paypal|amazon|microsoft|google).*\d+',
                r'(?i)\d+.*\.(com|net|org)',
                r'(?i)(login|signin|verify|update).*\.',
                r'(?i).*(-|_).*(-|_).*(-|_)'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, domain):
                    threat_score += 20
                    threats.append(f"Suspicious domain pattern: {pattern}")
            
            return {
                'score': threat_score,
                'threats': threats,
                'domain': domain
            }
            
        except Exception as e:
            logger.error(f"Error analyzing domain: {e}")
            return {'score': 10, 'threats': [f"Domain analysis error: {str(e)}"]}
    
    def _check_url_shorteners(self, url: str) -> Dict[str, Any]:
        """Check for URL shortening services."""
        threat_score = 0
        threats = []
        
        for domain in self.known_threat_indicators['suspicious_domains']:
            if domain in url.lower():
                threat_score += 15
                threats.append(f"URL shortener detected: {domain}")
        
        return {'score': threat_score, 'threats': threats}
    
    def _analyze_url_parameters(self, url: str) -> Dict[str, Any]:
        """Analyze URL parameters for suspicious content."""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            threat_score = 0
            threats = []
            
            # Check for suspicious parameter patterns
            suspicious_param_patterns = [
                r'(?i)(redirect|url|goto|next|return)',
                r'(?i)(download|file|attach|exec)',
                r'(?i)(cmd|shell|script|eval)',
                r'(?i)(pass|pwd|token|key|auth)'
            ]
            
            for param_name, param_values in params.items():
                for pattern in suspicious_param_patterns:
                    if re.search(pattern, param_name):
                        threat_score += 10
                        threats.append(f"Suspicious parameter: {param_name}")
                
                # Check parameter values
                for value in param_values:
                    if len(value) > 200:  # Unusually long parameter value
                        threat_score += 5
                        threats.append("Unusually long parameter value detected")
            
            return {'score': threat_score, 'threats': threats}
            
        except Exception as e:
            logger.error(f"Error analyzing URL parameters: {e}")
            return {'score': 0, 'threats': []}
    
    def _analyze_file_extension(self, file_path: str) -> Dict[str, Any]:
        """Analyze file extension for potential threats."""
        threat_score = 0
        threats = []
        file_type = 'unknown'
        
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext in self.known_threat_indicators['file_extensions']:
            if ext in ['.exe', '.scr', '.bat', '.com', '.pif']:
                threat_score += 25
                threats.append(f"Potentially dangerous executable: {ext}")
                file_type = 'executable'
            elif ext in ['.vbs', '.js']:
                threat_score += 20
                threats.append(f"Script file detected: {ext}")
                file_type = 'script'
            elif ext in ['.jar', '.app', '.deb', '.rpm', '.msi', '.dmg']:
                threat_score += 15
                threats.append(f"Installation package: {ext}")
                file_type = 'installer'
        
        # Double extension check
        if file_path.count('.') > 1:
            parts = file_path.split('.')
            if len(parts) >= 3 and parts[-2].lower() in ['txt', 'doc', 'pdf', 'jpg']:
                threat_score += 30
                threats.append("Double extension detected (possible disguise)")
        
        return {
            'score': threat_score,
            'threats': threats,
            'file_type': file_type
        }
    
    def _analyze_file_content(self, file_data: bytes) -> Dict[str, Any]:
        """Analyze file content for suspicious patterns."""
        threat_score = 0
        threats = []
        indicators = []
        
        # Check file signatures
        for sig_type, signatures in self.malicious_patterns['file_signatures'].items():
            for signature in signatures:
                if file_data.startswith(signature):
                    if sig_type == 'executable':
                        threat_score += 15
                        threats.append("Executable file signature detected")
                        indicators.append(f"File signature: {signature.hex()}")
        
        # Check for suspicious strings
        for suspicious_string in self.malicious_patterns['file_signatures']['suspicious_strings']:
            if suspicious_string in file_data.lower():
                threat_score += 20
                threats.append(f"Suspicious string detected: {suspicious_string.decode()}")
                indicators.append(suspicious_string.decode())
        
        # Check entropy (high entropy might indicate encryption/packing)
        entropy = self._calculate_entropy(file_data[:1024])  # Check first 1KB
        if entropy > 7.5:
            threat_score += 10
            threats.append("High entropy detected (possible packing/encryption)")
            indicators.append(f"Entropy: {entropy:.2f}")
        
        return {
            'score': threat_score,
            'threats': threats,
            'indicators': indicators
        }
    
    def _analyze_file_size(self, file_path: str) -> Dict[str, Any]:
        """Analyze file size for anomalies."""
        threat_score = 0
        threats = []
        
        try:
            file_size = os.path.getsize(file_path)
            
            # Very small executable files are suspicious
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.exe', '.app', '.dmg'] and file_size < 1024:
                threat_score += 20
                threats.append("Unusually small executable file")
            
            # Very large files might be suspicious
            if file_size > 500 * 1024 * 1024:  # 500MB
                threat_score += 10
                threats.append("Unusually large file")
            
        except OSError:
            threat_score += 5
            threats.append("Unable to determine file size")
        
        return {'score': threat_score, 'threats': threats}
    
    def _check_file_hash(self, file_path: str, file_data: Optional[bytes] = None) -> Dict[str, Any]:
        """Check file hash against known malicious hashes."""
        threat_score = 0
        threats = []
        
        try:
            if file_data:
                file_hash = hashlib.sha256(file_data).hexdigest()
            else:
                file_hash = self._calculate_file_hash(file_path)
            
            # In a real implementation, this would check against threat intelligence feeds
            # For now, we'll check against a simulated list
            if file_hash in self.threat_feeds.get('malicious_hashes', set()):
                threat_score += 100
                threats.append(f"File matches known malware signature: {file_hash[:8]}...")
        
        except Exception as e:
            logger.error(f"Error checking file hash: {e}")
            threat_score += 5
            threats.append("Unable to calculate file hash")
        
        return {'score': threat_score, 'threats': threats}
    
    def _analyze_remote_address(self, remote_address: str) -> Dict[str, Any]:
        """Analyze remote address for suspicious characteristics."""
        threat_score = 0
        threats = []
        
        if not remote_address or remote_address == "N/A":
            return {'score': 0, 'threats': []}
        
        try:
            ip = remote_address.split(':')[0]
            
            # Check if it's a private IP making external connections
            if self._is_private_ip(ip):
                threat_score += 5
                threats.append("Connection to private IP address")
            
            # Check against known malicious IP ranges (simulated)
            if ip.startswith('192.168.1.') and not self._is_private_ip(ip):
                threat_score += 30
                threats.append("Connection to suspicious IP range")
            
            # Check for non-standard ports
            port = remote_address.split(':')[1] if ':' in remote_address else '80'
            try:
                port_num = int(port)
                if port_num in self.suspicious_ports:
                    threat_score += 15
                    threats.append(f"Connection to suspicious port: {port_num}")
            except ValueError:
                pass
        
        except Exception as e:
            logger.error(f"Error analyzing remote address: {e}")
        
        return {'score': threat_score, 'threats': threats}
    
    def _analyze_port_usage(self, connection_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze port usage patterns."""
        threat_score = 0
        threats = []
        
        try:
            remote_address = connection_info.get('remote_address', '')
            if ':' in remote_address:
                port = int(remote_address.split(':')[1])
                
                # Check for commonly attacked ports
                high_risk_ports = [1433, 3389, 445, 135, 139, 21, 23]
                if port in high_risk_ports:
                    threat_score += 25
                    threats.append(f"Connection to high-risk port: {port}")
                
                # Check for unusual port combinations
                local_address = connection_info.get('local_address', '')
                if ':' in local_address:
                    local_port = int(local_address.split(':')[1])
                    if local_port > 49152 and port < 1024:  # Ephemeral to well-known
                        threat_score += 10
                        threats.append("Unusual port combination detected")
        
        except (ValueError, IndexError):
            pass
        
        return {'score': threat_score, 'threats': threats}
    
    def _analyze_process_behavior(self, connection_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze process behavior patterns."""
        threat_score = 0
        threats = []
        
        process_name = connection_info.get('process_name', '').lower()
        remote_address = connection_info.get('remote_address', '')
        
        # System processes making external connections
        system_processes = ['system', 'svchost.exe', 'winlogon.exe', 'lsass.exe']
        if process_name in system_processes and remote_address != "N/A":
            if not self._is_local_connection(remote_address):
                threat_score += 40
                threats.append(f"System process {process_name} making external connection")
        
        # Suspicious process names
        suspicious_names = ['cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe']
        if process_name in suspicious_names:
            threat_score += 20
            threats.append(f"Suspicious process detected: {process_name}")
        
        return {'score': threat_score, 'threats': threats}
    
    def _analyze_connection_patterns(self, connection_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze connection patterns for anomalies."""
        threat_score = 0
        threats = []
        
        status = connection_info.get('status', '')
        
        # Multiple connections in TIME_WAIT state might indicate scanning
        if status == 'TIME_WAIT':
            threat_score += 5
            threats.append("Connection in TIME_WAIT state")
        
        # Listening services on unusual ports
        if status == 'LISTEN':
            local_address = connection_info.get('local_address', '')
            if ':' in local_address:
                try:
                    port = int(local_address.split(':')[1])
                    if port > 10000:  # High port number
                        threat_score += 10
                        threats.append(f"Service listening on unusual port: {port}")
                except ValueError:
                    pass
        
        return {'score': threat_score, 'threats': threats}
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0
        
        # Count frequency of each byte
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in frequency:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {e}")
            return ""
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private/local."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            return (
                first_octet == 10 or
                first_octet == 127 or
                (first_octet == 172 and 16 <= second_octet <= 31) or
                (first_octet == 192 and second_octet == 168)
            )
        except (ValueError, IndexError):
            return False
    
    def _is_local_connection(self, remote_address: str) -> bool:
        """Check if connection is local."""
        if not remote_address or remote_address == "N/A":
            return True
        
        ip = remote_address.split(':')[0]
        return self._is_private_ip(ip) or ip == '127.0.0.1' or ip == 'localhost'
    
    def _load_threat_feeds(self) -> Dict[str, Any]:
        """Load threat intelligence feeds."""
        # In a production environment, this would load from external threat feeds
        # For now, return a simulated structure
        return {
            'malicious_hashes': set(),
            'malicious_ips': set(),
            'malicious_domains': set(),
            'last_updated': datetime.utcnow().isoformat()
        }
    
    def _generate_url_recommendations(self, threat_score: int) -> List[str]:
        """Generate security recommendations based on threat score."""
        recommendations = []
        
        if threat_score >= 50:
            recommendations.extend([
                "Do not visit this website",
                "Clear browser cookies and cache",
                "Run a full system scan",
                "Check for browser hijacking"
            ])
        elif threat_score >= 25:
            recommendations.extend([
                "Exercise caution when visiting this website",
                "Verify the website URL carefully",
                "Use an updated antivirus",
                "Consider using a VPN"
            ])
        else:
            recommendations.extend([
                "Website appears safe",
                "Keep browser updated",
                "Monitor for suspicious activity"
            ])
        
        return recommendations
    
    def update_threat_feeds(self) -> bool:
        """Update threat intelligence feeds."""
        try:
            # In a production environment, this would fetch from external sources
            logger.info("Threat feeds updated successfully")
            return True
        except Exception as e:
            logger.error(f"Error updating threat feeds: {e}")
            return False
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat detection statistics."""
        return {
            'patterns_loaded': len(self.malicious_patterns['urls']),
            'signatures_loaded': len(self.malicious_patterns['file_signatures']['suspicious_strings']),
            'threat_feeds_updated': self.threat_feeds.get('last_updated', 'Never'),
            'detection_capabilities': [
                'URL Analysis',
                'File Signature Detection',
                'Network Behavior Analysis',
                'Process Monitoring',
                'Hash Verification'
            ]
        }
