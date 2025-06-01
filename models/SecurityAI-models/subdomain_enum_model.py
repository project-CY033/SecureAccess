"""
CyberGuard Pro - Subdomain Enumeration AI Model
Advanced subdomain discovery with AI-enhanced validation and threat assessment
"""

import asyncio
import aiohttp
import socket
import ssl
import json
import re
import logging
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime
import dns.resolver
import dns.exception
from urllib.parse import urlparse
import hashlib
import os

class SubdomainEnumerationModel:
    """
    AI-enhanced subdomain enumeration model that combines multiple discovery techniques
    with intelligent validation and threat assessment.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.common_subdomains = self._load_common_subdomains()
        self.session = None
        self.discovered_subdomains = set()
        self.validated_subdomains = set()
        self.threat_indicators = {}
        
    def _load_common_subdomains(self) -> List[str]:
        """Load common subdomain list for brute force enumeration."""
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'secure', 'vpn', 'remote', 'portal', 'app',
            'beta', 'demo', 'docs', 'help', 'support', 'forum', 'chat',
            'mobile', 'm', 'cdn', 'static', 'assets', 'img', 'images',
            'video', 'media', 'download', 'files', 'upload', 'backup',
            'old', 'new', 'beta', 'alpha', 'preview', 'sandbox', 'lab',
            'git', 'svn', 'ci', 'jenkins', 'build', 'deploy', 'status',
            'monitor', 'metrics', 'logs', 'grafana', 'kibana', 'elastic',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
            'cache', 'queue', 'worker', 'cron', 'scheduler', 'api-v1',
            'api-v2', 'v1', 'v2', 'v3', 'internal', 'intranet', 'extranet'
        ]
        return common_subs
    
    async def enumerate_subdomains(self, domain: str, methods: List[str] = None, 
                                 deep_scan: bool = True, 
                                 validate_results: bool = True) -> Dict:
        """
        Main enumeration function that orchestrates multiple discovery methods.
        
        Args:
            domain: Target domain to enumerate
            methods: List of methods to use ['dns', 'bruteforce', 'certificate', 'all']
            deep_scan: Whether to perform deep scanning
            validate_results: Whether to validate discovered subdomains
            
        Returns:
            Dictionary containing enumeration results and analysis
        """
        
        if methods is None:
            methods = ['dns', 'bruteforce', 'certificate']
        elif 'all' in methods:
            methods = ['dns', 'bruteforce', 'certificate', 'search_engines', 'threat_intel']
        
        self.logger.info(f"Starting subdomain enumeration for {domain} using methods: {methods}")
        
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'methods_used': methods,
            'subdomains': [],
            'validated_subdomains': [],
            'threat_analysis': {},
            'statistics': {},
            'errors': []
        }
        
        try:
            # Initialize HTTP session
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False)
            )
            
            # Execute enumeration methods
            tasks = []
            
            if 'dns' in methods:
                tasks.append(self._dns_enumeration(domain))
            
            if 'bruteforce' in methods:
                tasks.append(self._bruteforce_enumeration(domain, deep_scan))
            
            if 'certificate' in methods:
                tasks.append(self._certificate_transparency_search(domain))
            
            if 'search_engines' in methods:
                tasks.append(self._search_engine_enumeration(domain))
            
            if 'threat_intel' in methods:
                tasks.append(self._threat_intel_enumeration(domain))
            
            # Execute all methods concurrently
            method_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results from each method
            for i, result in enumerate(method_results):
                if isinstance(result, Exception):
                    self.logger.error(f"Method {methods[i]} failed: {str(result)}")
                    results['errors'].append(f"{methods[i]}: {str(result)}")
                else:
                    self.discovered_subdomains.update(result)
            
            # Validation phase
            if validate_results and self.discovered_subdomains:
                self.logger.info(f"Validating {len(self.discovered_subdomains)} discovered subdomains")
                validated = await self._validate_subdomains(list(self.discovered_subdomains))
                self.validated_subdomains.update(validated)
            
            # Threat analysis
            if self.validated_subdomains:
                threat_analysis = await self._analyze_threats(self.validated_subdomains)
                results['threat_analysis'] = threat_analysis
            
            # Compile final results
            results['subdomains'] = sorted(list(self.discovered_subdomains))
            results['validated_subdomains'] = sorted(list(self.validated_subdomains))
            results['statistics'] = self._generate_statistics()
            
        except Exception as e:
            self.logger.error(f"Enumeration failed: {str(e)}")
            results['errors'].append(f"General error: {str(e)}")
        
        finally:
            if self.session:
                await self.session.close()
        
        return results
    
    async def _dns_enumeration(self, domain: str) -> Set[str]:
        """Enumerate subdomains using DNS queries."""
        subdomains = set()
        
        try:
            # Check for wildcard DNS
            wildcard_response = await self._check_wildcard_dns(domain)
            
            # Standard DNS record enumeration
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for answer in answers:
                        # Extract potential subdomains from DNS responses
                        subdomain = self._extract_subdomain_from_dns(str(answer), domain)
                        if subdomain:
                            subdomains.add(subdomain)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                    continue
                except Exception as e:
                    self.logger.debug(f"DNS query failed for {record_type}: {str(e)}")
            
            # Zone transfer attempt (usually fails but worth trying)
            try:
                ns_servers = dns.resolver.resolve(domain, 'NS')
                for ns in ns_servers:
                    zone_subdomains = await self._attempt_zone_transfer(domain, str(ns))
                    subdomains.update(zone_subdomains)
            except Exception as e:
                self.logger.debug(f"Zone transfer failed: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {str(e)}")
            raise
        
        return subdomains
    
    async def _bruteforce_enumeration(self, domain: str, deep_scan: bool) -> Set[str]:
        """Brute force subdomain enumeration using wordlist."""
        subdomains = set()
        
        try:
            wordlist = self.common_subdomains
            if deep_scan:
                # Add more comprehensive wordlist for deep scan
                wordlist.extend(self._get_extended_wordlist())
            
            # Limit concurrent requests to avoid overwhelming the target
            semaphore = asyncio.Semaphore(50)
            
            async def check_subdomain(subdomain_name):
                async with semaphore:
                    return await self._check_subdomain_exists(f"{subdomain_name}.{domain}")
            
            # Create tasks for all subdomain checks
            tasks = [check_subdomain(sub) for sub in wordlist]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(results):
                if result is True:  # Subdomain exists
                    subdomains.add(f"{wordlist[i]}.{domain}")
                elif isinstance(result, Exception):
                    self.logger.debug(f"Check failed for {wordlist[i]}.{domain}: {str(result)}")
        
        except Exception as e:
            self.logger.error(f"Brute force enumeration failed: {str(e)}")
            raise
        
        return subdomains
    
    async def _certificate_transparency_search(self, domain: str) -> Set[str]:
        """Search Certificate Transparency logs for subdomains."""
        subdomains = set()
        
        try:
            # Use crt.sh API for certificate transparency search
            ct_api_url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with self.session.get(ct_api_url) as response:
                if response.status == 200:
                    ct_data = await response.json()
                    
                    for cert in ct_data:
                        if 'name_value' in cert:
                            # Parse certificate names
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip()
                                if name.endswith(f".{domain}") and name != domain:
                                    # Validate subdomain format
                                    if self._is_valid_subdomain(name, domain):
                                        subdomains.add(name)
        
        except Exception as e:
            self.logger.error(f"Certificate transparency search failed: {str(e)}")
            raise
        
        return subdomains
    
    async def _search_engine_enumeration(self, domain: str) -> Set[str]:
        """Enumerate subdomains using search engine dorking."""
        subdomains = set()
        
        try:
            # This is a placeholder for search engine enumeration
            # In a real implementation, you would use search engine APIs
            # or web scraping (respecting robots.txt and rate limits)
            
            search_queries = [
                f"site:{domain}",
                f"site:*.{domain}",
                f"inurl:{domain}",
            ]
            
            # Simulate search results (replace with actual implementation)
            self.logger.info("Search engine enumeration would be implemented here")
            
        except Exception as e:
            self.logger.error(f"Search engine enumeration failed: {str(e)}")
            raise
        
        return subdomains
    
    async def _threat_intel_enumeration(self, domain: str) -> Set[str]:
        """Enumerate subdomains using threat intelligence sources."""
        subdomains = set()
        
        try:
            # This would integrate with threat intelligence APIs
            # like VirusTotal, PassiveTotal, etc.
            
            # VirusTotal passive DNS (requires API key)
            vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
            if vt_api_key:
                vt_subdomains = await self._virustotal_passive_dns(domain, vt_api_key)
                subdomains.update(vt_subdomains)
            
        except Exception as e:
            self.logger.error(f"Threat intel enumeration failed: {str(e)}")
            raise
        
        return subdomains
    
    async def _validate_subdomains(self, subdomains: List[str]) -> Set[str]:
        """Validate discovered subdomains by checking if they resolve."""
        validated = set()
        
        try:
            semaphore = asyncio.Semaphore(100)  # Limit concurrent validations
            
            async def validate_subdomain(subdomain):
                async with semaphore:
                    if await self._check_subdomain_exists(subdomain):
                        return subdomain
                    return None
            
            tasks = [validate_subdomain(sub) for sub in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    validated.add(result)
        
        except Exception as e:
            self.logger.error(f"Subdomain validation failed: {str(e)}")
            raise
        
        return validated
    
    async def _analyze_threats(self, subdomains: Set[str]) -> Dict:
        """Analyze validated subdomains for potential security threats."""
        threat_analysis = {
            'high_risk_subdomains': [],
            'suspicious_patterns': [],
            'exposed_services': [],
            'ssl_issues': [],
            'total_risk_score': 0
        }
        
        try:
            for subdomain in subdomains:
                risk_factors = []
                
                # Check for high-risk subdomain patterns
                high_risk_patterns = [
                    'admin', 'test', 'dev', 'staging', 'backup', 'old',
                    'temp', 'debug', 'api', 'internal', 'vpn', 'git'
                ]
                
                subdomain_name = subdomain.split('.')[0].lower()
                if subdomain_name in high_risk_patterns:
                    risk_factors.append(f"High-risk subdomain pattern: {subdomain_name}")
                
                # Check SSL configuration
                ssl_issues = await self._check_ssl_configuration(subdomain)
                if ssl_issues:
                    risk_factors.append(f"SSL issues: {', '.join(ssl_issues)}")
                    threat_analysis['ssl_issues'].append({
                        'subdomain': subdomain,
                        'issues': ssl_issues
                    })
                
                # Check for exposed services
                exposed_services = await self._check_exposed_services(subdomain)
                if exposed_services:
                    threat_analysis['exposed_services'].append({
                        'subdomain': subdomain,
                        'services': exposed_services
                    })
                
                if risk_factors:
                    threat_analysis['high_risk_subdomains'].append({
                        'subdomain': subdomain,
                        'risk_factors': risk_factors
                    })
            
            # Calculate overall risk score
            threat_analysis['total_risk_score'] = self._calculate_risk_score(threat_analysis)
        
        except Exception as e:
            self.logger.error(f"Threat analysis failed: {str(e)}")
        
        return threat_analysis
    
    async def _check_subdomain_exists(self, subdomain: str) -> bool:
        """Check if a subdomain exists by attempting DNS resolution."""
        try:
            # Try DNS resolution
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False
        except Exception as e:
            self.logger.debug(f"DNS check failed for {subdomain}: {str(e)}")
            return False
    
    async def _check_ssl_configuration(self, subdomain: str) -> List[str]:
        """Check SSL configuration for potential issues."""
        issues = []
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((subdomain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = cert.get('notAfter')
                    if not_after:
                        # Parse certificate expiry date
                        import ssl
                        expiry_date = ssl.cert_time_to_seconds(not_after)
                        current_time = datetime.utcnow().timestamp()
                        
                        if expiry_date < current_time:
                            issues.append("Certificate expired")
                        elif expiry_date - current_time < 2592000:  # 30 days
                            issues.append("Certificate expires soon")
                    
                    # Check for self-signed certificates
                    if cert.get('issuer') == cert.get('subject'):
                        issues.append("Self-signed certificate")
        
        except (socket.timeout, socket.gaierror, ssl.SSLError, ConnectionRefusedError):
            # SSL not available or connection failed
            pass
        except Exception as e:
            self.logger.debug(f"SSL check failed for {subdomain}: {str(e)}")
        
        return issues
    
    async def _check_exposed_services(self, subdomain: str) -> List[str]:
        """Check for potentially exposed services on the subdomain."""
        exposed_services = []
        
        try:
            # Check common service ports
            service_ports = {
                22: 'SSH',
                21: 'FTP',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S',
                3389: 'RDP',
                5432: 'PostgreSQL',
                3306: 'MySQL',
                27017: 'MongoDB',
                6379: 'Redis'
            }
            
            for port, service in service_ports.items():
                if await self._check_port_open(subdomain, port):
                    exposed_services.append(f"{service} ({port})")
        
        except Exception as e:
            self.logger.debug(f"Service check failed for {subdomain}: {str(e)}")
        
        return exposed_services
    
    async def _check_port_open(self, host: str, port: int, timeout: int = 3) -> bool:
        """Check if a specific port is open on the host."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return False
        except Exception as e:
            self.logger.debug(f"Port check failed for {host}:{port}: {str(e)}")
            return False
    
    def _calculate_risk_score(self, threat_analysis: Dict) -> int:
        """Calculate an overall risk score based on threat analysis."""
        score = 0
        
        # High-risk subdomains
        score += len(threat_analysis['high_risk_subdomains']) * 10
        
        # SSL issues
        score += len(threat_analysis['ssl_issues']) * 5
        
        # Exposed services
        for service_group in threat_analysis['exposed_services']:
            score += len(service_group['services']) * 3
        
        return min(score, 100)  # Cap at 100
    
    def _generate_statistics(self) -> Dict:
        """Generate enumeration statistics."""
        return {
            'total_discovered': len(self.discovered_subdomains),
            'total_validated': len(self.validated_subdomains),
            'validation_rate': (len(self.validated_subdomains) / max(len(self.discovered_subdomains), 1)) * 100,
            'unique_subdomains': len(set(sub.split('.')[0] for sub in self.validated_subdomains))
        }
    
    def _get_extended_wordlist(self) -> List[str]:
        """Get extended wordlist for deep scanning."""
        return [
            'www2', 'www3', 'mail2', 'smtp', 'pop', 'imap', 'webmail',
            'email', 'secure-mail', 'mx', 'mx1', 'mx2', 'exchange',
            'autodiscover', 'admin-panel', 'cpanel', 'plesk', 'whm',
            'control', 'manage', 'dashboard', 'panel', 'root', 'sys',
            'system', 'server', 'host', 'node', 'cluster', 'lb',
            'balancer', 'proxy', 'gateway', 'firewall', 'router',
            'switch', 'wireless', 'wifi', 'guest', 'public', 'private'
        ]
    
    def _extract_subdomain_from_dns(self, dns_response: str, domain: str) -> Optional[str]:
        """Extract potential subdomain from DNS response."""
        # Simple extraction logic - could be enhanced
        if f".{domain}" in dns_response and dns_response.endswith(f".{domain}."):
            subdomain = dns_response.replace(f".{domain}.", "")
            if subdomain and self._is_valid_subdomain(f"{subdomain}.{domain}", domain):
                return f"{subdomain}.{domain}"
        return None
    
    def _is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Validate subdomain format and constraints."""
        if not subdomain.endswith(f".{domain}"):
            return False
        
        # Remove the main domain part
        sub_part = subdomain[:-len(f".{domain}")]
        
        # Check for valid subdomain format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', sub_part):
            return False
        
        # Check length constraints
        if len(sub_part) > 253 or any(len(label) > 63 for label in sub_part.split('.')):
            return False
        
        return True
    
    async def _check_wildcard_dns(self, domain: str) -> Optional[str]:
        """Check if domain has wildcard DNS configured."""
        try:
            # Generate a random subdomain that shouldn't exist
            random_subdomain = f"{''.join([chr(ord('a') + i) for i in range(20)])}.{domain}"
            socket.gethostbyname(random_subdomain)
            return "Wildcard DNS detected"
        except socket.gaierror:
            return None  # No wildcard DNS
        except Exception as e:
            self.logger.debug(f"Wildcard DNS check failed: {str(e)}")
            return None
    
    async def _attempt_zone_transfer(self, domain: str, ns_server: str) -> Set[str]:
        """Attempt DNS zone transfer (usually fails but worth trying)."""
        subdomains = set()
        
        try:
            # This would implement AXFR zone transfer
            # Usually fails due to security configurations
            self.logger.debug(f"Zone transfer attempt for {domain} via {ns_server}")
        except Exception as e:
            self.logger.debug(f"Zone transfer failed: {str(e)}")
        
        return subdomains
    
    async def _virustotal_passive_dns(self, domain: str, api_key: str) -> Set[str]:
        """Query VirusTotal passive DNS for subdomains."""
        subdomains = set()
        
        try:
            headers = {'x-apikey': api_key}
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'domain': domain, 'apikey': api_key}
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Extract subdomains from VirusTotal response
                    if 'subdomains' in data:
                        for subdomain in data['subdomains']:
                            if self._is_valid_subdomain(subdomain, domain):
                                subdomains.add(subdomain)
        
        except Exception as e:
            self.logger.debug(f"VirusTotal passive DNS failed: {str(e)}")
        
        return subdomains
