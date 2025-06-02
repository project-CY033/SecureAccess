import os
import hashlib
import zipfile
import json
import logging
from datetime import datetime
from app import db
from models import ApplicationScan, SecurityAlert
from utils.file_scanner import FileScanner

logger = logging.getLogger(__name__)

class ApplicationScanner:
    def __init__(self):
        self.file_scanner = FileScanner()
        self.known_malicious_hashes = set()  # Could be populated from threat feeds
        self.suspicious_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
            'android.permission.READ_PHONE_STATE'
        ]
    
    def scan_file(self, file_path):
        """Scan a file for security threats"""
        try:
            if not os.path.exists(file_path):
                return {
                    'error': 'File not found',
                    'file_path': file_path,
                    'timestamp': datetime.utcnow().isoformat()
                }
            
            # Get file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Basic file analysis
            file_info = {
                'file_path': file_path,
                'file_hash': file_hash,
                'file_size': os.path.getsize(file_path),
                'file_extension': os.path.splitext(file_path)[1].lower(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Determine scan method based on file type
            scan_result = self._scan_by_file_type(file_path, file_info)
            
            # Save scan result to database
            self._save_scan_result(scan_result)
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return {
                'error': str(e),
                'file_path': file_path,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def _scan_by_file_type(self, file_path, file_info):
        """Scan file based on its type"""
        extension = file_info['file_extension']
        
        if extension == '.apk':
            return self._scan_apk(file_path, file_info)
        elif extension in ['.exe', '.msi', '.dll']:
            return self._scan_windows_executable(file_path, file_info)
        elif extension in ['.app', '.dmg']:
            return self._scan_macos_application(file_path, file_info)
        else:
            return self._scan_generic_file(file_path, file_info)
    
    def _scan_apk(self, file_path, file_info):
        """Scan Android APK file"""
        try:
            scan_result = file_info.copy()
            scan_result['scan_type'] = 'APK'
            scan_result['threats'] = []
            scan_result['permissions'] = []
            scan_result['threat_level'] = 'LOW'
            
            # Try to extract APK information
            try:
                with zipfile.ZipFile(file_path, 'r') as apk_zip:
                    # Look for AndroidManifest.xml
                    if 'AndroidManifest.xml' in apk_zip.namelist():
                        # In a real implementation, you would parse the manifest
                        # For now, we'll simulate permission detection
                        scan_result['permissions'] = self._simulate_apk_permissions()
                        
                        # Check for suspicious permissions
                        suspicious_found = []
                        for permission in scan_result['permissions']:
                            if permission in self.suspicious_permissions:
                                suspicious_found.append(permission)
                        
                        if suspicious_found:
                            scan_result['threats'].append(f"Suspicious permissions: {', '.join(suspicious_found)}")
                            scan_result['threat_level'] = 'MEDIUM' if len(suspicious_found) < 3 else 'HIGH'
                        
                        # Check for hidden permissions (simulated)
                        hidden_permissions = self._detect_hidden_permissions(scan_result['permissions'])
                        if hidden_permissions:
                            scan_result['threats'].append(f"Hidden permissions detected: {', '.join(hidden_permissions)}")
                            scan_result['threat_level'] = 'HIGH'
                    
                    # Check for suspicious files
                    suspicious_files = self._check_suspicious_files_in_apk(apk_zip.namelist())
                    if suspicious_files:
                        scan_result['threats'].append(f"Suspicious files found: {', '.join(suspicious_files)}")
                        scan_result['threat_level'] = 'HIGH'
            
            except zipfile.BadZipFile:
                scan_result['threats'].append("Corrupted or invalid APK file")
                scan_result['threat_level'] = 'HIGH'
            
            # Check against known malicious hashes
            if file_info['file_hash'] in self.known_malicious_hashes:
                scan_result['threats'].append("File matches known malware signature")
                scan_result['threat_level'] = 'CRITICAL'
            
            scan_result['scan_result'] = 'THREAT_DETECTED' if scan_result['threats'] else 'CLEAN'
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning APK {file_path}: {e}")
            return {**file_info, 'error': str(e), 'scan_type': 'APK'}
    
    def _scan_windows_executable(self, file_path, file_info):
        """Scan Windows executable file"""
        try:
            scan_result = file_info.copy()
            scan_result['scan_type'] = 'Windows Executable'
            scan_result['threats'] = []
            scan_result['threat_level'] = 'LOW'
            
            # Check file size (unusually small or large executables can be suspicious)
            file_size = file_info['file_size']
            if file_size < 1024:  # Less than 1KB
                scan_result['threats'].append("Unusually small executable file")
                scan_result['threat_level'] = 'MEDIUM'
            elif file_size > 100 * 1024 * 1024:  # Larger than 100MB
                scan_result['threats'].append("Unusually large executable file")
                scan_result['threat_level'] = 'MEDIUM'
            
            # Simple signature-based detection (simulated)
            with open(file_path, 'rb') as f:
                file_header = f.read(1024)
                
                # Check for suspicious patterns
                suspicious_patterns = [b'trojan', b'virus', b'malware', b'backdoor']
                for pattern in suspicious_patterns:
                    if pattern in file_header.lower():
                        scan_result['threats'].append(f"Suspicious pattern detected: {pattern.decode()}")
                        scan_result['threat_level'] = 'HIGH'
            
            # Check against known malicious hashes
            if file_info['file_hash'] in self.known_malicious_hashes:
                scan_result['threats'].append("File matches known malware signature")
                scan_result['threat_level'] = 'CRITICAL'
            
            scan_result['scan_result'] = 'THREAT_DETECTED' if scan_result['threats'] else 'CLEAN'
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning Windows executable {file_path}: {e}")
            return {**file_info, 'error': str(e), 'scan_type': 'Windows Executable'}
    
    def _scan_macos_application(self, file_path, file_info):
        """Scan macOS application file"""
        try:
            scan_result = file_info.copy()
            scan_result['scan_type'] = 'macOS Application'
            scan_result['threats'] = []
            scan_result['threat_level'] = 'LOW'
            
            # Basic checks for macOS applications
            if file_info['file_extension'] == '.app':
                # Check if it's actually a directory (proper .app structure)
                if not os.path.isdir(file_path):
                    scan_result['threats'].append("Invalid .app structure")
                    scan_result['threat_level'] = 'MEDIUM'
            
            # Check against known malicious hashes
            if file_info['file_hash'] in self.known_malicious_hashes:
                scan_result['threats'].append("File matches known malware signature")
                scan_result['threat_level'] = 'CRITICAL'
            
            scan_result['scan_result'] = 'THREAT_DETECTED' if scan_result['threats'] else 'CLEAN'
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning macOS application {file_path}: {e}")
            return {**file_info, 'error': str(e), 'scan_type': 'macOS Application'}
    
    def _scan_generic_file(self, file_path, file_info):
        """Scan generic file"""
        try:
            scan_result = file_info.copy()
            scan_result['scan_type'] = 'Generic File'
            scan_result['threats'] = []
            scan_result['threat_level'] = 'LOW'
            
            # Basic file checks
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read(10240)  # Read first 10KB
                    
                    # Check for executable signatures
                    if file_content.startswith(b'MZ') or file_content.startswith(b'\x7fELF'):
                        scan_result['threats'].append("File appears to be executable despite extension")
                        scan_result['threat_level'] = 'MEDIUM'
            
            except Exception:
                pass
            
            # Check against known malicious hashes
            if file_info['file_hash'] in self.known_malicious_hashes:
                scan_result['threats'].append("File matches known malware signature")
                scan_result['threat_level'] = 'CRITICAL'
            
            scan_result['scan_result'] = 'THREAT_DETECTED' if scan_result['threats'] else 'CLEAN'
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning generic file {file_path}: {e}")
            return {**file_info, 'error': str(e), 'scan_type': 'Generic File'}
    
    def _simulate_apk_permissions(self):
        """Simulate APK permission extraction"""
        # In a real implementation, this would parse AndroidManifest.xml
        return [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_EXTERNAL_STORAGE'
        ]
    
    def _detect_hidden_permissions(self, permissions):
        """Detect potentially hidden or undeclared permissions"""
        # Simulate detection of hidden permissions
        hidden = []
        for perm in self.suspicious_permissions[:2]:  # Simulate finding some hidden permissions
            if perm not in permissions:
                hidden.append(perm)
        return hidden
    
    def _check_suspicious_files_in_apk(self, file_list):
        """Check for suspicious files in APK"""
        suspicious_files = []
        suspicious_patterns = ['native', 'so', 'dex', 'jar']
        
        for filename in file_list:
            for pattern in suspicious_patterns:
                if pattern in filename.lower() and 'lib' not in filename.lower():
                    suspicious_files.append(filename)
                    break
        
        return suspicious_files[:5]  # Return first 5 suspicious files
    
    def _save_scan_result(self, scan_result):
        """Save scan result to database"""
        try:
            scan_record = ApplicationScan(
                file_path=scan_result['file_path'],
                file_hash=scan_result.get('file_hash'),
                scan_result=scan_result.get('scan_result', 'ERROR'),
                threat_level=scan_result.get('threat_level', 'UNKNOWN'),
                details=scan_result
            )
            db.session.add(scan_record)
            
            # Create alert if threat detected
            if scan_result.get('threats'):
                alert = SecurityAlert(
                    alert_type='APPLICATION_SCAN',
                    severity=scan_result.get('threat_level', 'MEDIUM'),
                    message=f"Threats detected in {scan_result['file_path']}: {', '.join(scan_result['threats'])}",
                    source='ApplicationScanner'
                )
                db.session.add(alert)
            
            db.session.commit()
            
        except Exception as e:
            logger.error(f"Error saving scan result: {e}")
    
    def get_recent_scans(self, limit=50):
        """Get recent scan results"""
        try:
            scans = ApplicationScan.query.order_by(
                ApplicationScan.timestamp.desc()
            ).limit(limit).all()
            
            scan_list = []
            for scan in scans:
                scan_list.append({
                    'id': scan.id,
                    'file_path': scan.file_path,
                    'file_hash': scan.file_hash,
                    'scan_result': scan.scan_result,
                    'threat_level': scan.threat_level,
                    'details': scan.details,
                    'timestamp': scan.timestamp.isoformat()
                })
            
            return scan_list
            
        except Exception as e:
            logger.error(f"Error getting recent scans: {e}")
            return []
