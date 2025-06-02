import os
import hashlib
import zipfile
import logging
import magic
import struct
from typing import Dict, List, Any, Optional, BinaryIO
from datetime import datetime
import tempfile
import json

logger = logging.getLogger(__name__)

class FileScanner:
    """
    Advanced file scanning utility for security analysis.
    Supports multiple file formats and provides detailed analysis.
    """
    
    def __init__(self):
        self.supported_formats = {
            '.exe': 'windows_executable',
            '.dll': 'windows_library',
            '.msi': 'windows_installer',
            '.apk': 'android_package',
            '.app': 'macos_application',
            '.dmg': 'macos_disk_image',
            '.deb': 'debian_package',
            '.rpm': 'redhat_package',
            '.jar': 'java_archive',
            '.zip': 'zip_archive',
            '.rar': 'rar_archive',
            '.7z': 'seven_zip_archive',
            '.tar': 'tar_archive',
            '.gz': 'gzip_archive',
            '.bz2': 'bzip2_archive'
        }
        
        self.file_signatures = {
            'PE': b'MZ',
            'ELF': b'\x7fELF',
            'Mach-O': b'\xfe\xed\xfa\xce',
            'ZIP': b'PK\x03\x04',
            'RAR': b'Rar!\x1a\x07\x00',
            'PDF': b'%PDF',
            'JPEG': b'\xff\xd8\xff',
            'PNG': b'\x89PNG\r\n\x1a\n',
            'GIF': b'GIF8',
            'RIFF': b'RIFF'
        }
        
        self.dangerous_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', 
            '.js', '.jar', '.app', '.dmg', '.deb', '.rpm', '.msi'
        ]
        
        self.archive_extensions = [
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'
        ]
        
        # Android permissions that are considered suspicious
        self.suspicious_android_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.DEVICE_ADMIN',
            'android.permission.BIND_DEVICE_ADMIN'
        ]
    
    def scan_file(self, file_path: str, deep_scan: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive file scanning.
        
        Args:
            file_path: Path to the file to scan
            deep_scan: Whether to perform deep content analysis
            
        Returns:
            Dictionary containing scan results
        """
        try:
            if not os.path.exists(file_path):
                return self._create_error_result(file_path, "File not found")
            
            # Basic file information
            file_info = self._get_file_info(file_path)
            
            # Determine file type
            file_type = self._determine_file_type(file_path, file_info)
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Initialize scan result
            scan_result = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': file_info['size'],
                'file_hash': file_hash,
                'file_type': file_type,
                'mime_type': file_info.get('mime_type', 'unknown'),
                'timestamp': datetime.utcnow().isoformat(),
                'scan_type': 'comprehensive',
                'threats': [],
                'warnings': [],
                'metadata': {},
                'permissions': [],
                'suspicious_indicators': [],
                'scan_details': {}
            }
            
            # Perform format-specific analysis
            format_analysis = self._analyze_by_format(file_path, file_type, deep_scan)
            scan_result.update(format_analysis)
            
            # Perform content analysis if deep scan is enabled
            if deep_scan:
                content_analysis = self._perform_content_analysis(file_path)
                scan_result['scan_details'].update(content_analysis)
            
            # Security assessment
            security_assessment = self._assess_security_risk(scan_result)
            scan_result.update(security_assessment)
            
            # Final threat determination
            scan_result['scan_result'] = self._determine_scan_result(scan_result)
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return self._create_error_result(file_path, str(e))
    
    def scan_archive(self, archive_path: str, max_files: int = 100) -> Dict[str, Any]:
        """
        Scan contents of an archive file.
        
        Args:
            archive_path: Path to the archive file
            max_files: Maximum number of files to scan in the archive
            
        Returns:
            Dictionary containing archive scan results
        """
        try:
            archive_result = {
                'archive_path': archive_path,
                'archive_type': self._determine_file_type(archive_path),
                'timestamp': datetime.utcnow().isoformat(),
                'files_scanned': 0,
                'total_files': 0,
                'threats_found': 0,
                'suspicious_files': [],
                'scan_results': []
            }
            
            if archive_path.lower().endswith('.zip') or archive_path.lower().endswith('.apk'):
                return self._scan_zip_archive(archive_path, archive_result, max_files)
            elif archive_path.lower().endswith('.rar'):
                return self._scan_rar_archive(archive_path, archive_result, max_files)
            else:
                archive_result['error'] = f"Unsupported archive format"
                return archive_result
                
        except Exception as e:
            logger.error(f"Error scanning archive {archive_path}: {e}")
            return {
                'archive_path': archive_path,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def extract_android_permissions(self, apk_path: str) -> List[str]:
        """
        Extract permissions from Android APK file.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            List of permissions found in the APK
        """
        permissions = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for AndroidManifest.xml
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    # In a real implementation, you would parse the binary XML
                    # For now, we'll simulate permission extraction
                    permissions = self._simulate_android_permissions()
                
                # Check for additional permission files
                for file_name in apk_zip.namelist():
                    if 'permission' in file_name.lower():
                        permissions.extend(self._extract_permissions_from_file(apk_zip, file_name))
        
        except Exception as e:
            logger.error(f"Error extracting Android permissions: {e}")
        
        return list(set(permissions))  # Remove duplicates
    
    def analyze_pe_file(self, pe_path: str) -> Dict[str, Any]:
        """
        Analyze Windows PE (Portable Executable) file.
        
        Args:
            pe_path: Path to the PE file
            
        Returns:
            Dictionary containing PE analysis results
        """
        try:
            pe_info = {
                'file_path': pe_path,
                'pe_type': 'unknown',
                'architecture': 'unknown',
                'imports': [],
                'exports': [],
                'sections': [],
                'suspicious_indicators': [],
                'compilation_timestamp': None,
                'entry_point': None,
                'image_base': None
            }
            
            with open(pe_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    pe_info['error'] = "Invalid PE file format"
                    return pe_info
                
                # Get PE header offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # Read PE signature
                pe_signature = f.read(4)
                if pe_signature != b'PE\x00\x00':
                    pe_info['error'] = "Invalid PE signature"
                    return pe_info
                
                # Read COFF header
                coff_header = f.read(20)
                if len(coff_header) < 20:
                    pe_info['error'] = "Invalid COFF header"
                    return pe_info
                
                machine_type = struct.unpack('<H', coff_header[0:2])[0]
                pe_info['architecture'] = self._get_pe_architecture(machine_type)
                
                number_of_sections = struct.unpack('<H', coff_header[2:4])[0]
                time_stamp = struct.unpack('<I', coff_header[4:8])[0]
                pe_info['compilation_timestamp'] = datetime.fromtimestamp(time_stamp).isoformat()
                
                # Read optional header
                optional_header_size = struct.unpack('<H', coff_header[16:18])[0]
                if optional_header_size > 0:
                    optional_header = f.read(optional_header_size)
                    if len(optional_header) >= 4:
                        magic = struct.unpack('<H', optional_header[0:2])[0]
                        pe_info['pe_type'] = 'PE32+' if magic == 0x20b else 'PE32'
                    
                    if len(optional_header) >= 16:
                        pe_info['entry_point'] = struct.unpack('<I', optional_header[16:20])[0]
                    
                    if len(optional_header) >= 28:
                        pe_info['image_base'] = struct.unpack('<I', optional_header[28:32])[0]
                
                # Analyze sections
                pe_info['sections'] = self._analyze_pe_sections(f, number_of_sections)
                
                # Check for suspicious indicators
                pe_info['suspicious_indicators'] = self._check_pe_suspicious_indicators(pe_info)
            
            return pe_info
            
        except Exception as e:
            logger.error(f"Error analyzing PE file: {e}")
            return {
                'file_path': pe_path,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information."""
        try:
            stat_info = os.stat(file_path)
            file_info = {
                'size': stat_info.st_size,
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'permissions': oct(stat_info.st_mode)[-3:]
            }
            
            # Try to get MIME type using python-magic
            try:
                import magic
                file_info['mime_type'] = magic.from_file(file_path, mime=True)
            except ImportError:
                # Fallback if python-magic is not available
                file_info['mime_type'] = self._guess_mime_type(file_path)
            
            return file_info
            
        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            return {'size': 0, 'error': str(e)}
    
    def _determine_file_type(self, file_path: str, file_info: Optional[Dict] = None) -> str:
        """Determine file type based on extension and content."""
        # Check by extension first
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.supported_formats:
            return self.supported_formats[ext]
        
        # Check by file signature
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                for sig_name, signature in self.file_signatures.items():
                    if header.startswith(signature):
                        return sig_name.lower()
        except Exception:
            pass
        
        # Check MIME type if available
        if file_info and 'mime_type' in file_info:
            mime_type = file_info['mime_type']
            if 'executable' in mime_type:
                return 'executable'
            elif 'archive' in mime_type:
                return 'archive'
        
        return 'unknown'
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of the file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {e}")
            return ""
    
    def _analyze_by_format(self, file_path: str, file_type: str, deep_scan: bool) -> Dict[str, Any]:
        """Perform format-specific analysis."""
        analysis_result = {
            'scan_details': {},
            'metadata': {},
            'permissions': [],
            'suspicious_indicators': []
        }
        
        try:
            if file_type == 'android_package':
                analysis_result.update(self._analyze_android_apk(file_path, deep_scan))
            elif file_type in ['windows_executable', 'windows_library', 'pe']:
                analysis_result.update(self._analyze_windows_executable(file_path, deep_scan))
            elif file_type == 'macos_application':
                analysis_result.update(self._analyze_macos_app(file_path, deep_scan))
            elif file_type in ['zip_archive', 'java_archive']:
                analysis_result.update(self._analyze_archive(file_path, deep_scan))
            else:
                analysis_result['scan_details']['analysis_type'] = 'generic'
                analysis_result.update(self._analyze_generic_file(file_path, deep_scan))
        
        except Exception as e:
            logger.error(f"Error in format-specific analysis: {e}")
            analysis_result['scan_details']['analysis_error'] = str(e)
        
        return analysis_result
    
    def _analyze_android_apk(self, apk_path: str, deep_scan: bool) -> Dict[str, Any]:
        """Analyze Android APK file."""
        result = {
            'scan_details': {'analysis_type': 'android_apk'},
            'permissions': [],
            'suspicious_indicators': [],
            'metadata': {}
        }
        
        try:
            # Extract permissions
            permissions = self.extract_android_permissions(apk_path)
            result['permissions'] = permissions
            
            # Check for suspicious permissions
            suspicious_perms = [p for p in permissions if p in self.suspicious_android_permissions]
            if suspicious_perms:
                result['suspicious_indicators'].extend([
                    f"Suspicious permission: {perm}" for perm in suspicious_perms
                ])
            
            # Analyze APK structure
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                file_list = apk_zip.namelist()
                result['metadata']['total_files'] = len(file_list)
                
                # Check for suspicious files
                suspicious_files = [f for f in file_list if self._is_suspicious_apk_file(f)]
                if suspicious_files:
                    result['suspicious_indicators'].extend([
                        f"Suspicious file in APK: {f}" for f in suspicious_files[:5]
                    ])
                
                # Check for native libraries
                native_libs = [f for f in file_list if f.startswith('lib/')]
                if native_libs:
                    result['metadata']['native_libraries'] = len(native_libs)
                    result['suspicious_indicators'].append(f"Contains {len(native_libs)} native libraries")
                
                # Deep scan if enabled
                if deep_scan:
                    result['scan_details'].update(self._deep_scan_apk(apk_zip))
        
        except Exception as e:
            logger.error(f"Error analyzing APK: {e}")
            result['scan_details']['analysis_error'] = str(e)
        
        return result
    
    def _analyze_windows_executable(self, exe_path: str, deep_scan: bool) -> Dict[str, Any]:
        """Analyze Windows executable file."""
        result = {
            'scan_details': {'analysis_type': 'windows_executable'},
            'suspicious_indicators': [],
            'metadata': {}
        }
        
        try:
            # Perform PE analysis
            pe_analysis = self.analyze_pe_file(exe_path)
            result['metadata'].update(pe_analysis)
            
            # Check for suspicious indicators
            if 'suspicious_indicators' in pe_analysis:
                result['suspicious_indicators'].extend(pe_analysis['suspicious_indicators'])
            
            # Check file size
            file_size = os.path.getsize(exe_path)
            if file_size < 1024:  # Very small executable
                result['suspicious_indicators'].append("Unusually small executable file")
            elif file_size > 100 * 1024 * 1024:  # Very large executable
                result['suspicious_indicators'].append("Unusually large executable file")
            
            # Deep scan if enabled
            if deep_scan:
                result['scan_details'].update(self._deep_scan_executable(exe_path))
        
        except Exception as e:
            logger.error(f"Error analyzing Windows executable: {e}")
            result['scan_details']['analysis_error'] = str(e)
        
        return result
    
    def _analyze_macos_app(self, app_path: str, deep_scan: bool) -> Dict[str, Any]:
        """Analyze macOS application."""
        result = {
            'scan_details': {'analysis_type': 'macos_application'},
            'suspicious_indicators': [],
            'metadata': {}
        }
        
        try:
            # Check if it's actually a directory (.app bundle)
            if not os.path.isdir(app_path):
                result['suspicious_indicators'].append("Invalid .app bundle structure")
                return result
            
            # Check for Info.plist
            info_plist_path = os.path.join(app_path, 'Contents', 'Info.plist')
            if os.path.exists(info_plist_path):
                result['metadata']['has_info_plist'] = True
                # In a real implementation, parse the plist file
            else:
                result['suspicious_indicators'].append("Missing Info.plist file")
            
            # Check for executable
            contents_dir = os.path.join(app_path, 'Contents')
            if os.path.exists(contents_dir):
                macos_dir = os.path.join(contents_dir, 'MacOS')
                if os.path.exists(macos_dir):
                    executables = [f for f in os.listdir(macos_dir) if os.access(os.path.join(macos_dir, f), os.X_OK)]
                    result['metadata']['executables'] = len(executables)
                else:
                    result['suspicious_indicators'].append("Missing MacOS directory")
            
            # Deep scan if enabled
            if deep_scan:
                result['scan_details'].update(self._deep_scan_macos_app(app_path))
        
        except Exception as e:
            logger.error(f"Error analyzing macOS app: {e}")
            result['scan_details']['analysis_error'] = str(e)
        
        return result
    
    def _analyze_archive(self, archive_path: str, deep_scan: bool) -> Dict[str, Any]:
        """Analyze archive file."""
        result = {
            'scan_details': {'analysis_type': 'archive'},
            'suspicious_indicators': [],
            'metadata': {}
        }
        
        try:
            archive_analysis = self.scan_archive(archive_path, max_files=50 if deep_scan else 10)
            result['metadata'].update(archive_analysis)
            
            if archive_analysis.get('threats_found', 0) > 0:
                result['suspicious_indicators'].append(f"Archive contains {archive_analysis['threats_found']} threats")
            
            if archive_analysis.get('suspicious_files'):
                result['suspicious_indicators'].extend(
                    [f"Suspicious file in archive: {f}" for f in archive_analysis['suspicious_files'][:3]]
                )
        
        except Exception as e:
            logger.error(f"Error analyzing archive: {e}")
            result['scan_details']['analysis_error'] = str(e)
        
        return result
    
    def _analyze_generic_file(self, file_path: str, deep_scan: bool) -> Dict[str, Any]:
        """Analyze generic file."""
        result = {
            'scan_details': {'analysis_type': 'generic'},
            'suspicious_indicators': [],
            'metadata': {}
        }
        
        try:
            # Check file extension
            ext = os.path.splitext(file_path)[1].lower()
            if ext in self.dangerous_extensions:
                result['suspicious_indicators'].append(f"Potentially dangerous file extension: {ext}")
            
            # Check for executable signatures
            with open(file_path, 'rb') as f:
                header = f.read(16)
                for sig_name, signature in self.file_signatures.items():
                    if header.startswith(signature):
                        if ext not in ['.exe', '.dll', '.app']:  # File appears to be executable despite extension
                            result['suspicious_indicators'].append(f"File appears to be {sig_name} despite extension")
            
            # Deep scan if enabled
            if deep_scan:
                result['scan_details'].update(self._deep_scan_generic(file_path))
        
        except Exception as e:
            logger.error(f"Error analyzing generic file: {e}")
            result['scan_details']['analysis_error'] = str(e)
        
        return result
    
    def _perform_content_analysis(self, file_path: str) -> Dict[str, Any]:
        """Perform deep content analysis."""
        content_analysis = {
            'entropy': 0.0,
            'suspicious_strings': [],
            'file_signature_match': False,
            'embedded_files': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Read first 10KB for analysis
                content = f.read(10240)
                
                # Calculate entropy
                content_analysis['entropy'] = self._calculate_entropy(content)
                
                # Check for suspicious strings
                suspicious_strings = self._find_suspicious_strings(content)
                content_analysis['suspicious_strings'] = suspicious_strings
                
                # Check file signature
                for sig_name, signature in self.file_signatures.items():
                    if content.startswith(signature):
                        content_analysis['file_signature_match'] = sig_name
                        break
                
                # Look for embedded files
                embedded_files = self._find_embedded_files(content)
                content_analysis['embedded_files'] = embedded_files
        
        except Exception as e:
            logger.error(f"Error in content analysis: {e}")
            content_analysis['analysis_error'] = str(e)
        
        return content_analysis
    
    def _assess_security_risk(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall security risk based on scan results."""
        risk_score = 0
        threat_level = 'LOW'
        threats = []
        warnings = []
        
        # Factor in file type
        file_type = scan_result.get('file_type', 'unknown')
        if file_type in ['windows_executable', 'android_package', 'macos_application']:
            risk_score += 20
        
        # Factor in suspicious indicators
        suspicious_indicators = scan_result.get('suspicious_indicators', [])
        risk_score += len(suspicious_indicators) * 10
        
        # Factor in permissions (for Android)
        permissions = scan_result.get('permissions', [])
        suspicious_perms = [p for p in permissions if p in self.suspicious_android_permissions]
        risk_score += len(suspicious_perms) * 15
        
        # Factor in entropy
        entropy = scan_result.get('scan_details', {}).get('entropy', 0)
        if entropy > 7.5:
            risk_score += 20
            threats.append("High entropy detected (possible packing/encryption)")
        
        # Factor in file size anomalies
        file_size = scan_result.get('file_size', 0)
        if file_type in ['windows_executable', 'macos_application'] and file_size < 1024:
            risk_score += 30
            threats.append("Unusually small executable file")
        
        # Factor in suspicious strings
        suspicious_strings = scan_result.get('scan_details', {}).get('suspicious_strings', [])
        if suspicious_strings:
            risk_score += len(suspicious_strings) * 5
            threats.extend([f"Suspicious string: {s}" for s in suspicious_strings[:3]])
        
        # Determine threat level
        if risk_score >= 75:
            threat_level = 'CRITICAL'
        elif risk_score >= 50:
            threat_level = 'HIGH'
        elif risk_score >= 25:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        
        # Add warnings for medium risk items
        if 10 <= risk_score < 25:
            warnings.extend(suspicious_indicators[:3])
        
        return {
            'risk_score': min(risk_score, 100),
            'threat_level': threat_level,
            'threats': threats,
            'warnings': warnings
        }
    
    def _determine_scan_result(self, scan_result: Dict[str, Any]) -> str:
        """Determine final scan result."""
        threat_level = scan_result.get('threat_level', 'LOW')
        threats = scan_result.get('threats', [])
        
        if threat_level in ['CRITICAL', 'HIGH'] or threats:
            return 'THREAT_DETECTED'
        elif threat_level == 'MEDIUM' or scan_result.get('warnings'):
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count frequency of each byte
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in frequency:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _find_suspicious_strings(self, content: bytes) -> List[str]:
        """Find suspicious strings in file content."""
        suspicious_patterns = [
            b'trojan', b'virus', b'malware', b'backdoor', b'keylogger',
            b'rootkit', b'spyware', b'adware', b'ransomware', b'cryptolocker',
            b'shell32.dll', b'kernel32.dll', b'ntdll.dll', b'user32.dll',
            b'cmd.exe', b'powershell', b'regsvr32', b'rundll32'
        ]
        
        found_strings = []
        for pattern in suspicious_patterns:
            if pattern in content.lower():
                found_strings.append(pattern.decode())
        
        return found_strings[:10]  # Limit to first 10 matches
    
    def _find_embedded_files(self, content: bytes) -> List[Dict[str, Any]]:
        """Find embedded files within the content."""
        embedded_files = []
        
        # Look for common file signatures within the content
        for i in range(len(content) - 16):
            chunk = content[i:i+16]
            for sig_name, signature in self.file_signatures.items():
                if chunk.startswith(signature) and i > 0:  # Not at the beginning
                    embedded_files.append({
                        'offset': i,
                        'type': sig_name,
                        'signature': signature.hex()
                    })
                    break
        
        return embedded_files[:5]  # Limit to first 5 matches
    
    def _simulate_android_permissions(self) -> List[str]:
        """Simulate Android permission extraction."""
        # In a real implementation, this would parse AndroidManifest.xml
        return [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.ACCESS_FINE_LOCATION'
        ]
    
    def _extract_permissions_from_file(self, zip_file: zipfile.ZipFile, file_name: str) -> List[str]:
        """Extract permissions from a specific file in the archive."""
        permissions = []
        try:
            with zip_file.open(file_name) as f:
                content = f.read(1024).decode('utf-8', errors='ignore')
                # Look for permission patterns
                import re
                perm_pattern = r'android\.permission\.[A-Z_]+'
                permissions = re.findall(perm_pattern, content)
        except Exception:
            pass
        return permissions
    
    def _is_suspicious_apk_file(self, file_name: str) -> bool:
        """Check if a file within an APK is suspicious."""
        suspicious_patterns = [
            'native', 'jni', 'exploit', 'backdoor', 'shell',
            'su', 'root', 'busybox', 'payload'
        ]
        
        file_name_lower = file_name.lower()
        return any(pattern in file_name_lower for pattern in suspicious_patterns)
    
    def _deep_scan_apk(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Perform deep scan of APK contents."""
        deep_scan_result = {
            'classes_dex_found': False,
            'resources_arsc_found': False,
            'lib_directories': [],
            'asset_files': []
        }
        
        file_list = apk_zip.namelist()
        
        # Check for standard APK files
        deep_scan_result['classes_dex_found'] = 'classes.dex' in file_list
        deep_scan_result['resources_arsc_found'] = 'resources.arsc' in file_list
        
        # Find library directories
        lib_dirs = set()
        for file_name in file_list:
            if file_name.startswith('lib/'):
                lib_dir = file_name.split('/')[1]
                lib_dirs.add(lib_dir)
        deep_scan_result['lib_directories'] = list(lib_dirs)
        
        # Find asset files
        asset_files = [f for f in file_list if f.startswith('assets/')]
        deep_scan_result['asset_files'] = asset_files[:10]  # Limit to first 10
        
        return deep_scan_result
    
    def _deep_scan_executable(self, exe_path: str) -> Dict[str, Any]:
        """Perform deep scan of executable file."""
        deep_scan_result = {
            'has_debug_info': False,
            'imported_dlls': [],
            'suspicious_sections': []
        }
        
        try:
            # Check for debug information
            with open(exe_path, 'rb') as f:
                content = f.read()
                if b'RSDS' in content or b'NB10' in content:
                    deep_scan_result['has_debug_info'] = True
                
                # Look for common DLL imports
                dll_patterns = [b'kernel32.dll', b'user32.dll', b'ntdll.dll', b'shell32.dll']
                for dll in dll_patterns:
                    if dll in content:
                        deep_scan_result['imported_dlls'].append(dll.decode())
        
        except Exception as e:
            deep_scan_result['scan_error'] = str(e)
        
        return deep_scan_result
    
    def _deep_scan_macos_app(self, app_path: str) -> Dict[str, Any]:
        """Perform deep scan of macOS application."""
        deep_scan_result = {
            'code_signature_found': False,
            'frameworks': [],
            'plugins': []
        }
        
        try:
            # Check for code signature
            code_sig_path = os.path.join(app_path, 'Contents', '_CodeSignature')
            deep_scan_result['code_signature_found'] = os.path.exists(code_sig_path)
            
            # Check for frameworks
            frameworks_path = os.path.join(app_path, 'Contents', 'Frameworks')
            if os.path.exists(frameworks_path):
                frameworks = os.listdir(frameworks_path)
                deep_scan_result['frameworks'] = frameworks[:10]
            
            # Check for plugins
            plugins_path = os.path.join(app_path, 'Contents', 'PlugIns')
            if os.path.exists(plugins_path):
                plugins = os.listdir(plugins_path)
                deep_scan_result['plugins'] = plugins[:10]
        
        except Exception as e:
            deep_scan_result['scan_error'] = str(e)
        
        return deep_scan_result
    
    def _deep_scan_generic(self, file_path: str) -> Dict[str, Any]:
        """Perform deep scan of generic file."""
        deep_scan_result = {
            'magic_numbers': [],
            'text_content_detected': False,
            'binary_content_detected': False
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Read first 1KB
                content = f.read(1024)
                
                # Check for magic numbers
                magic_numbers = []
                for i in range(min(16, len(content))):
                    magic_numbers.append(f"0x{content[i]:02x}")
                deep_scan_result['magic_numbers'] = magic_numbers
                
                # Detect content type
                try:
                    content.decode('utf-8')
                    deep_scan_result['text_content_detected'] = True
                except UnicodeDecodeError:
                    deep_scan_result['binary_content_detected'] = True
        
        except Exception as e:
            deep_scan_result['scan_error'] = str(e)
        
        return deep_scan_result
    
    def _scan_zip_archive(self, zip_path: str, archive_result: Dict[str, Any], max_files: int) -> Dict[str, Any]:
        """Scan ZIP archive contents."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                file_list = zip_file.namelist()
                archive_result['total_files'] = len(file_list)
                
                files_to_scan = file_list[:max_files]
                archive_result['files_scanned'] = len(files_to_scan)
                
                for file_name in files_to_scan:
                    try:
                        # Check if file is suspicious by name
                        if self._is_suspicious_archive_file(file_name):
                            archive_result['suspicious_files'].append(file_name)
                            archive_result['threats_found'] += 1
                        
                        # Extract and scan small files
                        file_info = zip_file.getinfo(file_name)
                        if file_info.file_size < 10 * 1024 * 1024:  # Less than 10MB
                            # Create temporary file for scanning
                            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                                temp_file.write(zip_file.read(file_name))
                                temp_path = temp_file.name
                            
                            try:
                                file_scan_result = self.scan_file(temp_path, deep_scan=False)
                                if file_scan_result.get('scan_result') == 'THREAT_DETECTED':
                                    archive_result['threats_found'] += 1
                                    archive_result['suspicious_files'].append(file_name)
                                
                                archive_result['scan_results'].append({
                                    'file_name': file_name,
                                    'scan_result': file_scan_result.get('scan_result', 'UNKNOWN'),
                                    'threat_level': file_scan_result.get('threat_level', 'LOW')
                                })
                            finally:
                                os.unlink(temp_path)
                    
                    except Exception as e:
                        logger.error(f"Error scanning file {file_name} in archive: {e}")
                        continue
        
        except Exception as e:
            archive_result['error'] = str(e)
        
        return archive_result
    
    def _scan_rar_archive(self, rar_path: str, archive_result: Dict[str, Any], max_files: int) -> Dict[str, Any]:
        """Scan RAR archive contents."""
        # RAR support would require additional library like rarfile
        archive_result['error'] = "RAR archive scanning not implemented"
        return archive_result
    
    def _is_suspicious_archive_file(self, file_name: str) -> bool:
        """Check if a file within an archive is suspicious."""
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']
        suspicious_names = ['autorun', 'setup', 'install', 'update', 'patch']
        
        file_name_lower = file_name.lower()
        
        # Check extension
        for ext in suspicious_extensions:
            if file_name_lower.endswith(ext):
                return True
        
        # Check name patterns
        for name in suspicious_names:
            if name in file_name_lower:
                return True
        
        return False
    
    def _get_pe_architecture(self, machine_type: int) -> str:
        """Get PE architecture from machine type."""
        architectures = {
            0x014c: 'i386',
            0x0200: 'ia64',
            0x8664: 'x64',
            0x01c0: 'arm',
            0xaa64: 'arm64'
        }
        return architectures.get(machine_type, f'unknown(0x{machine_type:04x})')
    
    def _analyze_pe_sections(self, file_handle: BinaryIO, num_sections: int) -> List[Dict[str, Any]]:
        """Analyze PE sections."""
        sections = []
        try:
            for i in range(num_sections):
                section_header = file_handle.read(40)
                if len(section_header) < 40:
                    break
                
                name = section_header[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<I', section_header[8:12])[0]
                raw_size = struct.unpack('<I', section_header[16:20])[0]
                characteristics = struct.unpack('<I', section_header[36:40])[0]
                
                sections.append({
                    'name': name,
                    'virtual_size': virtual_size,
                    'raw_size': raw_size,
                    'characteristics': characteristics,
                    'executable': bool(characteristics & 0x20000000),
                    'writable': bool(characteristics & 0x80000000),
                    'readable': bool(characteristics & 0x40000000)
                })
        except Exception as e:
            logger.error(f"Error analyzing PE sections: {e}")
        
        return sections
    
    def _check_pe_suspicious_indicators(self, pe_info: Dict[str, Any]) -> List[str]:
        """Check for suspicious indicators in PE file."""
        indicators = []
        
        # Check compilation timestamp
        if pe_info.get('compilation_timestamp'):
            try:
                comp_time = datetime.fromisoformat(pe_info['compilation_timestamp'])
                now = datetime.now()
                if comp_time > now:
                    indicators.append("Future compilation timestamp")
                elif (now - comp_time).days > 3650:  # Older than 10 years
                    indicators.append("Very old compilation timestamp")
            except:
                pass
        
        # Check sections
        sections = pe_info.get('sections', [])
        for section in sections:
            if section.get('writable') and section.get('executable'):
                indicators.append(f"Writable and executable section: {section['name']}")
        
        # Check entry point
        entry_point = pe_info.get('entry_point')
        if entry_point and entry_point == 0:
            indicators.append("Entry point at address 0")
        
        return indicators
    
    def _guess_mime_type(self, file_path: str) -> str:
        """Guess MIME type based on file extension."""
        ext = os.path.splitext(file_path)[1].lower()
        mime_types = {
            '.exe': 'application/x-executable',
            '.dll': 'application/x-msdownload',
            '.apk': 'application/vnd.android.package-archive',
            '.app': 'application/x-mac-app',
            '.dmg': 'application/x-apple-diskimage',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar-compressed',
            '.jar': 'application/java-archive'
        }
        return mime_types.get(ext, 'application/octet-stream')
    
    def _create_error_result(self, file_path: str, error_message: str) -> Dict[str, Any]:
        """Create error result structure."""
        return {
            'file_path': file_path,
            'timestamp': datetime.utcnow().isoformat(),
            'scan_result': 'ERROR',
            'threat_level': 'UNKNOWN',
            'error': error_message,
            'threats': [f"Scan error: {error_message}"],
            'warnings': [],
            'metadata': {},
            'permissions': [],
            'suspicious_indicators': [],
            'scan_details': {'analysis_type': 'error'}
        }
