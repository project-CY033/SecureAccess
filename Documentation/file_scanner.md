# File Scanner Documentation

## Overview
The File Scanner provides comprehensive malware detection, threat analysis, and security assessment for files and directories. It includes real-time scanning capabilities, signature-based detection, heuristic analysis, and integration with threat intelligence sources.

## Algorithm & Workflow

### File Analysis Algorithm
```
1. File discovery and enumeration
2. File type identification and validation
3. Hash calculation (MD5, SHA1, SHA256)
4. Signature-based malware detection
5. Heuristic behavioral analysis
6. File metadata extraction
7. Reputation checking against databases
8. Risk assessment and scoring
9. Quarantine recommendations
10. Detailed reporting generation
```

### Workflow Diagram
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ File Discovery  │────│  Hash Calculation│────│Signature Analysis│
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Type Detection  │    │ Metadata Extract │    │ Heuristic Scan  │
│ Size Validation │    │ Creation Time    │    │ Pattern Matching│
│ Access Control  │    │ Modification Log │    │ Behavior Profile│
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Threat Assessment Engine                     │
│  Risk Scoring • Quarantine Decision • Report Generation       │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. File Detection Engine
- **File Type Recognition**: Identification of executable, document, and media files
- **Magic Number Validation**: File header analysis for type verification
- **Extension Analysis**: Comparison of file extension with actual content
- **Compression Handling**: Analysis of archived and compressed files

### 2. Signature Database
- **Known Malware Signatures**: Database of malware hash signatures
- **Pattern Recognition**: Byte pattern matching for threat identification
- **Signature Updates**: Regular updates from threat intelligence sources
- **Custom Rules**: User-defined detection patterns

### 3. Heuristic Analysis
- **Behavioral Patterns**: Analysis of file behavior characteristics
- **Anomaly Detection**: Identification of unusual file properties
- **Code Analysis**: Static analysis of executable code structures
- **Entropy Calculation**: Detection of packed or encrypted content

## Implementation Details

### Backend Functions (scanner.py)
```python
def scan_file(file_path):
    """Comprehensive file security scan"""
    try:
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        
        # Basic file information
        file_info = get_file_info(file_path)
        
        # Calculate file hashes
        file_hashes = {
            'md5': calculate_file_hash(file_path, 'md5'),
            'sha1': calculate_file_hash(file_path, 'sha1'),
            'sha256': calculate_file_hash(file_path, 'sha256')
        }
        
        # Perform security analysis
        security_analysis = perform_security_scan(file_path, file_hashes)
        
        # Generate risk assessment
        risk_assessment = calculate_risk_score(file_info, security_analysis)
        
        return {
            'file_info': file_info,
            'hashes': file_hashes,
            'security': security_analysis,
            'risk': risk_assessment,
            'scan_time': datetime.now().isoformat()
        }
    
    except Exception as e:
        return {'error': str(e)}

def perform_security_scan(file_path, file_hashes):
    """Perform comprehensive security analysis"""
    analysis = {
        'is_malicious': False,
        'threat_type': 'none',
        'confidence': 0,
        'indicators': [],
        'recommendations': []
    }
    
    # Check against known malware hashes
    if check_malware_database(file_hashes['sha256']):
        analysis['is_malicious'] = True
        analysis['threat_type'] = 'known_malware'
        analysis['confidence'] = 95
        analysis['indicators'].append('Matches known malware signature')
    
    # Heuristic analysis
    heuristic_results = perform_heuristic_analysis(file_path)
    if heuristic_results['suspicious_patterns'] > 3:
        analysis['threat_type'] = 'suspicious'
        analysis['confidence'] = max(analysis['confidence'], 70)
        analysis['indicators'].extend(heuristic_results['patterns'])
    
    # File extension analysis
    extension_analysis = analyze_file_extension(file_path)
    if extension_analysis['mismatch']:
        analysis['indicators'].append('File extension mismatch')
        analysis['confidence'] += 15
    
    return analysis

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate file hash using specified algorithm"""
    hash_func = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }.get(algorithm.lower())
    
    if not hash_func:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def get_file_info(file_path):
    """Get comprehensive file information"""
    stat_info = os.stat(file_path)
    
    file_info = {
        'name': os.path.basename(file_path),
        'path': file_path,
        'size': stat_info.st_size,
        'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
        'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
        'permissions': oct(stat_info.st_mode)[-3:],
        'owner': stat_info.st_uid,
        'group': stat_info.st_gid
    }
    
    # Determine file type
    try:
        import magic
        file_info['mime_type'] = magic.from_file(file_path, mime=True)
        file_info['file_type'] = magic.from_file(file_path)
    except ImportError:
        # Fallback to extension-based detection
        extension = os.path.splitext(file_path)[1].lower()
        file_info['extension'] = extension
        file_info['file_type'] = 'Unknown'
    
    return file_info
```

  

## Threat Detection Mechanisms

### 1. Signature-Based Detection
- **Hash Matching**: Comparison against known malware hash databases
- **Byte Pattern Recognition**: Detection of specific malware byte sequences
- **YARA Rules**: Custom rule-based pattern matching
- **Fuzzy Hashing**: Detection of similar file variants

### 2. Heuristic Analysis
```python
def perform_heuristic_analysis(file_path):
    """Perform heuristic analysis on file"""
    suspicious_patterns = 0
    detected_patterns = []
    
    # Check file entropy (packed/encrypted files)
    entropy = calculate_file_entropy(file_path)
    if entropy > 7.5:
        suspicious_patterns += 1
        detected_patterns.append('High entropy - possibly packed')
    
    # Check for suspicious strings
    suspicious_strings = ['keylogger', 'backdoor', 'trojan', 'virus']
    file_content = read_file_safely(file_path, max_size=1024*1024)  # 1MB limit
    
    for string in suspicious_strings:
        if string.encode() in file_content:
            suspicious_patterns += 1
            detected_patterns.append(f'Suspicious string: {string}')
    
    # PE file analysis (Windows executables)
    if file_path.lower().endswith('.exe'):
        pe_analysis = analyze_pe_file(file_path)
        suspicious_patterns += pe_analysis['suspicious_sections']
        detected_patterns.extend(pe_analysis['warnings'])
    
    return {
        'suspicious_patterns': suspicious_patterns,
        'patterns': detected_patterns,
        'entropy': entropy
    }
```

### 3. Behavioral Analysis
- **API Call Analysis**: Detection of suspicious system calls
- **Network Behavior**: Monitoring of network-related activities
- **File System Operations**: Tracking of file creation/modification patterns
- **Registry Modifications**: Windows registry interaction analysis

## Risk Assessment Framework

### Risk Scoring Algorithm
```python
def calculate_risk_score(file_info, security_analysis):
    """Calculate comprehensive risk score"""
    risk_score = 0
    risk_factors = []
    
    # File type risk factors
    high_risk_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']
    if any(file_info['name'].lower().endswith(ext) for ext in high_risk_extensions):
        risk_score += 25
        risk_factors.append('High-risk file type')
    
    # Security analysis results
    if security_analysis['is_malicious']:
        risk_score += 50
        risk_factors.append('Malware detected')
    
    if security_analysis['confidence'] > 70:
        risk_score += 30
        risk_factors.append('High confidence threat detection')
    
    # File size anomalies
    if file_info['size'] < 1024:  # Very small executable
        risk_score += 15
        risk_factors.append('Unusually small file size')
    elif file_info['size'] > 100 * 1024 * 1024:  # Very large file
        risk_score += 10
        risk_factors.append('Unusually large file size')
    
    # Determine risk level
    if risk_score >= 70:
        risk_level = 'critical'
    elif risk_score >= 50:
        risk_level = 'high'
    elif risk_score >= 30:
        risk_level = 'medium'
    elif risk_score >= 15:
        risk_level = 'low'
    else:
        risk_level = 'minimal'
    
    return {
        'score': risk_score,
        'level': risk_level,
        'factors': risk_factors,
        'recommendation': get_risk_recommendation(risk_level)
    }

def get_risk_recommendation(risk_level):
    """Get security recommendation based on risk level"""
    recommendations = {
        'critical': 'Immediate quarantine and removal required',
        'high': 'Quarantine and further analysis recommended',
        'medium': 'Monitor closely and consider quarantine',
        'low': 'Continue monitoring, no immediate action needed',
        'minimal': 'File appears safe for normal use'
    }
    return recommendations.get(risk_level, 'Unknown risk level')
```

## Real-time Scanning Features

### 1. Live File Monitoring
- **File System Watchers**: Real-time detection of new files
- **Automatic Scanning**: Immediate analysis of newly created files
- **Background Scanning**: Continuous scanning with minimal system impact
- **Priority Queuing**: Intelligent prioritization of scanning tasks

### 2. Batch Processing
- **Directory Scanning**: Recursive scanning of entire directory trees
- **Selective Scanning**: Filtering by file type, size, or age
- **Progress Tracking**: Real-time progress reporting for large scans
- **Resume Capability**: Ability to resume interrupted scans

### 3. Performance Optimization
- **Multi-threading**: Parallel processing for improved performance
- **Resource Management**: CPU and memory usage controls
- **Scan Scheduling**: Off-peak scanning to minimize system impact
- **Caching**: Results caching to avoid redundant scans

## Integration Capabilities

### 1. External Threat Intelligence
- **VirusTotal Integration**: Submission and lookup of file hashes
- **Threat Feed Integration**: Real-time threat intelligence updates
- **Custom Databases**: Integration with organization-specific threat data
- **Community Sharing**: Contribution to collective threat intelligence

### 2. Quarantine Management
- **Secure Isolation**: Safe storage of potentially malicious files
- **Restoration Capabilities**: Ability to restore false positives
- **Encryption**: Encrypted storage of quarantined files
- **Audit Trails**: Complete logging of quarantine actions

### 3. Reporting and Analytics
- **Detailed Reports**: Comprehensive scan result documentation
- **Trend Analysis**: Historical threat detection patterns
- **Export Capabilities**: Multiple format support for report export
- **Dashboard Integration**: Real-time threat status updates

## Security Considerations

### Safe Analysis Practices
- **Sandboxed Execution**: Isolated environment for dynamic analysis
- **Limited Privileges**: Minimal system access for scanning processes
- **Timeout Controls**: Prevention of infinite analysis loops
- **Resource Limits**: CPU and memory usage restrictions

### Data Protection
- **File Privacy**: Secure handling of sensitive file content
- **Hash-only Analysis**: Option for privacy-preserving analysis
- **Secure Deletion**: Complete removal of temporary analysis files
- **Access Controls**: Restricted access to scan results and quarantine

## Usage Guidelines

### Scanning Best Practices
1. Regular full system scans for comprehensive coverage
2. Real-time monitoring for immediate threat detection
3. Targeted scans for suspicious file locations
4. Verification of scan results before taking action

### Performance Considerations
- Schedule intensive scans during low-usage periods
- Adjust scan sensitivity based on system requirements
- Monitor system resources during scanning operations
- Configure appropriate exclusions for known safe files

### Incident Response
- Immediate isolation of confirmed threats
- Documentation of all detection events
- Analysis of attack vectors and entry points
- Implementation of preventive measures
