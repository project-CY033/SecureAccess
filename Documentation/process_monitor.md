# Process Monitor Documentation

## Overview
The Process Monitor provides comprehensive real-time tracking of system processes, including CPU and memory usage, process relationships, security analysis, and the ability to terminate suspicious or malicious processes.

## Algorithm & Workflow

### Process Analysis Algorithm
```
1. Enumerate all running processes
2. Collect process metadata (PID, name, user, etc.)
3. Gather resource usage statistics
4. Analyze process behavior patterns
5. Check process signatures and reputation
6. Identify parent-child relationships
7. Detect suspicious process activities
8. Calculate threat scores
9. Generate security assessments
10. Provide termination recommendations
```

### Workflow Diagram
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│Process Discovery│────│ Behavior Analysis│────│Security Scoring │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Resource Monitor│    │ Signature Check  │    │ Threat Detection│
│ Memory Tracking │    │ Hash Validation  │    │ Anomaly Analysis│
│ CPU Utilization │    │ Binary Analysis  │    │ Risk Assessment │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Process Management Interface                  │
│  Process Table • Resource Charts • Security Actions           │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Process Enumeration
- **Active Processes**: Complete list of running processes
- **Process Hierarchy**: Parent-child process relationships
- **User Context**: Process ownership and permissions
- **Command Lines**: Full command line arguments

### 2. Resource Monitoring
- **CPU Usage**: Per-process CPU utilization
- **Memory Consumption**: Physical and virtual memory usage
- **File Handles**: Open file descriptors
- **Network Connections**: Process-associated network activity

### 3. Security Analysis
- **Behavioral Patterns**: Unusual process behavior detection
- **Digital Signatures**: Verification of process authenticity
- **Hash Analysis**: File integrity checking
- **Reputation Scoring**: Process trustworthiness assessment

## Implementation Details

### Backend Functions (monitor.py)
```python
def get_processes():
    """Comprehensive process information collection"""
    processes = []
    suspicious_count = 0
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info', 'create_time', 'status']):
        try:
            process_info = proc.info
            
            # Enhance with security analysis
            security_analysis = analyze_process_security(proc)
            process_info['security'] = security_analysis
            
            if security_analysis['is_suspicious']:
                suspicious_count += 1
            
            processes.append(process_info)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return {
        'processes': processes,
        'total_processes': len(processes),
        'suspicious_count': suspicious_count,
        'timestamp': datetime.now().isoformat()
    }

def analyze_process_security(process):
    """Analyze process for security threats"""
    security_analysis = {
        'is_suspicious': False,
        'threat_level': 'low',
        'indicators': [],
        'recommendation': 'monitor'
    }
    
    try:
        # Check process name patterns
        suspicious_names = ['keylogger', 'trojan', 'backdoor', 'malware']
        if any(name in process.name().lower() for name in suspicious_names):
            security_analysis['is_suspicious'] = True
            security_analysis['threat_level'] = 'high'
            security_analysis['indicators'].append('Suspicious process name')
        
        # Check CPU usage patterns
        if process.cpu_percent() > 80:
            security_analysis['indicators'].append('High CPU usage')
        
        # Check memory usage
        memory_mb = process.memory_info().rss / 1024 / 1024
        if memory_mb > 500:
            security_analysis['indicators'].append('High memory usage')
        
        # Check process location
        try:
            exe_path = process.exe()
            if not exe_path.startswith(('/usr/', '/bin/', '/sbin/', 'C:\\Program Files', 'C:\\Windows')):
                security_analysis['indicators'].append('Unusual execution location')
        except:
            security_analysis['indicators'].append('Cannot access executable path')
        
        # Determine overall threat level
        if len(security_analysis['indicators']) >= 3:
            security_analysis['threat_level'] = 'high'
            security_analysis['recommendation'] = 'terminate'
        elif len(security_analysis['indicators']) >= 1:
            security_analysis['threat_level'] = 'medium'
            security_analysis['recommendation'] = 'investigate'
    
    except Exception as e:
        security_analysis['error'] = str(e)
    
    return security_analysis

def terminate_process(pid):
    """Safely terminate a process"""
    try:
        process = psutil.Process(pid)
        process_name = process.name()
        
        # Try graceful termination first
        process.terminate()
        
        # Wait for process to terminate
        try:
            process.wait(timeout=5)
        except psutil.TimeoutExpired:
            # Force kill if graceful termination fails
            process.kill()
        
        return {
            'success': True,
            'message': f'Process {process_name} (PID: {pid}) terminated successfully',
            'method': 'terminated'
        }
    
    except psutil.NoSuchProcess:
        return {'success': False, 'error': 'Process not found'}
    except psutil.AccessDenied:
        return {'success': False, 'error': 'Access denied - insufficient privileges'}
    except Exception as e:
        return {'success': False, 'error': str(e)}
```

## Security Analysis Framework

### 1. Behavioral Analysis
- **Resource Consumption Patterns**: Identify processes consuming excessive resources
- **Network Activity Correlation**: Link processes to suspicious network connections
- **File System Activity**: Monitor file access patterns for malicious behavior
- **Registry Modifications**: Track Windows registry changes (Windows systems)

### 2. Signature Verification
- **Digital Certificate Validation**: Verify process authenticity through digital signatures
- **Hash-based Detection**: Compare process hashes against known malware databases
- **Code Injection Detection**: Identify processes with injected malicious code
- **Packing Analysis**: Detect packed or obfuscated executables

### 3. Threat Scoring Algorithm
```python
def calculate_threat_score(process_data):
    score = 0
    
    # Baseline scoring factors
    if process_data['cpu_usage'] > 50:
        score += 20
    
    if process_data['memory_usage'] > 100:  # MB
        score += 15
    
    if not process_data['has_valid_signature']:
        score += 30
    
    if process_data['network_connections'] > 10:
        score += 25
    
    if process_data['location_suspicious']:
        score += 40
    
    # Determine threat level
    if score >= 70:
        return 'critical'
    elif score >= 40:
        return 'high'
    elif score >= 20:
        return 'medium'
    else:
        return 'low'
```

## Process Management Features

### 1. Process Filtering and Search
- **Name-based Filtering**: Filter processes by executable name
- **User-based Filtering**: Show processes for specific users
- **Resource-based Filtering**: Filter by CPU or memory usage
- **Security-based Filtering**: Show only suspicious processes

### 2. Process Details View
- **Extended Information**: Command line, environment variables, working directory
- **Resource History**: Historical CPU and memory usage charts
- **Network Connections**: Associated network connections and ports
- **File Operations**: Recently accessed files and directories

### 3. Bulk Operations
- **Mass Termination**: Terminate multiple suspicious processes
- **Process Grouping**: Group related processes for collective actions
- **Whitelisting**: Mark trusted processes to reduce false positives
- **Automated Responses**: Configure automatic actions for threat detection

## Real-time Monitoring Capabilities

### 1. Live Process Updates
- **Real-time Refresh**: Process list updates every 2-3 seconds
- **Change Highlighting**: Visual indicators for new or terminated processes
- **Resource Trending**: Live charts showing resource usage trends
- **Alert Integration**: Immediate notifications for critical processes

### 2. Performance Impact Monitoring
- **System Load Analysis**: Track overall system impact of process monitoring
- **Monitoring Overhead**: Measure resource consumption of monitoring itself
- **Optimization Recommendations**: Suggest monitoring interval adjustments
- **Baseline Establishment**: Learn normal system behavior patterns

## Security Response Actions

### 1. Immediate Response
- **Process Termination**: Immediate stopping of malicious processes
- **Network Isolation**: Block network access for suspicious processes
- **File Quarantine**: Isolate executable files for analysis
- **Memory Dumping**: Capture process memory for forensic analysis

### 2. Forensic Capabilities
- **Process Timeline**: Track process creation and termination history
- **Parent-Child Mapping**: Visualize process relationship hierarchies
- **Execution Context**: Capture environmental conditions during process execution
- **Evidence Collection**: Gather data for security incident analysis

## Usage Guidelines

### Monitoring Best Practices
1. Regular review of process lists for anomalies
2. Investigation of high-resource consumption processes
3. Verification of unknown or suspicious process names
4. Monitoring of processes with network activity

### Termination Decisions
- Verify process necessity before termination
- Check for system-critical processes
- Consider graceful shutdown options
- Document termination actions for audit trails

### Performance Considerations
- Balance monitoring frequency with system performance
- Adjust monitoring scope based on system capabilities
- Configure appropriate alert thresholds
- Implement efficient filtering to reduce noise
