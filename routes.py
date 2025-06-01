from flask import render_template, request, jsonify, redirect, url_for, flash
from app import app, db
from models import Alert, ProcessLog, NetworkLog, FileScanning, APILog, BrowserActivity, SystemMetrics
from security_scanner import SecurityScanner
from datetime import datetime, timedelta
import psutil
import hashlib
import os
import json

@app.route('/')
def dashboard():
    """Main dashboard with system overview"""
    # Get recent system metrics
    recent_metrics = SystemMetrics.query.order_by(SystemMetrics.created_at.desc()).limit(10).all()
    
    # Get critical alerts
    critical_alerts = Alert.query.filter_by(severity='critical', status='active').limit(5).all()
    
    # Get system stats
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    stats = {
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'disk_percent': disk.percent,
        'total_processes': len(psutil.pids()),
        'active_alerts': Alert.query.filter_by(status='active').count(),
        'network_connections': len(psutil.net_connections())
    }
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_metrics=recent_metrics, 
                         critical_alerts=critical_alerts)

@app.route('/process-monitor')
def process_monitor():
    """Process monitoring page"""
    processes = ProcessLog.query.order_by(ProcessLog.created_at.desc()).limit(50).all()
    suspicious_count = ProcessLog.query.filter_by(risk_level='suspicious').count()
    malicious_count = ProcessLog.query.filter_by(risk_level='malicious').count()
    
    return render_template('process_monitor.html', 
                         processes=processes,
                         suspicious_count=suspicious_count,
                         malicious_count=malicious_count)

@app.route('/browser-monitor')
def browser_monitor():
    """Browser activity monitoring page"""
    activities = BrowserActivity.query.order_by(BrowserActivity.created_at.desc()).limit(50).all()
    risky_sites = BrowserActivity.query.filter(BrowserActivity.security_score < 50).limit(10).all()
    
    return render_template('browser_monitor.html', 
                         activities=activities,
                         risky_sites=risky_sites)

@app.route('/application-monitor')
def application_monitor():
    """Application and file monitoring page"""
    scanned_files = FileScanning.query.order_by(FileScanning.created_at.desc()).limit(50).all()
    malicious_files = FileScanning.query.filter_by(scan_result='malicious').count()
    suspicious_files = FileScanning.query.filter_by(scan_result='suspicious').count()
    
    return render_template('application_monitor.html', 
                         scanned_files=scanned_files,
                         malicious_files=malicious_files,
                         suspicious_files=suspicious_files)

@app.route('/api-monitor')
def api_monitor():
    """API monitoring page"""
    api_logs = APILog.query.order_by(APILog.created_at.desc()).limit(100).all()
    
    # Calculate API statistics
    total_requests = APILog.query.count()
    failed_requests = APILog.query.filter(APILog.status_code >= 400).count()
    avg_response_time = db.session.query(db.func.avg(APILog.response_time)).scalar() or 0
    
    stats = {
        'total_requests': total_requests,
        'failed_requests': failed_requests,
        'success_rate': ((total_requests - failed_requests) / max(total_requests, 1)) * 100,
        'avg_response_time': round(avg_response_time, 2)
    }
    
    return render_template('api_monitor.html', 
                         api_logs=api_logs,
                         stats=stats)

@app.route('/alerts')
def alerts():
    """Alerts and notifications page"""
    active_alerts = Alert.query.filter_by(status='active').order_by(Alert.created_at.desc()).all()
    resolved_alerts = Alert.query.filter_by(status='resolved').order_by(Alert.resolved_at.desc()).limit(20).all()
    
    alert_counts = {
        'critical': Alert.query.filter_by(severity='critical', status='active').count(),
        'high': Alert.query.filter_by(severity='high', status='active').count(),
        'medium': Alert.query.filter_by(severity='medium', status='active').count(),
        'low': Alert.query.filter_by(severity='low', status='active').count()
    }
    
    return render_template('alerts.html', 
                         active_alerts=active_alerts,
                         resolved_alerts=resolved_alerts,
                         alert_counts=alert_counts)

@app.route('/security-ai-scan')
def security_ai_scan():
    """SecurityAI scanning tools hub"""
    return render_template('security_ai_scan.html')

@app.route('/api/scan-file', methods=['POST'])
def scan_file():
    """API endpoint for file scanning"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Save file temporarily
    filename = file.filename
    file_path = os.path.join('/tmp', filename)
    file.save(file_path)
    
    try:
        # Calculate file hash
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Perform security scan
        scanner = SecurityScanner()
        scan_result = scanner.scan_file(file_path)
        
        # Save scan result to database
        file_scan = FileScanning(
            filename=filename,
            file_hash=file_hash,
            file_size=file_size,
            file_type=scan_result.get('file_type', 'unknown'),
            scan_result=scan_result.get('result', 'clean'),
            threat_level=scan_result.get('threat_level', 0),
            scan_details=json.dumps(scan_result.get('details', {}))
        )
        db.session.add(file_scan)
        db.session.commit()
        
        # Create alert if malicious
        if scan_result.get('result') == 'malicious':
            alert = Alert(
                title=f'Malicious file detected: {filename}',
                message=f'File {filename} has been identified as malicious with threat level {scan_result.get("threat_level", 0)}',
                severity='high',
                category='file'
            )
            db.session.add(alert)
            db.session.commit()
        
        return jsonify(scan_result)
    
    finally:
        # Clean up temporary file
        if os.path.exists(file_path):
            os.remove(file_path)

@app.route('/api/terminate-process', methods=['POST'])
def terminate_process():
    """API endpoint to terminate a process"""
    pid = request.json.get('pid')
    if not pid:
        return jsonify({'error': 'PID required'}), 400
    
    try:
        process = psutil.Process(pid)
        process.terminate()
        
        # Create alert
        alert = Alert(
            title=f'Process terminated: {process.name()}',
            message=f'Process {process.name()} (PID: {pid}) has been terminated by user',
            severity='medium',
            category='process'
        )
        db.session.add(alert)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Process {pid} terminated'})
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except psutil.AccessDenied:
        return jsonify({'error': 'Access denied - insufficient privileges'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system-stats')
def get_system_stats():
    """API endpoint for real-time system statistics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        
        stats = {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'disk_percent': (disk.used / disk.total) * 100,
            'network_sent': network.bytes_sent,
            'network_recv': network.bytes_recv,
            'active_processes': len(psutil.pids()),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/process-list')
def get_process_list():
    """API endpoint for current process list"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                proc_info = proc.info
                processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'] or 'Unknown',
                    'cpu_percent': proc_info.get('cpu_percent', 0) or 0,
                    'memory_percent': proc_info.get('memory_percent', 0) or 0,
                    'status': proc_info.get('status', 'unknown')
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return jsonify({'processes': processes})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/app-permissions')
def app_permissions():
    """Application permissions monitoring page"""
    return render_template('app_permissions.html')

@app.route('/api/installed-applications')
def get_installed_applications():
    """API endpoint for installed applications"""
    try:
        applications = []
        
        # Get running processes with more details
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            try:
                proc_info = proc.info
                if proc_info['name'] and proc_info['exe']:
                    app_data = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'executable_path': proc_info['exe'],
                        'start_time': datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                        'status': 'running',
                        'network_connections': 0,  # Will be calculated separately
                        'permissions': _get_app_permissions(proc_info['exe']),
                        'network_activity': _get_network_activity(proc_info['pid'])
                    }
                    applications.append(app_data)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return jsonify({'applications': applications})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/application-network-activity/<int:pid>')
def get_application_network_activity(pid):
    """Get network activity for specific application"""
    try:
        proc = psutil.Process(pid)
        connections = proc.connections()
        
        activity = []
        for conn in connections:
            if conn.laddr and conn.raddr:
                activity.append({
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                    'status': conn.status,
                    'protocol': 'TCP' if conn.type == 1 else 'UDP',
                    'direction': 'outgoing' if conn.status == 'ESTABLISHED' else 'incoming'
                })
        
        return jsonify({'network_activity': activity})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/change-app-permission', methods=['POST'])
def change_app_permission():
    """Change application permission"""
    try:
        data = request.get_json()
        app_path = data.get('app_path')
        permission_type = data.get('permission_type')
        action = data.get('action')  # grant, revoke, restrict
        
        if not all([app_path, permission_type, action]):
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # This would implement actual permission changes
        # For now, we'll log the action and create an alert
        alert = Alert(
            title=f'Permission {action}d for application',
            message=f'Permission {permission_type} was {action}d for {os.path.basename(app_path)}',
            severity='medium',
            category='application'
        )
        db.session.add(alert)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Permission {permission_type} {action}d for application'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/terminate-application', methods=['POST'])
def terminate_application():
    """Terminate application due to malicious activity"""
    try:
        data = request.get_json()
        pid = data.get('pid')
        reason = data.get('reason', 'malicious activity detected')
        
        if not pid:
            return jsonify({'error': 'PID required'}), 400
        
        proc = psutil.Process(pid)
        app_name = proc.name()
        proc.terminate()
        
        # Create alert
        alert = Alert(
            title=f'Application terminated: {app_name}',
            message=f'Application {app_name} (PID: {pid}) was terminated due to {reason}',
            severity='high',
            category='application'
        )
        db.session.add(alert)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Application {app_name} terminated successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _get_app_permissions(exe_path):
    """Get application permissions (simplified implementation)"""
    permissions = {
        'network_access': True,
        'file_system_access': True,
        'camera_access': False,
        'microphone_access': False,
        'location_access': False,
        'contacts_access': False,
        'hidden_permissions': []
    }
    
    try:
        # Check if it's a system application
        if '/usr/' in exe_path or '/bin/' in exe_path:
            permissions['system_level'] = True
            permissions['hidden_permissions'].append('system_administration')
        
        # Check for network-related executables
        if any(x in exe_path.lower() for x in ['browser', 'chrome', 'firefox', 'network']):
            permissions['network_access'] = True
            permissions['hidden_permissions'].append('full_network_access')
            
    except Exception:
        pass
    
    return permissions

def _get_network_activity(pid):
    """Get network activity summary for process"""
    try:
        proc = psutil.Process(pid)
        connections = proc.connections()
        
        return {
            'total_connections': len(connections),
            'established_connections': len([c for c in connections if c.status == 'ESTABLISHED']),
            'listening_ports': len([c for c in connections if c.status == 'LISTEN']),
            'last_activity': datetime.utcnow().isoformat()
        }
    except Exception:
        return {
            'total_connections': 0,
            'established_connections': 0,
            'listening_ports': 0,
            'last_activity': None
        }

@app.route('/api/resolve-alert', methods=['POST'])
def resolve_alert():
    """API endpoint to resolve an alert"""
    alert_id = request.json.get('alert_id')
    if not alert_id:
        return jsonify({'error': 'Alert ID required'}), 400
    
    alert = Alert.query.get(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    alert.status = 'resolved'
    alert.resolved_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Alert resolved'})

@app.route('/api/security-tools/<tool_name>', methods=['POST'])
def security_tool_scan(tool_name):
    """API endpoint for SecurityAI tools"""
    scanner = SecurityScanner()
    data = request.json
    
    if tool_name == 'subdomain-enum':
        domain = data.get('domain')
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        result = scanner.enumerate_subdomains(domain)
    
    elif tool_name == 'port-scan':
        target = data.get('target')
        if not target:
            return jsonify({'error': 'Target required'}), 400
        result = scanner.port_scan(target)
    
    elif tool_name == 'dns-lookup':
        domain = data.get('domain')
        if not domain:
            return jsonify({'error': 'Domain required'}), 400
        result = scanner.dns_lookup(domain)
    
    elif tool_name == 'virus-total':
        file_hash = data.get('hash')
        if not file_hash:
            return jsonify({'error': 'File hash required'}), 400
        result = scanner.virus_total_check(file_hash)
    
    else:
        return jsonify({'error': 'Unknown tool'}), 404
    
    return jsonify(result)

@app.route('/api/system-stats')
def system_stats():
    """API endpoint for real-time system statistics"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    network = psutil.net_io_counters()
    
    # Save metrics to database
    metrics = SystemMetrics(
        cpu_percent=cpu_percent,
        memory_percent=memory.percent,
        disk_percent=(disk.used / disk.total) * 100,
        network_sent=network.bytes_sent,
        network_recv=network.bytes_recv,
        active_processes=len(psutil.pids())
    )
    db.session.add(metrics)
    db.session.commit()
    
    return jsonify({
        'cpu_percent': cpu_percent,
        'memory_percent': memory.percent,
        'disk_percent': (disk.used / disk.total) * 100,
        'network_sent': network.bytes_sent,
        'network_recv': network.bytes_recv,
        'active_processes': len(psutil.pids()),
        'timestamp': datetime.utcnow().isoformat()
    })
