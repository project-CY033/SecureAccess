import threading
import time
import psutil
import json
from datetime import datetime
from app import app, db
from models import Alert, ProcessLog, NetworkLog, SystemMetrics
import hashlib
import os

class SystemMonitor:
    def __init__(self):
        self.running = False
        self.known_processes = set()
        self.suspicious_patterns = [
            'keylogger', 'rootkit', 'trojan', 'backdoor', 'malware',
            'virus', 'worm', 'spyware', 'adware', 'cryptominer'
        ]
        
    def start(self):
        """Start all monitoring services"""
        self.running = True
        
        # Start monitoring threads
        threading.Thread(target=self._monitor_processes, daemon=True).start()
        threading.Thread(target=self._monitor_network, daemon=True).start()
        threading.Thread(target=self._monitor_system_metrics, daemon=True).start()
        threading.Thread(target=self._monitor_file_system, daemon=True).start()
        
    def stop(self):
        """Stop monitoring services"""
        self.running = False
        
    def _monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        while self.running:
            try:
                with app.app_context():
                    current_processes = set()
                    
                    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                        try:
                            proc_info = proc.info
                            if proc_info['pid'] and proc_info['name']:
                                current_processes.add(proc_info['pid'])
                                
                                # Analyze process for risk
                                risk_level = self._analyze_process_risk(proc_info['name'])
                                
                                # Save to database
                                process_log = ProcessLog(
                                    pid=proc_info['pid'],
                                    name=proc_info['name'],
                                    cpu_percent=proc_info.get('cpu_percent', 0),
                                    memory_percent=proc_info.get('memory_percent', 0),
                                    status=proc_info.get('status', 'unknown'),
                                    risk_level=risk_level
                                )
                                db.session.add(process_log)
                                
                                # Create alert for suspicious processes
                                if risk_level in ['suspicious', 'malicious']:
                                    alert = Alert(
                                        title=f"{risk_level.capitalize()} Process Detected",
                                        message=f"Process '{proc_info['name']}' (PID: {proc_info['pid']}) shows {risk_level} behavior",
                                        severity='high' if risk_level == 'malicious' else 'medium',
                                        category='process'
                                    )
                                    db.session.add(alert)
                                    
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    db.session.commit()
                    self.known_processes = current_processes
                    
            except Exception as e:
                print(f"Process monitoring error: {e}")
            
            time.sleep(5)  # Monitor every 5 seconds
    
    def _monitor_network(self):
        """Monitor network connections"""
        while self.running:
            try:
                with app.app_context():
                    connections = psutil.net_connections(kind='inet')
                    
                    for conn in connections:
                        try:
                            if conn.laddr and conn.raddr:
                                # Analyze connection for suspicious activity
                                is_suspicious = self._analyze_network_connection(conn)
                                
                                # Save to database
                                network_log = NetworkLog(
                                    connection_type='outgoing' if conn.status == 'ESTABLISHED' else 'incoming',
                                    local_address=f"{conn.laddr.ip}:{conn.laddr.port}",
                                    remote_address=f"{conn.raddr.ip}:{conn.raddr.port}",
                                    port=conn.raddr.port,
                                    protocol='TCP',
                                    status=conn.status,
                                    bytes_sent=0,
                                    bytes_recv=0
                                )
                                db.session.add(network_log)
                                
                                # Create alert for suspicious connections
                                if is_suspicious:
                                    alert = Alert(
                                        title="Suspicious Network Activity",
                                        message=f"Suspicious connection to {conn.raddr.ip}:{conn.raddr.port}",
                                        severity='medium',
                                        category='network'
                                    )
                                    db.session.add(alert)
                                    
                        except Exception:
                            continue
                    
                    db.session.commit()
                    
            except Exception as e:
                print(f"Network monitoring error: {e}")
            
            time.sleep(10)  # Monitor every 10 seconds
    
    def _monitor_system_metrics(self):
        """Monitor system performance metrics"""
        while self.running:
            try:
                with app.app_context():
                    cpu_percent = psutil.cpu_percent(interval=1)
                    memory = psutil.virtual_memory()
                    disk = psutil.disk_usage('/')
                    network = psutil.net_io_counters()
                    
                    # Save system metrics
                    metrics = SystemMetrics(
                        cpu_percent=cpu_percent,
                        memory_percent=memory.percent,
                        disk_percent=(disk.used / disk.total) * 100,
                        network_sent=network.bytes_sent,
                        network_recv=network.bytes_recv,
                        active_processes=len(psutil.pids())
                    )
                    db.session.add(metrics)
                    
                    # Create alerts for critical system states
                    if cpu_percent > 90:
                        alert = Alert(
                            title="High CPU Usage",
                            message=f"CPU usage is critically high: {cpu_percent:.1f}%",
                            severity='critical',
                            category='process'
                        )
                        db.session.add(alert)
                    
                    if memory.percent > 90:
                        alert = Alert(
                            title="High Memory Usage",
                            message=f"Memory usage is critically high: {memory.percent:.1f}%",
                            severity='critical',
                            category='process'
                        )
                        db.session.add(alert)
                    
                    db.session.commit()
                    
            except Exception as e:
                print(f"System metrics monitoring error: {e}")
            
            time.sleep(30)  # Monitor every 30 seconds
    
    def _monitor_file_system(self):
        """Monitor file system for suspicious activity"""
        while self.running:
            try:
                with app.app_context():
                    # Monitor common directories for changes
                    monitored_dirs = ['/tmp', '/var/tmp', os.path.expanduser('~')]
                    
                    for directory in monitored_dirs:
                        if os.path.exists(directory):
                            for root, dirs, files in os.walk(directory):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    if self._is_executable(file_path):
                                        # Create alert for new executable files
                                        alert = Alert(
                                            title="New Executable File Detected",
                                            message=f"New executable file found: {file_path}",
                                            severity='medium',
                                            category='file'
                                        )
                                        db.session.add(alert)
                                        break
                                break
                    
                    db.session.commit()
                    
            except Exception as e:
                print(f"File system monitoring error: {e}")
            
            time.sleep(60)  # Monitor every minute
    
    def _analyze_process_risk(self, process_name):
        """Analyze process for risk factors"""
        if not process_name:
            return 'safe'
            
        process_name_lower = process_name.lower()
        
        # Check for known malicious patterns
        for pattern in self.suspicious_patterns:
            if pattern in process_name_lower:
                return 'malicious'
        
        # Check for suspicious patterns
        suspicious_indicators = ['temp', 'tmp', 'unknown', 'noname', '.exe', 'svchost']
        for indicator in suspicious_indicators:
            if indicator in process_name_lower:
                return 'suspicious'
        
        return 'safe'
    
    def _analyze_network_connection(self, connection):
        """Analyze network connection for suspicious activity"""
        if not connection.raddr:
            return False
        
        # Check for connections to suspicious ports
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
        if connection.raddr.port in suspicious_ports:
            return True
        
        # Check for connections to private IP ranges from external
        remote_ip = connection.raddr.ip
        if (remote_ip.startswith('10.') or 
            remote_ip.startswith('192.168.') or 
            remote_ip.startswith('172.')):
            return False
        
        return False
    
    def _is_executable(self, file_path):
        """Check if file is executable"""
        try:
            return os.access(file_path, os.X_OK)
        except:
            return False

# Global monitor instance
monitor = SystemMonitor()

def start_background_monitoring():
    """Start background monitoring services"""
    monitor.start()

def stop_background_monitoring():
    """Stop background monitoring services"""
    monitor.stop()