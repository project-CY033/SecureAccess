import threading
import time
import logging
from datetime import datetime
from monitors.system_monitor import SystemMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.browser_monitor import BrowserMonitor
from monitors.app_scanner import ApplicationScanner

logger = logging.getLogger(__name__)

class BackgroundMonitoringService:
    def __init__(self, socketio):
        self.socketio = socketio
        self.system_monitor = SystemMonitor()
        self.network_monitor = NetworkMonitor()
        self.browser_monitor = BrowserMonitor()
        self.app_scanner = ApplicationScanner()
        self.monitoring = False
        self.threads = []
    
    def start_monitoring(self):
        """Start all background monitoring services"""
        if self.monitoring:
            return
        
        self.monitoring = True
        logger.info("Starting background monitoring services...")
        
        # Start system monitoring thread
        system_thread = threading.Thread(target=self._system_monitoring_loop, daemon=True)
        system_thread.start()
        self.threads.append(system_thread)
        
        # Start network monitoring thread
        network_thread = threading.Thread(target=self._network_monitoring_loop, daemon=True)
        network_thread.start()
        self.threads.append(network_thread)
        
        logger.info("Background monitoring services started")
    
    def stop_monitoring(self):
        """Stop all background monitoring services"""
        self.monitoring = False
        logger.info("Stopping background monitoring services...")
    
    def _system_monitoring_loop(self):
        """Background loop for system monitoring"""
        while self.monitoring:
            try:
                # Get system metrics
                metrics = self.system_monitor.get_system_metrics()
                if metrics:
                    # Save to database
                    self.system_monitor.save_metrics(metrics)
                    
                    # Emit to connected clients
                    self.socketio.emit('system_metrics', metrics)
                
                # Get process information
                processes = self.system_monitor.get_process_info()
                if processes:
                    self.socketio.emit('process_info', {'processes': processes})
                
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in system monitoring loop: {e}")
                time.sleep(10)  # Wait longer on error
    
    def _network_monitoring_loop(self):
        """Background loop for network monitoring"""
        while self.monitoring:
            try:
                # Get network connections
                connections = self.network_monitor.get_network_connections()
                if connections:
                    # Emit to connected clients
                    self.socketio.emit('network_connections', {'connections': connections})
                
                # Get network stats
                network_stats = self.network_monitor.get_network_stats()
                if network_stats:
                    self.socketio.emit('network_stats', network_stats)
                
                time.sleep(10)  # Update every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in network monitoring loop: {e}")
                time.sleep(15)  # Wait longer on error

# Global service instance
background_service = None

def start_background_monitoring(socketio):
    """Initialize and start background monitoring service"""
    global background_service
    
    if background_service is None:
        background_service = BackgroundMonitoringService(socketio)
    
    # Start monitoring in a separate thread to avoid blocking
    def start_service():
        time.sleep(2)  # Wait for app to fully initialize
        background_service.start_monitoring()
    
    thread = threading.Thread(target=start_service, daemon=True)
    thread.start()

def get_background_service():
    """Get the background service instance"""
    return background_service
