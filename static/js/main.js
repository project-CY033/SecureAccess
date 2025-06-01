// CyberGuard Pro - Main JavaScript File
// Real-time monitoring and WebSocket communication

// Global variables
let socket;
let alertCount = 0;
let isConnected = false;

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeWebSocket();
    initializeToasts();
    updateCurrentTime();
    loadSidebarData();
    
    // Update time every second
    setInterval(updateCurrentTime, 1000);
    
    // Update sidebar data every 30 seconds
    setInterval(loadSidebarData, 30000);
});

// WebSocket initialization and event handlers
function initializeWebSocket() {
    try {
        socket = io();
        
        socket.on('connect', function() {
            isConnected = true;
            updateConnectionStatus(true);
            console.log('Connected to monitoring system');
            
            // Request initial data
            socket.emit('request_system_stats');
            socket.emit('request_recent_alerts');
        });
        
        socket.on('disconnect', function() {
            isConnected = false;
            updateConnectionStatus(false);
            console.log('Disconnected from monitoring system');
            
            // Try to reconnect after 5 seconds
            setTimeout(() => {
                if (!isConnected) {
                    socket.connect();
                }
            }, 5000);
        });
        
        // Real-time system statistics
        socket.on('system_stats', function(data) {
            updateSidebarStats(data);
            updateSystemMetrics(data);
        });
        
        // Real-time alerts
        socket.on('new_alert', function(data) {
            handleNewAlert(data);
            updateAlertBadges();
        });
        
        // Process updates
        socket.on('process_update', function(data) {
            updateProcessCount(data.total_processes);
        });
        
        // Network updates
        socket.on('network_update', function(data) {
            updateNetworkStatus(data);
        });
        
        // Error handling
        socket.on('error', function(data) {
            showToast('System Error: ' + data.message, 'danger');
        });
        
    } catch (error) {
        console.error('WebSocket initialization failed:', error);
        updateConnectionStatus(false);
    }
}

// Update connection status indicator
function updateConnectionStatus(connected) {
    const statusElement = document.getElementById('connection-status');
    if (statusElement) {
        if (connected) {
            statusElement.innerHTML = '<i class="fas fa-wifi"></i> Connected';
            statusElement.className = 'badge bg-success';
        } else {
            statusElement.innerHTML = '<i class="fas fa-wifi"></i> Disconnected';
            statusElement.className = 'badge bg-danger';
        }
    }
}

// Update current time display
function updateCurrentTime() {
    const timeElement = document.getElementById('current-time');
    if (timeElement) {
        const now = new Date();
        timeElement.textContent = now.toLocaleTimeString();
    }
}

// Update sidebar statistics
function updateSidebarStats(data) {
    const cpuElement = document.getElementById('sidebar-cpu');
    const memoryElement = document.getElementById('sidebar-memory');
    const networkElement = document.getElementById('sidebar-network');
    
    if (cpuElement) {
        cpuElement.textContent = Math.round(data.cpu_percent) + '%';
        cpuElement.className = data.cpu_percent > 80 ? 'fw-bold text-danger' : 
                              data.cpu_percent > 60 ? 'fw-bold text-warning' : 'fw-bold text-success';
    }
    
    if (memoryElement) {
        memoryElement.textContent = Math.round(data.memory_percent) + '%';
        memoryElement.className = data.memory_percent > 80 ? 'fw-bold text-danger' : 
                                  data.memory_percent > 60 ? 'fw-bold text-warning' : 'fw-bold text-success';
    }
    
    if (networkElement) {
        const networkConnections = data.active_processes || 0;
        networkElement.textContent = networkConnections.toString();
    }
}

// Update system metrics for dashboard
function updateSystemMetrics(data) {
    // Update CPU usage
    const cpuUsage = document.getElementById('cpu-usage');
    if (cpuUsage) {
        cpuUsage.textContent = Math.round(data.cpu_percent) + '%';
        const cpuProgress = cpuUsage.closest('.card').querySelector('.progress-bar');
        if (cpuProgress) {
            cpuProgress.style.width = data.cpu_percent + '%';
        }
    }
    
    // Update Memory usage
    const memoryUsage = document.getElementById('memory-usage');
    if (memoryUsage) {
        memoryUsage.textContent = Math.round(data.memory_percent) + '%';
        const memoryProgress = memoryUsage.closest('.card').querySelector('.progress-bar');
        if (memoryProgress) {
            memoryProgress.style.width = data.memory_percent + '%';
        }
    }
    
    // Update Process count
    const processCount = document.getElementById('process-count');
    if (processCount) {
        processCount.textContent = data.active_processes || 0;
    }
}

// Handle new alerts
function handleNewAlert(alertData) {
    alertCount++;
    
    // Add to sidebar alerts
    addToSidebarAlerts(alertData);
    
    // Show toast notification
    showToast(
        `${alertData.title}: ${alertData.message}`, 
        getSeverityClass(alertData.severity),
        8000
    );
    
    // Play notification sound if enabled
    playNotificationSound(alertData.severity);
    
    // Show desktop notification if permitted
    showDesktopNotification(alertData);
}

// Add alert to sidebar
function addToSidebarAlerts(alertData) {
    const alertsList = document.getElementById('sidebar-alerts');
    if (!alertsList) return;
    
    const alertElement = document.createElement('div');
    alertElement.className = `alert alert-${getSeverityClass(alertData.severity)} py-2 px-3 mb-2`;
    alertElement.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
            <div>
                <small class="fw-bold">${alertData.title}</small><br>
                <small>${alertData.message.substring(0, 50)}...</small>
            </div>
            <small class="text-muted">${new Date().toLocaleTimeString()}</small>
        </div>
    `;
    
    // Add to top of list
    alertsList.insertBefore(alertElement, alertsList.firstChild);
    
    // Keep only last 5 alerts
    while (alertsList.children.length > 5) {
        alertsList.removeChild(alertsList.lastChild);
    }
}

// Get CSS class for alert severity
function getSeverityClass(severity) {
    const severityClasses = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'success'
    };
    return severityClasses[severity] || 'secondary';
}

// Update alert count badges
function updateAlertBadges() {
    const alertBadges = document.querySelectorAll('#alert-count, .alert-count');
    alertBadges.forEach(badge => {
        badge.textContent = alertCount;
        if (alertCount > 0) {
            badge.classList.remove('d-none');
        }
    });
}

// Update process count
function updateProcessCount(count) {
    const processCountElements = document.querySelectorAll('#total-processes, .process-count');
    processCountElements.forEach(element => {
        element.textContent = count;
    });
}

// Update network status
function updateNetworkStatus(data) {
    const networkElements = document.querySelectorAll('.network-status');
    networkElements.forEach(element => {
        element.textContent = `${data.total_connections} connections`;
        if (data.suspicious_count > 0) {
            element.classList.add('text-warning');
        } else {
            element.classList.remove('text-warning');
        }
    });
}

// Load sidebar data
function loadSidebarData() {
    if (socket && isConnected) {
        socket.emit('request_system_stats');
        socket.emit('request_recent_alerts');
    }
}

// Toast notification system
function initializeToasts() {
    // Create toast container if it doesn't exist
    if (!document.getElementById('toast-container')) {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }
}

// Show toast notification
function showToast(message, type = 'info', duration = 5000) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toastId = 'toast-' + Date.now();
    const iconMap = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    
    const toastHTML = `
        <div id="${toastId}" class="toast align-items-center text-white bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-${iconMap[type] || 'info-circle'} me-2"></i>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;
    
    container.insertAdjacentHTML('beforeend', toastHTML);
    
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, {
        autohide: true,
        delay: duration
    });
    
    toast.show();
    
    // Remove toast element after it's hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

// Play notification sound
function playNotificationSound(severity) {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        // Different frequencies for different severities
        const frequencies = {
            'critical': 1000,
            'high': 800,
            'medium': 600,
            'low': 400
        };
        
        oscillator.frequency.value = frequencies[severity] || 500;
        oscillator.type = 'sine';
        
        gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.3);
    } catch (error) {
        console.warn('Audio notification failed:', error);
    }
}

// Desktop notification
function showDesktopNotification(alertData) {
    if ('Notification' in window && Notification.permission === 'granted') {
        const notification = new Notification(alertData.title, {
            body: alertData.message,
            icon: '/static/icons/alert.png',
            tag: 'cyberguard-alert',
            requireInteraction: alertData.severity === 'critical'
        });
        
        notification.onclick = function() {
            window.focus();
            notification.close();
        };
        
        // Auto-close after 10 seconds for non-critical alerts
        if (alertData.severity !== 'critical') {
            setTimeout(() => notification.close(), 10000);
        }
    }
}

// Request notification permission
function requestNotificationPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                showToast('Desktop notifications enabled', 'success');
            }
        });
    }
}

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hrs > 0) {
        return `${hrs}h ${mins}m ${secs}s`;
    } else if (mins > 0) {
        return `${mins}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Export functions for global access
window.CyberGuard = {
    showToast,
    formatBytes,
    formatDuration,
    formatTimestamp,
    requestNotificationPermission,
    socket: () => socket,
    isConnected: () => isConnected
};

// Initialize notification permission request
document.addEventListener('DOMContentLoaded', function() {
    // Request notification permission after 3 seconds
    setTimeout(requestNotificationPermission, 3000);
});
