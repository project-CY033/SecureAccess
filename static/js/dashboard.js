// CyberGuard Pro - Dashboard JavaScript
// Real-time system monitoring and security dashboard

let systemChart, networkChart;
let systemMetricsData = [];
let networkMetricsData = [];
let chartUpdateInterval;

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    startRealTimeMonitoring();
    loadDashboardData();
    setupEventListeners();
});

// Initialize Chart.js charts
function initializeCharts() {
    initializeSystemChart();
    initializeNetworkChart();
}

// Initialize system performance chart
function initializeSystemChart() {
    const ctx = document.getElementById('systemChart');
    if (!ctx) return;
    
    systemChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: generateTimeLabels(20),
            datasets: [
                {
                    label: 'CPU %',
                    data: new Array(20).fill(0),
                    borderColor: 'rgb(54, 162, 235)',
                    backgroundColor: 'rgba(54, 162, 235, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Memory %',
                    data: new Array(20).fill(0),
                    borderColor: 'rgb(255, 193, 7)',
                    backgroundColor: 'rgba(255, 193, 7, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Disk %',
                    data: new Array(20).fill(0),
                    borderColor: 'rgb(40, 167, 69)',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#fff' }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#fff',
                    bodyColor: '#fff'
                }
            },
            scales: {
                x: {
                    ticks: { color: '#fff' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                },
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: { 
                        color: '#fff',
                        callback: function(value) {
                            return value + '%';
                        }
                    },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                }
            },
            animation: {
                duration: 750,
                easing: 'easeInOutQuart'
            }
        }
    });
}

// Initialize network activity chart
function initializeNetworkChart() {
    const ctx = document.getElementById('networkChart');
    if (!ctx) return;
    
    networkChart = new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: generateTimeLabels(15),
            datasets: [
                {
                    label: 'Bytes Sent',
                    data: new Array(15).fill(0),
                    borderColor: 'rgb(220, 53, 69)',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Bytes Received',
                    data: new Array(15).fill(0),
                    borderColor: 'rgb(13, 202, 240)',
                    backgroundColor: 'rgba(13, 202, 240, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#fff' }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    callbacks: {
                        label: function(context) {
                            return context.dataset.label + ': ' + formatBytes(context.parsed.y);
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#fff' },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                },
                y: {
                    beginAtZero: true,
                    ticks: { 
                        color: '#fff',
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                }
            },
            animation: {
                duration: 500,
                easing: 'easeInOutQuart'
            }
        }
    });
}

// Generate time labels for charts
function generateTimeLabels(count) {
    const labels = [];
    const now = new Date();
    
    for (let i = count - 1; i >= 0; i--) {
        const time = new Date(now.getTime() - (i * 2000)); // 2 second intervals
        labels.push(time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'}));
    }
    
    return labels;
}

// Start real-time monitoring
function startRealTimeMonitoring() {
    // Listen for real-time system metrics
    if (typeof socket !== 'undefined' && socket) {
        socket.on('system_metrics', function(data) {
            updateSystemChart(data);
            updateNetworkChart(data);
            updateDashboardCards(data);
            updateThreatLevel(data);
        });
    }
    
    // Fallback: poll for data every 5 seconds if WebSocket unavailable
    if (!window.CyberGuard || !window.CyberGuard.isConnected()) {
        chartUpdateInterval = setInterval(fetchSystemStats, 5000);
    }
}

// Update system performance chart
function updateSystemChart(data) {
    if (!systemChart) return;
    
    const now = new Date();
    const timeLabel = now.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
    
    // Add new data point
    systemChart.data.labels.push(timeLabel);
    systemChart.data.datasets[0].data.push(data.cpu_percent);
    systemChart.data.datasets[1].data.push(data.memory_percent);
    systemChart.data.datasets[2].data.push(data.disk_percent || 0);
    
    // Remove old data points (keep last 20)
    if (systemChart.data.labels.length > 20) {
        systemChart.data.labels.shift();
        systemChart.data.datasets.forEach(dataset => dataset.data.shift());
    }
    
    systemChart.update('none'); // Update without animation for real-time feel
}

// Update network activity chart
function updateNetworkChart(data) {
    if (!networkChart) return;
    
    const now = new Date();
    const timeLabel = now.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
    
    // Calculate network throughput from previous reading
    const currentSent = data.network_sent || 0;
    const currentRecv = data.network_recv || 0;
    
    let sentThroughput = 0;
    let recvThroughput = 0;
    
    if (networkMetricsData.length > 0) {
        const lastReading = networkMetricsData[networkMetricsData.length - 1];
        const timeDiff = 2; // 2 seconds between readings
        
        sentThroughput = Math.max(0, (currentSent - lastReading.sent) / timeDiff);
        recvThroughput = Math.max(0, (currentRecv - lastReading.recv) / timeDiff);
    }
    
    // Store current reading
    networkMetricsData.push({
        timestamp: now.getTime(),
        sent: currentSent,
        recv: currentRecv
    });
    
    // Keep only last 50 readings
    if (networkMetricsData.length > 50) {
        networkMetricsData.shift();
    }
    
    // Add to chart
    networkChart.data.labels.push(timeLabel);
    networkChart.data.datasets[0].data.push(sentThroughput);
    networkChart.data.datasets[1].data.push(recvThroughput);
    
    // Remove old data points (keep last 15)
    if (networkChart.data.labels.length > 15) {
        networkChart.data.labels.shift();
        networkChart.data.datasets.forEach(dataset => dataset.data.shift());
    }
    
    networkChart.update('none');
}

// Update dashboard cards with real-time data
function updateDashboardCards(data) {
    // Update CPU usage card
    updateCardValue('cpu-usage', Math.round(data.cpu_percent) + '%', data.cpu_percent);
    
    // Update Memory usage card
    updateCardValue('memory-usage', Math.round(data.memory_percent) + '%', data.memory_percent);
    
    // Update Process count
    updateCardValue('process-count', data.active_processes || 0);
    
    // Update last scan time
    const lastScanElement = document.getElementById('last-scan');
    if (lastScanElement) {
        lastScanElement.textContent = 'Just now';
    }
}

// Update individual card value with progress bar
function updateCardValue(elementId, value, percentage = null) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value;
        
        // Update associated progress bar if exists
        if (percentage !== null) {
            const progressBar = element.closest('.card').querySelector('.progress-bar');
            if (progressBar) {
                progressBar.style.width = percentage + '%';
                
                // Update color based on percentage
                progressBar.className = 'progress-bar';
                if (percentage > 80) {
                    progressBar.classList.add('bg-danger');
                } else if (percentage > 60) {
                    progressBar.classList.add('bg-warning');
                } else {
                    progressBar.classList.add('bg-success');
                }
            }
        }
    }
}

// Update threat level indicator
function updateThreatLevel(data) {
    const threatLevelElement = document.getElementById('threat-level');
    const threatProgressElement = document.getElementById('threat-progress');
    
    if (!threatLevelElement || !threatProgressElement) return;
    
    // Calculate threat level based on system metrics
    let threatLevel = 0;
    let threatClass = 'success';
    let threatText = 'LOW';
    
    // CPU factor
    if (data.cpu_percent > 90) threatLevel += 30;
    else if (data.cpu_percent > 75) threatLevel += 20;
    else if (data.cpu_percent > 50) threatLevel += 10;
    
    // Memory factor
    if (data.memory_percent > 90) threatLevel += 25;
    else if (data.memory_percent > 75) threatLevel += 15;
    else if (data.memory_percent > 50) threatLevel += 5;
    
    // Active processes factor
    const processCount = data.active_processes || 0;
    if (processCount > 200) threatLevel += 15;
    else if (processCount > 150) threatLevel += 10;
    else if (processCount > 100) threatLevel += 5;
    
    // Determine threat level
    if (threatLevel > 60) {
        threatClass = 'danger';
        threatText = 'CRITICAL';
    } else if (threatLevel > 40) {
        threatClass = 'warning';
        threatText = 'HIGH';
    } else if (threatLevel > 20) {
        threatClass = 'info';
        threatText = 'MEDIUM';
    }
    
    // Update UI
    threatLevelElement.textContent = threatText;
    threatLevelElement.className = `badge bg-${threatClass}`;
    
    threatProgressElement.style.width = Math.min(threatLevel, 100) + '%';
    threatProgressElement.className = `progress-bar bg-${threatClass}`;
}

// Load initial dashboard data
function loadDashboardData() {
    fetchSystemStats();
    loadRecentActivity();
    updateAlertCounts();
}

// Fetch system statistics
function fetchSystemStats() {
    fetch('/api/system-stats')
        .then(response => response.json())
        .then(data => {
            updateSystemChart(data);
            updateNetworkChart(data);
            updateDashboardCards(data);
            updateThreatLevel(data);
        })
        .catch(error => {
            console.error('Error fetching system stats:', error);
            if (window.CyberGuard) {
                window.CyberGuard.showToast('Failed to fetch system statistics', 'danger');
            }
        });
}

// Load recent activity data
function loadRecentActivity() {
    const activityTable = document.getElementById('activity-table');
    if (!activityTable) return;
    
    // Clear existing rows
    activityTable.innerHTML = '';
    
    // Show loading state
    activityTable.innerHTML = `
        <tr>
            <td colspan="5" class="text-center">
                <div class="spinner-border spinner-border-sm" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                Loading recent activity...
            </td>
        </tr>
    `;
    
    // In a real implementation, this would fetch from an API
    // For now, we'll show a placeholder message
    setTimeout(() => {
        activityTable.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted">
                    <i class="fas fa-info-circle me-2"></i>
                    Activity monitoring is active. Events will appear here as they occur.
                </td>
            </tr>
        `;
    }, 1000);
}

// Update alert counts
function updateAlertCounts() {
    // This would typically fetch from an API
    // The counts are updated via WebSocket in real-time
}

// Resolve alert function
function resolveAlert(alertId) {
    fetch('/api/resolve-alert', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ alert_id: alertId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove alert from UI
            const alertElement = document.querySelector(`[data-alert-id="${alertId}"]`);
            if (alertElement) {
                alertElement.remove();
            }
            
            if (window.CyberGuard) {
                window.CyberGuard.showToast('Alert resolved successfully', 'success');
            }
        } else {
            if (window.CyberGuard) {
                window.CyberGuard.showToast('Error resolving alert: ' + data.error, 'danger');
            }
        }
    })
    .catch(error => {
        console.error('Error resolving alert:', error);
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Failed to resolve alert', 'danger');
        }
    });
}

// Refresh dashboard
function refreshDashboard() {
    loadDashboardData();
    if (window.CyberGuard) {
        window.CyberGuard.showToast('Dashboard refreshed', 'info');
    }
}

// Setup event listeners
function setupEventListeners() {
    // Handle window resize for chart responsiveness
    window.addEventListener('resize', function() {
        if (systemChart) systemChart.resize();
        if (networkChart) networkChart.resize();
    });
    
    // Handle visibility change to pause/resume updates
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            // Page is hidden, reduce update frequency
            if (chartUpdateInterval) {
                clearInterval(chartUpdateInterval);
            }
        } else {
            // Page is visible, resume normal updates
            if (!window.CyberGuard || !window.CyberGuard.isConnected()) {
                chartUpdateInterval = setInterval(fetchSystemStats, 5000);
            }
        }
    });
}

// Cleanup function
function cleanup() {
    if (chartUpdateInterval) {
        clearInterval(chartUpdateInterval);
    }
    
    if (systemChart) {
        systemChart.destroy();
    }
    
    if (networkChart) {
        networkChart.destroy();
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', cleanup);

// Helper function to format bytes (from main.js)
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Export functions for external access
window.DashboardModule = {
    refreshDashboard,
    resolveAlert,
    updateSystemChart,
    updateNetworkChart,
    cleanup
};
