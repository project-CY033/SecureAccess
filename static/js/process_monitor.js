// CyberGuard Pro - Process Monitor JavaScript
// Real-time process monitoring and management

let processUpdateInterval;
let autoRefreshEnabled = false;
let currentProcesses = [];
let filteredProcesses = [];

// Initialize process monitor when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    loadProcessList();
    setupEventListeners();
    setupWebSocketListeners();
});

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('process-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(filterProcesses, 300));
    }
    
    // Risk level filter
    const riskFilter = document.getElementById('risk-filter');
    if (riskFilter) {
        riskFilter.addEventListener('change', filterProcesses);
    }
    
    // Modal event listeners
    const processModal = document.getElementById('processModal');
    if (processModal) {
        processModal.addEventListener('hidden.bs.modal', clearProcessDetails);
    }
    
    const terminateModal = document.getElementById('terminateModal');
    if (terminateModal) {
        const confirmBtn = document.getElementById('confirm-terminate-btn');
        if (confirmBtn) {
            confirmBtn.addEventListener('click', confirmTerminateProcess);
        }
    }
}

// Setup WebSocket listeners for real-time updates
function setupWebSocketListeners() {
    if (typeof socket !== 'undefined' && socket) {
        socket.on('process_update', function(data) {
            updateProcessCounts(data);
        });
        
        socket.on('process_list', function(data) {
            updateProcessTable(data.processes);
        });
        
        socket.on('process_killed', function(data) {
            removeProcessFromTable(data.pid);
            if (window.CyberGuard) {
                window.CyberGuard.showToast(`Process ${data.name} (PID: ${data.pid}) terminated`, 'success');
            }
        });
    }
}

// Load initial process list
function loadProcessList() {
    showLoadingState();
    
    if (typeof socket !== 'undefined' && socket) {
        socket.emit('request_process_list');
    } else {
        // Fallback to manual refresh
        refreshProcesses();
    }
}

// Show loading state in table
function showLoadingState() {
    const tableBody = document.getElementById('process-table');
    if (tableBody) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading processes...</span>
                    </div>
                    <div class="mt-2">Loading process information...</div>
                </td>
            </tr>
        `;
    }
    
    updateLastUpdateTime('Loading...');
}

// Update process table with new data
function updateProcessTable(processes) {
    const tableBody = document.getElementById('process-table');
    if (!tableBody) return;
    
    currentProcesses = processes;
    filteredProcesses = [...processes];
    
    // Apply current filters
    filterProcesses();
    
    // Update process counts
    updateProcessStatistics();
    updateLastUpdateTime();
}

// Render process table rows
function renderProcessTable(processes) {
    const tableBody = document.getElementById('process-table');
    if (!tableBody) return;
    
    if (processes.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-muted">
                    <i class="fas fa-search me-2"></i>
                    No processes match the current filter criteria
                </td>
            </tr>
        `;
        return;
    }
    
    tableBody.innerHTML = processes.map(process => {
        const riskLevel = determineRiskLevel(process);
        const riskClass = getRiskClass(riskLevel);
        const riskIcon = getRiskIcon(riskLevel);
        
        return `
            <tr data-pid="${process.pid}" class="process-row">
                <td class="font-monospace">${process.pid}</td>
                <td>
                    <div class="d-flex align-items-center">
                        <i class="fas fa-cog me-2 text-muted"></i>
                        <span class="process-name">${escapeHtml(process.name || 'Unknown')}</span>
                    </div>
                </td>
                <td>
                    <div class="d-flex align-items-center">
                        <span class="me-2">${(process.cpu_percent || 0).toFixed(1)}%</span>
                        <div class="progress flex-grow-1" style="height: 6px; width: 60px;">
                            <div class="progress-bar ${getCpuProgressClass(process.cpu_percent)}" 
                                 style="width: ${Math.min(process.cpu_percent || 0, 100)}%"></div>
                        </div>
                    </div>
                </td>
                <td>
                    <div class="d-flex align-items-center">
                        <span class="me-2">${(process.memory_percent || 0).toFixed(1)}%</span>
                        <div class="progress flex-grow-1" style="height: 6px; width: 60px;">
                            <div class="progress-bar ${getMemoryProgressClass(process.memory_percent)}" 
                                 style="width: ${Math.min(process.memory_percent || 0, 100)}%"></div>
                        </div>
                    </div>
                </td>
                <td>
                    <span class="badge bg-${getStatusClass(process.status)}">
                        ${process.status || 'unknown'}
                    </span>
                </td>
                <td>
                    <span class="badge bg-${riskClass}">
                        <i class="fas fa-${riskIcon} me-1"></i>
                        ${riskLevel}
                    </span>
                </td>
                <td>
                    <div class="btn-group" role="group">
                        <button class="btn btn-sm btn-outline-info" 
                                onclick="viewProcessDetails(${process.pid}, '${escapeHtml(process.name || '')}')"
                                title="View Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" 
                                onclick="initiateTerminateProcess(${process.pid}, '${escapeHtml(process.name || '')}')"
                                title="Terminate Process">
                            <i class="fas fa-skull"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// Filter processes based on search and filters
function filterProcesses() {
    const searchTerm = document.getElementById('process-search')?.value.toLowerCase() || '';
    const riskFilter = document.getElementById('risk-filter')?.value || '';
    
    filteredProcesses = currentProcesses.filter(process => {
        // Search filter
        const nameMatch = (process.name || '').toLowerCase().includes(searchTerm);
        const pidMatch = process.pid.toString().includes(searchTerm);
        
        if (searchTerm && !nameMatch && !pidMatch) {
            return false;
        }
        
        // Risk filter
        if (riskFilter) {
            const processRiskLevel = determineRiskLevel(process);
            if (processRiskLevel !== riskFilter) {
                return false;
            }
        }
        
        return true;
    });
    
    renderProcessTable(filteredProcesses);
}

// Determine risk level based on process characteristics
function determineRiskLevel(process) {
    const name = (process.name || '').toLowerCase();
    const cpuUsage = process.cpu_percent || 0;
    const memoryUsage = process.memory_percent || 0;
    
    // Known malicious patterns
    const maliciousPatterns = ['keylogger', 'rootkit', 'trojan', 'backdoor', 'malware', 'virus'];
    if (maliciousPatterns.some(pattern => name.includes(pattern))) {
        return 'malicious';
    }
    
    // Suspicious patterns or high resource usage
    const suspiciousPatterns = ['temp', 'tmp', 'unknown', 'noname'];
    const highResourceUsage = cpuUsage > 80 || memoryUsage > 50;
    const suspiciousName = suspiciousPatterns.some(pattern => name.includes(pattern));
    
    if (suspiciousName || highResourceUsage) {
        return 'suspicious';
    }
    
    return 'safe';
}

// Get CSS class for risk level
function getRiskClass(riskLevel) {
    const classes = {
        'safe': 'success',
        'suspicious': 'warning',
        'malicious': 'danger'
    };
    return classes[riskLevel] || 'secondary';
}

// Get icon for risk level
function getRiskIcon(riskLevel) {
    const icons = {
        'safe': 'check-circle',
        'suspicious': 'exclamation-triangle',
        'malicious': 'skull-crossbones'
    };
    return icons[riskLevel] || 'question-circle';
}

// Get CSS class for CPU progress bar
function getCpuProgressClass(cpuPercent) {
    if (cpuPercent > 80) return 'bg-danger';
    if (cpuPercent > 50) return 'bg-warning';
    return 'bg-info';
}

// Get CSS class for memory progress bar
function getMemoryProgressClass(memoryPercent) {
    if (memoryPercent > 70) return 'bg-danger';
    if (memoryPercent > 40) return 'bg-warning';
    return 'bg-info';
}

// Get CSS class for process status
function getStatusClass(status) {
    const statusLower = (status || '').toLowerCase();
    if (statusLower === 'running') return 'success';
    if (statusLower === 'sleeping') return 'info';
    if (statusLower === 'stopped') return 'warning';
    if (statusLower === 'zombie') return 'danger';
    return 'secondary';
}

// Update process statistics
function updateProcessStatistics() {
    const totalCount = currentProcesses.length;
    const safeCount = currentProcesses.filter(p => determineRiskLevel(p) === 'safe').length;
    const suspiciousCount = currentProcesses.filter(p => determineRiskLevel(p) === 'suspicious').length;
    const maliciousCount = currentProcesses.filter(p => determineRiskLevel(p) === 'malicious').length;
    
    updateElementText('total-processes', totalCount);
    updateElementText('safe-processes', safeCount);
    
    // Update suspicious and malicious counts in cards
    const suspiciousCard = document.querySelector('.card .h5:contains("' + suspiciousCount + '")');
    const maliciousCard = document.querySelector('.card .h5:contains("' + maliciousCount + '")');
    
    // Find and update the card values
    const cards = document.querySelectorAll('.card .h5');
    cards.forEach(card => {
        const parent = card.closest('.card');
        if (parent && parent.textContent.includes('Suspicious')) {
            card.textContent = suspiciousCount;
        } else if (parent && parent.textContent.includes('Malicious')) {
            card.textContent = maliciousCount;
        }
    });
}

// Update element text content safely
function updateElementText(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value;
    }
}

// Update last update time
function updateLastUpdateTime(text = null) {
    const element = document.getElementById('last-update');
    if (element) {
        element.textContent = text || new Date().toLocaleTimeString();
    }
}

// View process details
function viewProcessDetails(pid, processName) {
    const modal = new bootstrap.Modal(document.getElementById('processModal'));
    const detailsContent = document.getElementById('process-details');
    
    if (!detailsContent) return;
    
    // Show loading state
    detailsContent.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">Loading process details...</span>
            </div>
            <div class="mt-2">Loading detailed information...</div>
        </div>
    `;
    
    modal.show();
    
    // Find process in current data
    const process = currentProcesses.find(p => p.pid === pid);
    
    setTimeout(() => {
        if (process) {
            const riskLevel = determineRiskLevel(process);
            const riskClass = getRiskClass(riskLevel);
            
            detailsContent.innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <h6>Process Information</h6>
                        <table class="table table-dark table-sm">
                            <tr>
                                <td><strong>PID:</strong></td>
                                <td class="font-monospace">${process.pid}</td>
                            </tr>
                            <tr>
                                <td><strong>Name:</strong></td>
                                <td>${escapeHtml(process.name || 'Unknown')}</td>
                            </tr>
                            <tr>
                                <td><strong>Status:</strong></td>
                                <td>
                                    <span class="badge bg-${getStatusClass(process.status)}">
                                        ${process.status || 'unknown'}
                                    </span>
                                </td>
                            </tr>
                            <tr>
                                <td><strong>CPU Usage:</strong></td>
                                <td>${(process.cpu_percent || 0).toFixed(2)}%</td>
                            </tr>
                            <tr>
                                <td><strong>Memory Usage:</strong></td>
                                <td>${(process.memory_percent || 0).toFixed(2)}%</td>
                            </tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h6>Security Assessment</h6>
                        <div class="alert alert-${riskClass}">
                            <strong>Risk Level:</strong> 
                            <span class="badge bg-${riskClass}">
                                <i class="fas fa-${getRiskIcon(riskLevel)} me-1"></i>
                                ${riskLevel.toUpperCase()}
                            </span>
                        </div>
                        
                        <h6>Actions Available</h6>
                        <div class="d-grid gap-2">
                            <button class="btn btn-outline-info btn-sm" onclick="refreshProcessDetails(${pid})">
                                <i class="fas fa-sync-alt"></i> Refresh Details
                            </button>
                            ${riskLevel !== 'safe' ? `
                                <button class="btn btn-outline-warning btn-sm" onclick="quarantineProcess(${pid})">
                                    <i class="fas fa-shield-alt"></i> Quarantine Process
                                </button>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;
            
            // Set up terminate button
            const terminateBtn = document.getElementById('terminate-process-btn');
            if (terminateBtn) {
                terminateBtn.onclick = () => initiateTerminateProcess(pid, process.name);
            }
        } else {
            detailsContent.innerHTML = `
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Process with PID ${pid} not found. It may have already terminated.
                </div>
            `;
        }
    }, 1000);
}

// Refresh process details
function refreshProcessDetails(pid) {
    if (typeof socket !== 'undefined' && socket) {
        socket.emit('request_process_list');
    }
    
    setTimeout(() => {
        const process = currentProcesses.find(p => p.pid === pid);
        if (process) {
            viewProcessDetails(pid, process.name);
        }
    }, 500);
}

// Quarantine process (placeholder for future implementation)
function quarantineProcess(pid) {
    if (window.CyberGuard) {
        window.CyberGuard.showToast('Process quarantine feature coming soon', 'info');
    }
}

// Clear process details modal
function clearProcessDetails() {
    const detailsContent = document.getElementById('process-details');
    if (detailsContent) {
        detailsContent.innerHTML = '';
    }
}

// Initiate process termination
function initiateTerminateProcess(pid, processName) {
    const modal = new bootstrap.Modal(document.getElementById('terminateModal'));
    
    document.getElementById('terminate-process-name').textContent = processName || 'Unknown';
    document.getElementById('terminate-process-pid').textContent = pid;
    
    // Store PID for confirmation
    document.getElementById('confirm-terminate-btn').dataset.pid = pid;
    
    modal.show();
}

// Confirm and execute process termination
function confirmTerminateProcess() {
    const btn = document.getElementById('confirm-terminate-btn');
    const pid = parseInt(btn.dataset.pid);
    
    if (!pid) return;
    
    // Show loading state
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Terminating...';
    btn.disabled = true;
    
    if (typeof socket !== 'undefined' && socket) {
        socket.emit('kill_process', { pid: pid });
    } else {
        // Fallback to API call
        terminateProcessAPI(pid);
    }
    
    // Close modal
    setTimeout(() => {
        bootstrap.Modal.getInstance(document.getElementById('terminateModal')).hide();
        btn.innerHTML = '<i class="fas fa-skull"></i> Terminate';
        btn.disabled = false;
    }, 2000);
}

// Terminate process via API
function terminateProcessAPI(pid) {
    fetch('/api/terminate-process', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ pid: pid })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            removeProcessFromTable(pid);
            if (window.CyberGuard) {
                window.CyberGuard.showToast(data.message, 'success');
            }
        } else {
            if (window.CyberGuard) {
                window.CyberGuard.showToast('Error: ' + data.error, 'danger');
            }
        }
    })
    .catch(error => {
        console.error('Error terminating process:', error);
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Failed to terminate process', 'danger');
        }
    });
}

// Remove process from table
function removeProcessFromTable(pid) {
    const row = document.querySelector(`tr[data-pid="${pid}"]`);
    if (row) {
        row.remove();
    }
    
    // Update current processes array
    currentProcesses = currentProcesses.filter(p => p.pid !== pid);
    filteredProcesses = filteredProcesses.filter(p => p.pid !== pid);
    
    // Update statistics
    updateProcessStatistics();
}

// Refresh processes manually
function refreshProcesses() {
    showLoadingState();
    
    if (typeof socket !== 'undefined' && socket) {
        socket.emit('request_process_list');
    } else {
        // In a real implementation, this would fetch from an API
        setTimeout(() => {
            updateLastUpdateTime('Unable to connect');
        }, 1000);
    }
}

// Toggle auto-refresh
function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;
    const icon = document.getElementById('auto-refresh-icon');
    const button = icon?.closest('button');
    
    if (autoRefreshEnabled) {
        if (icon) icon.className = 'fas fa-pause';
        if (button) button.classList.add('active');
        
        processUpdateInterval = setInterval(() => {
            if (typeof socket !== 'undefined' && socket) {
                socket.emit('request_process_list');
            }
        }, 5000);
        
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Auto-refresh enabled (5s interval)', 'success');
        }
    } else {
        if (icon) icon.className = 'fas fa-play';
        if (button) button.classList.remove('active');
        
        if (processUpdateInterval) {
            clearInterval(processUpdateInterval);
            processUpdateInterval = null;
        }
        
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Auto-refresh disabled', 'info');
        }
    }
}

// Utility functions
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Update process counts from WebSocket
function updateProcessCounts(data) {
    updateElementText('total-processes', data.total_processes || 0);
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (processUpdateInterval) {
        clearInterval(processUpdateInterval);
    }
});

// Export functions for external access
window.ProcessMonitor = {
    refreshProcesses,
    toggleAutoRefresh,
    viewProcessDetails,
    initiateTerminateProcess
};
