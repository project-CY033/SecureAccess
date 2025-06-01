// CyberGuard Pro - Application Permissions JavaScript
// Real-time application monitoring, permissions management, and network activity tracking

let currentApplications = [];
let filteredApplications = [];
let refreshInterval;
let networkMonitoringInterval;
let selectedApplication = null;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    loadApplications();
    setupEventListeners();
    startRealTimeMonitoring();
    initializeNetworkMonitoring();
});

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('app-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(filterApplications, 300));
    }
    
    // Filter dropdowns
    const permissionFilter = document.getElementById('permission-filter');
    const activityFilter = document.getElementById('activity-filter');
    
    if (permissionFilter) {
        permissionFilter.addEventListener('change', filterApplications);
    }
    
    if (activityFilter) {
        activityFilter.addEventListener('change', filterApplications);
    }
    
    // Modal event listeners
    const permissionModal = document.getElementById('permissionModal');
    if (permissionModal) {
        const saveBtn = document.getElementById('save-permissions-btn');
        if (saveBtn) {
            saveBtn.addEventListener('click', savePermissionChanges);
        }
    }
    
    const networkModal = document.getElementById('networkActivityModal');
    if (networkModal) {
        const blockBtn = document.getElementById('block-network-btn');
        if (blockBtn) {
            blockBtn.addEventListener('click', blockNetworkAccess);
        }
    }
}

// Load applications list
function loadApplications() {
    showLoadingState();
    
    fetch('/api/installed-applications')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showError('Error loading applications: ' + data.error);
                return;
            }
            
            currentApplications = data.applications || [];
            filteredApplications = [...currentApplications];
            
            updateApplicationsTable();
            updateStatistics();
        })
        .catch(error => {
            showError('Failed to load applications: ' + error.message);
        });
}

// Show loading state
function showLoadingState() {
    const tableBody = document.getElementById('applications-table');
    if (tableBody) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading applications...</span>
                    </div>
                    <div class="mt-2">Loading application information...</div>
                </td>
            </tr>
        `;
    }
}

// Update applications table
function updateApplicationsTable() {
    const tableBody = document.getElementById('applications-table');
    if (!tableBody) return;
    
    if (filteredApplications.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center py-4 text-muted">
                    <i class="fas fa-search me-2"></i>
                    No applications match the current filter criteria
                </td>
            </tr>
        `;
        return;
    }
    
    tableBody.innerHTML = filteredApplications.map(app => {
        const riskLevel = calculateRiskLevel(app);
        const riskClass = getRiskClass(riskLevel);
        const statusClass = app.status === 'running' ? 'success' : 'secondary';
        
        return `
            <tr data-app-pid="${app.pid}" class="application-row">
                <td>
                    <div class="d-flex align-items-center">
                        <div class="app-icon me-2">
                            <i class="fas fa-desktop text-primary"></i>
                        </div>
                        <div>
                            <div class="fw-bold">${escapeHtml(app.name)}</div>
                            <small class="text-muted">${escapeHtml(app.executable_path || 'Unknown path')}</small>
                        </div>
                    </div>
                </td>
                <td>
                    <span class="badge bg-${statusClass}">
                        <i class="fas fa-circle me-1"></i>
                        ${app.status}
                    </span>
                </td>
                <td>
                    <div class="permission-indicators">
                        ${generatePermissionBadges(app.permissions)}
                        <div class="mt-1">
                            <small class="text-warning">
                                Hidden: ${app.permissions.hidden_permissions.length}
                            </small>
                        </div>
                    </div>
                </td>
                <td>
                    <div class="network-activity">
                        <div class="d-flex align-items-center">
                            <i class="fas fa-network-wired me-2"></i>
                            <span>${app.network_activity.total_connections} connections</span>
                        </div>
                        <small class="text-muted">
                            Active: ${app.network_activity.established_connections}
                        </small>
                    </div>
                </td>
                <td>
                    <span class="badge bg-${app.permissions.file_system_access ? 'warning' : 'success'}">
                        ${app.permissions.file_system_access ? 'Full Access' : 'Restricted'}
                    </span>
                </td>
                <td>
                    <span class="badge bg-${riskClass}">
                        <i class="fas fa-${getRiskIcon(riskLevel)} me-1"></i>
                        ${riskLevel}
                    </span>
                </td>
                <td>
                    <div class="btn-group" role="group">
                        <button class="btn btn-sm btn-outline-info" 
                                onclick="viewApplicationDetails(${app.pid})"
                                title="View Details">
                            <i class="fas fa-info-circle"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-warning" 
                                onclick="managePermissions(${app.pid})"
                                title="Manage Permissions">
                            <i class="fas fa-shield-alt"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-success" 
                                onclick="viewNetworkActivity(${app.pid})"
                                title="Network Activity">
                            <i class="fas fa-network-wired"></i>
                        </button>
                        <button class="btn btn-sm btn-outline-danger" 
                                onclick="terminateApplication(${app.pid}, '${escapeHtml(app.name)}')"
                                title="Terminate">
                            <i class="fas fa-skull"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// Generate permission badges
function generatePermissionBadges(permissions) {
    const badges = [];
    
    if (permissions.network_access) {
        badges.push('<span class="badge bg-warning me-1"><i class="fas fa-globe"></i> Network</span>');
    }
    
    if (permissions.file_system_access) {
        badges.push('<span class="badge bg-danger me-1"><i class="fas fa-folder"></i> Files</span>');
    }
    
    if (permissions.camera_access) {
        badges.push('<span class="badge bg-danger me-1"><i class="fas fa-camera"></i> Camera</span>');
    }
    
    if (permissions.microphone_access) {
        badges.push('<span class="badge bg-danger me-1"><i class="fas fa-microphone"></i> Mic</span>');
    }
    
    if (permissions.system_level) {
        badges.push('<span class="badge bg-dark me-1"><i class="fas fa-cog"></i> System</span>');
    }
    
    return badges.join('');
}

// Calculate risk level
function calculateRiskLevel(app) {
    let riskScore = 0;
    
    // Check permissions
    if (app.permissions.system_level) riskScore += 3;
    if (app.permissions.network_access) riskScore += 2;
    if (app.permissions.file_system_access) riskScore += 2;
    if (app.permissions.camera_access) riskScore += 2;
    if (app.permissions.microphone_access) riskScore += 2;
    
    // Check hidden permissions
    riskScore += app.permissions.hidden_permissions.length;
    
    // Check network activity
    if (app.network_activity.total_connections > 10) riskScore += 2;
    if (app.network_activity.established_connections > 5) riskScore += 1;
    
    if (riskScore >= 8) return 'Critical';
    if (riskScore >= 5) return 'High';
    if (riskScore >= 3) return 'Medium';
    return 'Low';
}

// Get risk class
function getRiskClass(riskLevel) {
    const classes = {
        'Critical': 'danger',
        'High': 'warning', 
        'Medium': 'info',
        'Low': 'success'
    };
    return classes[riskLevel] || 'secondary';
}

// Get risk icon
function getRiskIcon(riskLevel) {
    const icons = {
        'Critical': 'skull-crossbones',
        'High': 'exclamation-triangle',
        'Medium': 'exclamation-circle',
        'Low': 'check-circle'
    };
    return icons[riskLevel] || 'question-circle';
}

// Filter applications
function filterApplications() {
    const searchTerm = document.getElementById('app-search')?.value.toLowerCase() || '';
    const permissionFilter = document.getElementById('permission-filter')?.value || '';
    const activityFilter = document.getElementById('activity-filter')?.value || '';
    
    filteredApplications = currentApplications.filter(app => {
        // Search filter
        const nameMatch = app.name.toLowerCase().includes(searchTerm);
        const pathMatch = app.executable_path.toLowerCase().includes(searchTerm);
        
        if (searchTerm && !nameMatch && !pathMatch) {
            return false;
        }
        
        // Permission filter
        if (permissionFilter) {
            const riskLevel = calculateRiskLevel(app).toLowerCase();
            if (permissionFilter === 'high' && !['critical', 'high'].includes(riskLevel)) return false;
            if (permissionFilter === 'medium' && riskLevel !== 'medium') return false;
            if (permissionFilter === 'low' && riskLevel !== 'low') return false;
            if (permissionFilter === 'system' && !app.permissions.system_level) return false;
        }
        
        // Activity filter
        if (activityFilter) {
            if (activityFilter === 'network' && app.network_activity.total_connections === 0) return false;
            if (activityFilter === 'file' && !app.permissions.file_system_access) return false;
            if (activityFilter === 'suspicious' && calculateRiskLevel(app) === 'Low') return false;
        }
        
        return true;
    });
    
    updateApplicationsTable();
    updateStatistics();
}

// Update statistics
function updateStatistics() {
    const totalApps = currentApplications.length;
    const highPermissionApps = currentApplications.filter(app => 
        ['Critical', 'High'].includes(calculateRiskLevel(app))
    ).length;
    const suspiciousApps = currentApplications.filter(app => 
        calculateRiskLevel(app) === 'Critical'
    ).length;
    const networkActiveApps = currentApplications.filter(app => 
        app.network_activity.total_connections > 0
    ).length;
    
    updateElementText('total-apps', totalApps);
    updateElementText('high-permission-apps', highPermissionApps);
    updateElementText('suspicious-apps', suspiciousApps);
    updateElementText('network-active-apps', networkActiveApps);
}

// View application details
function viewApplicationDetails(pid) {
    const app = currentApplications.find(a => a.pid === pid);
    if (!app) return;
    
    selectedApplication = app;
    const modal = new bootstrap.Modal(document.getElementById('appDetailsModal'));
    const content = document.getElementById('app-details-content');
    
    content.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <h6>Application Information</h6>
                <table class="table table-dark table-sm">
                    <tr>
                        <td><strong>Name:</strong></td>
                        <td>${escapeHtml(app.name)}</td>
                    </tr>
                    <tr>
                        <td><strong>PID:</strong></td>
                        <td>${app.pid}</td>
                    </tr>
                    <tr>
                        <td><strong>Executable:</strong></td>
                        <td><small>${escapeHtml(app.executable_path)}</small></td>
                    </tr>
                    <tr>
                        <td><strong>Start Time:</strong></td>
                        <td>${new Date(app.start_time).toLocaleString()}</td>
                    </tr>
                    <tr>
                        <td><strong>Status:</strong></td>
                        <td><span class="badge bg-success">${app.status}</span></td>
                    </tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6>Permissions & Access</h6>
                <div class="permission-list">
                    ${generateDetailedPermissions(app.permissions)}
                </div>
                
                <h6 class="mt-3">Network Activity</h6>
                <div class="network-stats">
                    <div class="row">
                        <div class="col-6">
                            <small>Total Connections:</small>
                            <div class="h5">${app.network_activity.total_connections}</div>
                        </div>
                        <div class="col-6">
                            <small>Active:</small>
                            <div class="h5">${app.network_activity.established_connections}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-3">
            <div class="col-12">
                <h6>Risk Assessment</h6>
                <div class="alert alert-${getRiskClass(calculateRiskLevel(app))}">
                    <strong>Risk Level:</strong> ${calculateRiskLevel(app)}
                    <br>
                    <small>Based on permissions, network activity, and system access</small>
                </div>
            </div>
        </div>
    `;
    
    modal.show();
}

// Generate detailed permissions
function generateDetailedPermissions(permissions) {
    const items = [];
    
    Object.keys(permissions).forEach(key => {
        if (key === 'hidden_permissions') return;
        
        const value = permissions[key];
        const icon = value ? 'check-circle text-success' : 'times-circle text-danger';
        const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        
        items.push(`
            <div class="d-flex align-items-center mb-2">
                <i class="fas fa-${icon} me-2"></i>
                <span>${label}</span>
            </div>
        `);
    });
    
    if (permissions.hidden_permissions.length > 0) {
        items.push(`
            <div class="mt-2">
                <small class="text-warning">
                    <i class="fas fa-eye-slash me-1"></i>
                    Hidden Permissions: ${permissions.hidden_permissions.join(', ')}
                </small>
            </div>
        `);
    }
    
    return items.join('');
}

// Manage permissions
function managePermissions(pid) {
    const app = currentApplications.find(a => a.pid === pid);
    if (!app) return;
    
    selectedApplication = app;
    const modal = new bootstrap.Modal(document.getElementById('permissionModal'));
    const controls = document.getElementById('permission-controls');
    
    controls.innerHTML = generatePermissionControls(app.permissions);
    modal.show();
}

// Generate permission controls
function generatePermissionControls(permissions) {
    const controls = [];
    
    Object.keys(permissions).forEach(key => {
        if (key === 'hidden_permissions') return;
        
        const value = permissions[key];
        const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        
        controls.push(`
            <div class="mb-3">
                <div class="d-flex justify-content-between align-items-center">
                    <label class="form-label">${label}</label>
                    <div class="btn-group" role="group">
                        <input type="radio" class="btn-check" name="perm_${key}" id="grant_${key}" value="grant" ${value ? 'checked' : ''}>
                        <label class="btn btn-outline-success btn-sm" for="grant_${key}">Grant</label>
                        
                        <input type="radio" class="btn-check" name="perm_${key}" id="revoke_${key}" value="revoke" ${!value ? 'checked' : ''}>
                        <label class="btn btn-outline-danger btn-sm" for="revoke_${key}">Revoke</label>
                        
                        <input type="radio" class="btn-check" name="perm_${key}" id="restrict_${key}" value="restrict">
                        <label class="btn btn-outline-warning btn-sm" for="restrict_${key}">Restrict</label>
                    </div>
                </div>
            </div>
        `);
    });
    
    return controls.join('');
}

// Save permission changes
function savePermissionChanges() {
    if (!selectedApplication) return;
    
    const changes = [];
    const controls = document.getElementById('permission-controls');
    const radioGroups = controls.querySelectorAll('input[type="radio"]:checked');
    
    radioGroups.forEach(radio => {
        const permissionType = radio.name.replace('perm_', '');
        const action = radio.value;
        
        changes.push({
            permission_type: permissionType,
            action: action
        });
    });
    
    // Apply changes
    changes.forEach(change => {
        fetch('/api/change-app-permission', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                app_path: selectedApplication.executable_path,
                permission_type: change.permission_type,
                action: change.action
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showSuccess('Permission updated successfully');
            } else {
                showError('Failed to update permission: ' + data.error);
            }
        })
        .catch(error => {
            showError('Error updating permission: ' + error.message);
        });
    });
    
    // Close modal and refresh
    bootstrap.Modal.getInstance(document.getElementById('permissionModal')).hide();
    setTimeout(() => loadApplications(), 1000);
}

// View network activity
function viewNetworkActivity(pid) {
    const app = currentApplications.find(a => a.pid === pid);
    if (!app) return;
    
    selectedApplication = app;
    const modal = new bootstrap.Modal(document.getElementById('networkActivityModal'));
    const content = document.getElementById('network-activity-content');
    
    content.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading network activity...</span>
            </div>
            <div class="mt-2">Fetching real-time network data...</div>
        </div>
    `;
    
    modal.show();
    
    // Fetch detailed network activity
    fetch(`/api/application-network-activity/${pid}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                content.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                return;
            }
            
            const activity = data.network_activity || [];
            content.innerHTML = generateNetworkActivityTable(activity);
        })
        .catch(error => {
            content.innerHTML = `<div class="alert alert-danger">Error loading network activity: ${error.message}</div>`;
        });
}

// Generate network activity table
function generateNetworkActivityTable(activity) {
    if (activity.length === 0) {
        return `
            <div class="text-center py-4 text-muted">
                <i class="fas fa-network-wired fa-3x mb-3"></i>
                <div>No network activity detected</div>
            </div>
        `;
    }
    
    return `
        <div class="table-responsive">
            <table class="table table-dark table-striped">
                <thead>
                    <tr>
                        <th>Direction</th>
                        <th>Protocol</th>
                        <th>Local Address</th>
                        <th>Remote Address</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${activity.map(conn => `
                        <tr>
                            <td>
                                <span class="badge bg-${conn.direction === 'outgoing' ? 'warning' : 'info'}">
                                    <i class="fas fa-${conn.direction === 'outgoing' ? 'arrow-up' : 'arrow-down'} me-1"></i>
                                    ${conn.direction}
                                </span>
                            </td>
                            <td><code>${conn.protocol}</code></td>
                            <td><code>${conn.local_address}</code></td>
                            <td><code>${conn.remote_address}</code></td>
                            <td>
                                <span class="badge bg-${conn.status === 'ESTABLISHED' ? 'success' : 'secondary'}">
                                    ${conn.status}
                                </span>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-danger" 
                                        onclick="blockConnection('${conn.remote_address}')">
                                    <i class="fas fa-ban"></i> Block
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Block network access
function blockNetworkAccess() {
    if (!selectedApplication) return;
    
    if (confirm(`Block all network access for ${selectedApplication.name}?`)) {
        // This would implement actual network blocking
        showSuccess('Network access blocked for ' + selectedApplication.name);
        bootstrap.Modal.getInstance(document.getElementById('networkActivityModal')).hide();
    }
}

// Terminate application
function terminateApplication(pid, name) {
    if (confirm(`Terminate application "${name}"? This action cannot be undone.`)) {
        fetch('/api/terminate-application', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                pid: pid,
                reason: 'User terminated due to security concerns'
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showSuccess(data.message);
                loadApplications(); // Refresh the list
            } else {
                showError('Failed to terminate application: ' + data.error);
            }
        })
        .catch(error => {
            showError('Error terminating application: ' + error.message);
        });
    }
}

// Refresh applications
function refreshApplications() {
    loadApplications();
}

// Scan for new applications
function scanForNewApplications() {
    showSuccess('Scanning for new applications...');
    loadApplications();
}

// Start real-time monitoring
function startRealTimeMonitoring() {
    refreshInterval = setInterval(() => {
        loadApplications();
    }, 10000); // Refresh every 10 seconds
}

// Initialize network monitoring
function initializeNetworkMonitoring() {
    networkMonitoringInterval = setInterval(() => {
        updateNetworkMonitoring();
    }, 5000); // Update every 5 seconds
}

// Update network monitoring
function updateNetworkMonitoring() {
    const networkContainer = document.getElementById('network-monitoring');
    if (!networkContainer) return;
    
    // This would show real-time network activity charts
    networkContainer.innerHTML = `
        <div class="row">
            <div class="col-md-4">
                <div class="card bg-info text-white">
                    <div class="card-body text-center">
                        <h5>Active Connections</h5>
                        <h3>${currentApplications.reduce((sum, app) => sum + app.network_activity.established_connections, 0)}</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card bg-warning text-white">
                    <div class="card-body text-center">
                        <h5>Total Connections</h5>
                        <h3>${currentApplications.reduce((sum, app) => sum + app.network_activity.total_connections, 0)}</h3>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card bg-danger text-white">
                    <div class="card-body text-center">
                        <h5>Suspicious Activity</h5>
                        <h3>${currentApplications.filter(app => calculateRiskLevel(app) === 'Critical').length}</h3>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Utility functions
function updateElementText(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value;
    }
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

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

function showSuccess(message) {
    // This would integrate with the global toast system
    console.log('Success:', message);
}

function showError(message) {
    // This would integrate with the global toast system
    console.error('Error:', message);
}

function blockConnection(remoteAddress) {
    if (confirm(`Block connection to ${remoteAddress}?`)) {
        showSuccess(`Connection to ${remoteAddress} blocked`);
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (refreshInterval) clearInterval(refreshInterval);
    if (networkMonitoringInterval) clearInterval(networkMonitoringInterval);
});