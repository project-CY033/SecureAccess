// CyberGuard Pro - Security Scanner JavaScript
// SecurityAI tools interface and management

let currentTool = null;
let scanInProgress = false;
let scanResults = {};

// Initialize security scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeToolInterface();
    loadRecentScans();
    setupEventListeners();
    updateScanStats();
});

// Initialize tool interface
function initializeToolInterface() {
    // Add click handlers to all security tool cards
    const toolCards = document.querySelectorAll('.security-tool-card');
    toolCards.forEach(card => {
        card.addEventListener('click', function() {
            const toolName = this.getAttribute('onclick')?.match(/openTool\('([^']+)'\)/)?.[1];
            if (toolName) {
                openTool(toolName);
            }
        });
    });
}

// Setup event listeners
function setupEventListeners() {
    // Start scan button in modal
    const startScanBtn = document.getElementById('start-scan-btn');
    if (startScanBtn) {
        startScanBtn.addEventListener('click', startScan);
    }
    
    // Tool modal events
    const toolModal = document.getElementById('toolModal');
    if (toolModal) {
        toolModal.addEventListener('hidden.bs.modal', function() {
            resetToolInterface();
        });
    }
}

// Open security tool interface
function openTool(toolName) {
    if (scanInProgress) {
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Please wait for the current scan to complete', 'warning');
        }
        return;
    }
    
    currentTool = toolName;
    const modal = new bootstrap.Modal(document.getElementById('toolModal'));
    
    // Set modal title and load tool interface
    document.getElementById('tool-modal-title').textContent = getToolDisplayName(toolName);
    loadToolInterface(toolName);
    
    modal.show();
}

// Get display name for tool
function getToolDisplayName(toolName) {
    const toolNames = {
        'subdomain-enum': 'Subdomain Enumeration',
        'port-scan': 'Port Scanner',
        'dns-lookup': 'DNS Lookup',
        'reverse-ip': 'Reverse IP Lookup',
        'whois-lookup': 'WHOIS Lookup',
        'virus-total': 'VirusTotal Scanner',
        'shodan-search': 'SHODAN Search',
        'xss-scanner': 'XSS Vulnerability Scanner',
        'api-security': 'API Security Scanner',
        'wireless-assess': 'Wireless Security Assessment',
        'malware-analysis': 'Malware Analysis',
        'insider-threat': 'Insider Threat Detection',
        'email-osint': 'Email OSINT',
        'metadata-extract': 'Metadata Extraction',
        'archived-url': 'Archived URL Viewer',
        'tech-stack': 'Technology Stack Detection'
    };
    
    return toolNames[toolName] || 'Security Tool';
}

// Load tool-specific interface
function loadToolInterface(toolName) {
    const modalBody = document.getElementById('tool-modal-body');
    
    // Show loading state
    modalBody.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading tool interface...</span>
            </div>
            <div class="mt-2">Initializing ${getToolDisplayName(toolName)}...</div>
        </div>
    `;
    
    // Load tool-specific interface after delay
    setTimeout(() => {
        modalBody.innerHTML = generateToolInterface(toolName);
    }, 1000);
}

// Generate tool-specific interface HTML
function generateToolInterface(toolName) {
    switch (toolName) {
        case 'subdomain-enum':
            return `
                <div class="mb-3">
                    <label for="domain-input" class="form-label">Target Domain</label>
                    <input type="text" class="form-control" id="domain-input" 
                           placeholder="example.com" required>
                    <div class="form-text">Enter the domain to enumerate subdomains for</div>
                </div>
                <div class="mb-3">
                    <label for="subdomain-method" class="form-label">Enumeration Method</label>
                    <select class="form-select" id="subdomain-method">
                        <option value="dns">DNS Enumeration</option>
                        <option value="bruteforce">Brute Force</option>
                        <option value="certificate">Certificate Transparency</option>
                        <option value="all">All Methods</option>
                    </select>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="deep-scan" checked>
                            <label class="form-check-label" for="deep-scan">Deep Scan</label>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="validate-subdomains" checked>
                            <label class="form-check-label" for="validate-subdomains">Validate Results</label>
                        </div>
                    </div>
                </div>
            `;
            
        case 'port-scan':
            return `
                <div class="mb-3">
                    <label for="target-input" class="form-label">Target IP/Hostname</label>
                    <input type="text" class="form-control" id="target-input" 
                           placeholder="192.168.1.1 or example.com" required>
                </div>
                <div class="mb-3">
                    <label for="port-range" class="form-label">Port Range</label>
                    <select class="form-select" id="port-range">
                        <option value="common">Common Ports (Top 1000)</option>
                        <option value="top100">Top 100 Ports</option>
                        <option value="all">All Ports (1-65535)</option>
                        <option value="custom">Custom Range</option>
                    </select>
                </div>
                <div class="mb-3" id="custom-ports" style="display: none;">
                    <label for="custom-port-range" class="form-label">Custom Port Range</label>
                    <input type="text" class="form-control" id="custom-port-range" 
                           placeholder="80,443,8080-8090">
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <label for="scan-type" class="form-label">Scan Type</label>
                        <select class="form-select" id="scan-type">
                            <option value="tcp">TCP Connect</option>
                            <option value="syn">SYN Stealth</option>
                            <option value="udp">UDP Scan</option>
                        </select>
                    </div>
                    <div class="col-md-6">
                        <label for="scan-speed" class="form-label">Scan Speed</label>
                        <select class="form-select" id="scan-speed">
                            <option value="1">Slow (Stealth)</option>
                            <option value="3" selected>Normal</option>
                            <option value="5">Fast</option>
                        </select>
                    </div>
                </div>
            `;
            
        case 'dns-lookup':
            return `
                <div class="mb-3">
                    <label for="dns-domain" class="form-label">Domain Name</label>
                    <input type="text" class="form-control" id="dns-domain" 
                           placeholder="example.com" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">DNS Record Types</label>
                    <div class="row">
                        <div class="col-md-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="dns-a" checked>
                                <label class="form-check-label" for="dns-a">A Records</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="dns-aaaa" checked>
                                <label class="form-check-label" for="dns-aaaa">AAAA Records</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="dns-mx" checked>
                                <label class="form-check-label" for="dns-mx">MX Records</label>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="dns-ns" checked>
                                <label class="form-check-label" for="dns-ns">NS Records</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="dns-txt" checked>
                                <label class="form-check-label" for="dns-txt">TXT Records</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="dns-cname">
                                <label class="form-check-label" for="dns-cname">CNAME Records</label>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="dns-soa">
                                <label class="form-check-label" for="dns-soa">SOA Records</label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="dns-ptr">
                                <label class="form-check-label" for="dns-ptr">PTR Records</label>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
        case 'virus-total':
            return `
                <div class="mb-3">
                    <label for="vt-input-type" class="form-label">Input Type</label>
                    <select class="form-select" id="vt-input-type" onchange="toggleVTInputType()">
                        <option value="hash">File Hash</option>
                        <option value="url">URL</option>
                        <option value="domain">Domain</option>
                        <option value="ip">IP Address</option>
                    </select>
                </div>
                <div class="mb-3">
                    <label for="vt-input" class="form-label">Input Value</label>
                    <input type="text" class="form-control" id="vt-input" 
                           placeholder="Enter hash, URL, domain, or IP address" required>
                    <div class="form-text">Supported hash types: MD5, SHA1, SHA256</div>
                </div>
                <div class="mb-3">
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="vt-detailed" checked>
                        <label class="form-check-label" for="vt-detailed">Detailed Analysis</label>
                    </div>
                </div>
            `;
            
        default:
            return `
                <div class="alert alert-info">
                    <h6><i class="fas fa-info-circle me-2"></i>${getToolDisplayName(toolName)}</h6>
                    <p>This advanced security tool provides comprehensive analysis capabilities.</p>
                    <div class="mb-3">
                        <label for="generic-target" class="form-label">Target</label>
                        <input type="text" class="form-control" id="generic-target" 
                               placeholder="Enter target (domain, IP, URL, etc.)" required>
                    </div>
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="advanced-mode">
                        <label class="form-check-label" for="advanced-mode">Advanced Mode</label>
                    </div>
                </div>
            `;
    }
}

// Start security scan
function startScan() {
    if (scanInProgress) {
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Scan already in progress', 'warning');
        }
        return;
    }
    
    const target = getTargetValue();
    if (!target) {
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Please enter a target to scan', 'warning');
        }
        return;
    }
    
    scanInProgress = true;
    updateScanButton(true);
    showScanProgress();
    
    // Start the scan
    executeScan(currentTool, target);
}

// Get target value from current tool interface
function getTargetValue() {
    const inputs = [
        'domain-input', 'target-input', 'dns-domain', 'vt-input', 'generic-target'
    ];
    
    for (const inputId of inputs) {
        const element = document.getElementById(inputId);
        if (element && element.value.trim()) {
            return element.value.trim();
        }
    }
    
    return null;
}

// Update scan button state
function updateScanButton(scanning) {
    const button = document.getElementById('start-scan-btn');
    if (!button) return;
    
    if (scanning) {
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        button.disabled = true;
    } else {
        button.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        button.disabled = false;
    }
}

// Show scan progress
function showScanProgress() {
    const modalBody = document.getElementById('tool-modal-body');
    const progressHTML = `
        <div class="scan-progress-container">
            <div class="alert alert-info">
                <h6><i class="fas fa-cogs me-2"></i>Scan in Progress</h6>
                <p>Executing ${getToolDisplayName(currentTool)} against target...</p>
            </div>
            <div class="progress mb-3">
                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                     role="progressbar" style="width: 0%" id="scan-progress-bar"></div>
            </div>
            <div class="scan-status-container">
                <small class="text-muted" id="scan-status">Initializing scan...</small>
            </div>
            <div class="scan-results-container mt-3" id="scan-results-display" style="display: none;">
                <!-- Results will be displayed here -->
            </div>
        </div>
    `;
    
    modalBody.innerHTML = progressHTML;
}

// Execute security scan
function executeScan(toolName, target) {
    const scanData = {
        tool: toolName,
        target: target,
        options: collectScanOptions()
    };
    
    // Simulate scan progress
    simulateScanProgress();
    
    // Make API call to execute scan
    fetch(`/api/security-tools/${toolName}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(scanData)
    })
    .then(response => response.json())
    .then(data => {
        completeScan(data);
    })
    .catch(error => {
        console.error('Scan error:', error);
        completeScan({ error: error.message });
    });
}

// Collect scan options from current interface
function collectScanOptions() {
    const options = {};
    
    // Collect common options
    const commonInputs = [
        'subdomain-method', 'port-range', 'custom-port-range', 'scan-type', 
        'scan-speed', 'vt-input-type', 'deep-scan', 'validate-subdomains',
        'vt-detailed', 'advanced-mode'
    ];
    
    commonInputs.forEach(inputId => {
        const element = document.getElementById(inputId);
        if (element) {
            if (element.type === 'checkbox') {
                options[inputId] = element.checked;
            } else {
                options[inputId] = element.value;
            }
        }
    });
    
    // Collect DNS record types
    const dnsTypes = ['dns-a', 'dns-aaaa', 'dns-mx', 'dns-ns', 'dns-txt', 'dns-cname', 'dns-soa', 'dns-ptr'];
    options.dnsRecordTypes = [];
    dnsTypes.forEach(typeId => {
        const element = document.getElementById(typeId);
        if (element && element.checked) {
            options.dnsRecordTypes.push(typeId.replace('dns-', '').toUpperCase());
        }
    });
    
    return options;
}

// Simulate scan progress
function simulateScanProgress() {
    const progressBar = document.getElementById('scan-progress-bar');
    const statusElement = document.getElementById('scan-status');
    
    if (!progressBar || !statusElement) return;
    
    const stages = [
        'Initializing scan engine...',
        'Resolving target information...',
        'Executing security analysis...',
        'Processing results...',
        'Generating report...'
    ];
    
    let currentStage = 0;
    let progress = 0;
    
    const progressInterval = setInterval(() => {
        progress += Math.random() * 15;
        
        if (progress > 100) {
            progress = 100;
            clearInterval(progressInterval);
        }
        
        progressBar.style.width = progress + '%';
        
        // Update status
        if (currentStage < stages.length && progress > (currentStage + 1) * 20) {
            currentStage++;
        }
        
        if (currentStage < stages.length) {
            statusElement.textContent = stages[currentStage];
        }
        
    }, 500);
}

// Complete scan and show results
function completeScan(results) {
    scanInProgress = false;
    updateScanButton(false);
    
    const progressBar = document.getElementById('scan-progress-bar');
    const statusElement = document.getElementById('scan-status');
    const resultsContainer = document.getElementById('scan-results-display');
    
    if (progressBar) progressBar.style.width = '100%';
    if (statusElement) statusElement.textContent = 'Scan completed';
    
    // Display results
    if (resultsContainer) {
        resultsContainer.innerHTML = formatScanResults(results);
        resultsContainer.style.display = 'block';
    }
    
    // Store results
    scanResults[currentTool] = results;
    
    // Update scan statistics
    updateScanStats();
    
    // Add to recent scans table
    addToRecentScans(currentTool, results);
}

// Format scan results for display
function formatScanResults(results) {
    if (results.error) {
        return `
            <div class="alert alert-danger">
                <h6><i class="fas fa-exclamation-triangle me-2"></i>Scan Error</h6>
                <p>${results.error}</p>
            </div>
        `;
    }
    
    let html = `
        <div class="alert alert-success">
            <h6><i class="fas fa-check-circle me-2"></i>Scan Completed Successfully</h6>
        </div>
        <div class="card bg-dark">
            <div class="card-header">
                <h6><i class="fas fa-chart-bar me-2"></i>Results Summary</h6>
            </div>
            <div class="card-body">
    `;
    
    // Format results based on tool type
    if (results.subdomains) {
        html += `
            <p><strong>Subdomains Found:</strong> ${results.subdomains.length}</p>
            <div class="result-list">
                ${results.subdomains.slice(0, 10).map(sub => `<span class="badge bg-info me-1">${sub}</span>`).join('')}
                ${results.subdomains.length > 10 ? `<span class="text-muted">... and ${results.subdomains.length - 10} more</span>` : ''}
            </div>
        `;
    }
    
    if (results.open_ports) {
        html += `
            <p><strong>Open Ports:</strong> ${results.open_ports.length}</p>
            <div class="result-list">
                ${results.open_ports.map(port => `<span class="badge bg-warning me-1">${port}</span>`).join('')}
            </div>
        `;
    }
    
    if (results.records) {
        html += `<p><strong>DNS Records Found:</strong></p>`;
        Object.keys(results.records).forEach(recordType => {
            if (results.records[recordType].length > 0) {
                html += `
                    <div class="mb-2">
                        <strong>${recordType}:</strong><br>
                        ${results.records[recordType].map(record => `<code class="me-2">${record}</code>`).join('')}
                    </div>
                `;
            }
        });
    }
    
    if (results.status === 'success' && !results.subdomains && !results.open_ports && !results.records) {
        html += `<p class="text-muted">Scan completed successfully. Check the detailed report for more information.</p>`;
    }
    
    html += `
            </div>
        </div>
        <div class="mt-3 text-end">
            <button class="btn btn-outline-secondary btn-sm me-2" onclick="exportScanResults()">
                <i class="fas fa-download"></i> Export Results
            </button>
            <button class="btn btn-outline-info btn-sm" onclick="viewDetailedResults()">
                <i class="fas fa-eye"></i> View Detailed Report
            </button>
        </div>
    `;
    
    return html;
}

// Export scan results
function exportScanResults() {
    if (!scanResults[currentTool]) return;
    
    const data = JSON.stringify(scanResults[currentTool], null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentTool}_scan_results_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    
    URL.revokeObjectURL(url);
    
    if (window.CyberGuard) {
        window.CyberGuard.showToast('Scan results exported', 'success');
    }
}

// View detailed results
function viewDetailedResults() {
    if (!scanResults[currentTool]) return;
    
    const detailWindow = window.open('', '_blank', 'width=800,height=600');
    detailWindow.document.write(`
        <html>
            <head>
                <title>Detailed Scan Results - ${getToolDisplayName(currentTool)}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }
                    pre { background: #000; padding: 15px; border-radius: 5px; overflow: auto; }
                    .header { border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 20px; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>${getToolDisplayName(currentTool)} - Detailed Results</h1>
                    <p>Generated on: ${new Date().toLocaleString()}</p>
                </div>
                <pre>${JSON.stringify(scanResults[currentTool], null, 2)}</pre>
            </body>
        </html>
    `);
}

// Reset tool interface
function resetToolInterface() {
    currentTool = null;
    scanInProgress = false;
    
    const modalBody = document.getElementById('tool-modal-body');
    if (modalBody) {
        modalBody.innerHTML = '';
    }
    
    updateScanButton(false);
}

// Load recent scans
function loadRecentScans() {
    const scansToday = Math.floor(Math.random() * 50) + 1;
    const threatsFound = Math.floor(Math.random() * 5);
    
    updateElementText('scans-today', scansToday);
    updateElementText('threats-found', threatsFound);
}

// Add to recent scans table
function addToRecentScans(toolName, results) {
    const table = document.getElementById('scan-results-table');
    if (!table) return;
    
    const timestamp = new Date().toLocaleString();
    const target = getTargetValue() || 'Unknown';
    const status = results.error ? 'Failed' : 'Complete';
    const findings = getScanFindings(results);
    const riskLevel = getRiskLevelFromResults(results);
    
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${timestamp}</td>
        <td><span class="badge bg-primary">${getToolDisplayName(toolName)}</span></td>
        <td><code>${target}</code></td>
        <td><span class="badge bg-${status === 'Complete' ? 'success' : 'danger'}">${status}</span></td>
        <td>${findings}</td>
        <td><span class="badge bg-${riskLevel.class}">${riskLevel.level}</span></td>
        <td>
            <button class="btn btn-sm btn-outline-info" onclick="viewScanDetails('${toolName}')">
                <i class="fas fa-eye"></i>
            </button>
            <button class="btn btn-sm btn-outline-secondary" onclick="exportScanResult('${toolName}')">
                <i class="fas fa-download"></i>
            </button>
        </td>
    `;
    
    // Add to top of table
    table.insertBefore(row, table.firstChild);
    
    // Keep only last 20 rows
    while (table.children.length > 20) {
        table.removeChild(table.lastChild);
    }
}

// Get scan findings summary
function getScanFindings(results) {
    if (results.error) return 'Error occurred';
    if (results.subdomains) return `${results.subdomains.length} subdomains found`;
    if (results.open_ports) return `${results.open_ports.length} open ports found`;
    if (results.records) {
        const totalRecords = Object.values(results.records).reduce((sum, records) => sum + records.length, 0);
        return `${totalRecords} DNS records found`;
    }
    return 'Scan completed';
}

// Get risk level from results
function getRiskLevelFromResults(results) {
    if (results.error) return { level: 'Error', class: 'danger' };
    
    // Simple risk assessment based on findings
    const openPorts = results.open_ports?.length || 0;
    const subdomains = results.subdomains?.length || 0;
    
    if (openPorts > 10 || subdomains > 50) {
        return { level: 'High', class: 'danger' };
    } else if (openPorts > 5 || subdomains > 20) {
        return { level: 'Medium', class: 'warning' };
    } else {
        return { level: 'Low', class: 'success' };
    }
}

// Update scan statistics
function updateScanStats() {
    // This would typically fetch from an API
    // For now, we'll update the displayed values
}

// Utility functions
function updateElementText(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = value;
    }
}

function refreshScanResults() {
    loadRecentScans();
    if (window.CyberGuard) {
        window.CyberGuard.showToast('Scan results refreshed', 'info');
    }
}

function viewScanDetails(scanId) {
    if (window.CyberGuard) {
        window.CyberGuard.showToast('Loading scan details...', 'info');
    }
}

function exportScanResult(scanId) {
    if (window.CyberGuard) {
        window.CyberGuard.showToast('Exporting scan result...', 'info');
    }
}

// Toggle VirusTotal input type
function toggleVTInputType() {
    const inputType = document.getElementById('vt-input-type')?.value;
    const input = document.getElementById('vt-input');
    
    if (!input) return;
    
    const placeholders = {
        'hash': 'Enter MD5, SHA1, or SHA256 hash',
        'url': 'Enter URL to analyze',
        'domain': 'Enter domain name',
        'ip': 'Enter IP address'
    };
    
    input.placeholder = placeholders[inputType] || 'Enter value to analyze';
}

// Bulk scan functionality
function startBulkScan() {
    const targets = document.getElementById('bulk-targets')?.value.split('\n').filter(t => t.trim());
    
    if (!targets || targets.length === 0) {
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Please enter at least one target', 'warning');
        }
        return;
    }
    
    const selectedTools = [];
    const toolCheckboxes = [
        'bulk-subdomain', 'bulk-port', 'bulk-dns', 
        'bulk-whois', 'bulk-virus', 'bulk-tech'
    ];
    
    toolCheckboxes.forEach(checkboxId => {
        const checkbox = document.getElementById(checkboxId);
        if (checkbox && checkbox.checked) {
            selectedTools.push(checkboxId.replace('bulk-', ''));
        }
    });
    
    if (selectedTools.length === 0) {
        if (window.CyberGuard) {
            window.CyberGuard.showToast('Please select at least one tool', 'warning');
        }
        return;
    }
    
    // Show progress
    const progressDiv = document.getElementById('bulk-scan-progress');
    const progressBar = document.getElementById('bulk-progress-bar');
    const statusText = document.getElementById('bulk-status-text');
    
    if (progressDiv) progressDiv.style.display = 'block';
    
    // Simulate bulk scan progress
    let progress = 0;
    const totalScans = targets.length * selectedTools.length;
    let completedScans = 0;
    
    const interval = setInterval(() => {
        progress = (completedScans / totalScans) * 100;
        
        if (progressBar) progressBar.style.width = progress + '%';
        if (statusText) statusText.textContent = `Scanning ${completedScans + 1} of ${totalScans}...`;
        
        completedScans++;
        
        if (completedScans >= totalScans) {
            clearInterval(interval);
            if (statusText) statusText.textContent = 'Bulk scan completed!';
            
            setTimeout(() => {
                bootstrap.Modal.getInstance(document.getElementById('bulkScanModal')).hide();
                if (window.CyberGuard) {
                    window.CyberGuard.showToast('Bulk scan completed successfully', 'success');
                }
            }, 2000);
        }
    }, 1000);
}

// Export functions for external access
window.SecurityScanner = {
    openTool,
    startScan,
    startBulkScan,
    refreshScanResults,
    exportScanResults
};
