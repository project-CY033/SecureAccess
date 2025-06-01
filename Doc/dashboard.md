# Dashboard - Main Monitoring Interface

## Overview
The dashboard serves as the central command center for the cybersecurity monitoring platform, providing real-time system overview and security status at a glance.

## Methodology

### Real-time Data Aggregation
The dashboard implements a continuous data polling mechanism that aggregates information from multiple monitoring modules:

1. **System Metrics Collection**: Uses `psutil` library to gather CPU, memory, and disk usage
2. **Security Alert Aggregation**: Queries active alerts from the database with severity classification
3. **Network Activity Summary**: Processes network connection data for security analysis
4. **Process Risk Assessment**: Analyzes running processes for potential threats

### Algorithm Implementation

#### Security Status Algorithm
```python
def calculate_security_status(alerts, processes, network_activity):
    risk_score = 0
    
    # Alert-based scoring
    for alert in alerts:
        if alert.severity == 'critical':
            risk_score += 10
        elif alert.severity == 'high':
            risk_score += 5
        elif alert.severity == 'medium':
            risk_score += 2
    
    # Process-based scoring
    suspicious_processes = filter_suspicious_processes(processes)
    risk_score += len(suspicious_processes) * 3
    
    # Network-based scoring
    if network_activity.suspicious_connections > 0:
        risk_score += network_activity.suspicious_connections * 2
    
    return classify_risk_level(risk_score)
```

### Data Processing Approach

#### 1. Performance Metrics Processing
- **CPU Usage**: Calculated using `psutil.cpu_percent()` with 1-second interval
- **Memory Usage**: Virtual memory statistics processed for percentage calculation
- **Disk Usage**: Root filesystem usage analysis with capacity planning alerts

#### 2. Security Metrics Compilation
- **Active Threats**: Real-time counting of unresolved security alerts
- **Risk Assessment**: Weighted scoring based on threat severity and frequency
- **Trend Analysis**: Historical data comparison for pattern recognition

### Real-time Updates
The dashboard implements WebSocket connections for live data streaming:
- Updates every 5 seconds for system metrics
- Immediate updates for security alerts
- Background polling for network activity changes

## How It Works

### Data Flow
1. **Collection Phase**: Background services collect data from system APIs
2. **Processing Phase**: Raw data is analyzed and classified for security risks
3. **Storage Phase**: Processed data is stored in SQLite database with timestamps
4. **Presentation Phase**: Dashboard queries recent data and formats for display

### Security Analysis Pipeline
1. **Threat Detection**: Continuous monitoring for suspicious activities
2. **Risk Classification**: Multi-level threat assessment (low, medium, high, critical)
3. **Alert Generation**: Automatic notification creation for significant events
4. **Response Tracking**: Status monitoring for alert resolution

### User Interface Components
- **System Health Cards**: Visual representation of CPU, memory, disk usage
- **Security Status Panel**: Real-time threat level with color-coded indicators
- **Recent Alerts Feed**: Latest security notifications with severity badges
- **Quick Action Buttons**: Direct navigation to detailed monitoring pages

## Technical Implementation

### Backend Processing
- Flask routes handle API requests for dashboard data
- SQLAlchemy ORM manages database queries and relationships
- Background threads maintain continuous monitoring services

### Frontend Visualization
- Bootstrap components for responsive design
- JavaScript fetch API for asynchronous data updates
- Chart.js integration for performance metric visualization
- Real-time DOM updates without page refresh

## Security Considerations
- All data queries include proper input validation
- Database access uses parameterized queries to prevent injection
- Real-time updates implement rate limiting to prevent abuse
- Sensitive system information is filtered before display