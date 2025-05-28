
# Dashboard Page Documentation

## Overview
The dashboard serves as the central command center for the SecureAccess platform, providing real-time security metrics, threat monitoring, and system status information.

## Technical Implementation
- **Backend**: Flask routes in `new_routes.py`
- **Frontend**: HTML/JavaScript with Bootstrap
- **Data Models**: `dashboard_model.py`
- **Real-time Updates**: WebSocket for live metric updates

## Core Components
1. Security Status Cards
   - Protection Status
   - Threat Level
   - Active Services
   - System Health

2. Real-time Monitoring
   - Active Threats
   - Network Traffic
   - System Resources
   - Security Events

## Workflow
1. Initial page load fetches base metrics
2. WebSocket connection established for real-time updates
3. Periodic API calls update non-critical data
4. Event listeners handle user interactions

## Technologies Used
- Flask-SocketIO for real-time communication
- Chart.js for metrics visualization
- Bootstrap for responsive layout
- SQLAlchemy for data persistence
