# SecureAccess Monitoring Platform

<p align="center">
  <img src="https://github.com/project-CY033/SecureAccess/blob/main/image/secureaccess-logo.svg" alt="SecureAccess" width="300" height="250">
</p>

<!-- Embed this SVG below in your repo as a separate `.svg` file or inline in a webpage -->

<svg width="300" height="80" viewBox="0 0 600 150" xmlns="http://www.w3.org/2000/svg">
  <style>
    .text { 
      font-family: 'Segoe UI', sans-serif; 
      font-size: 40px; 
      fill: white;
      animation: fadein 2s ease-in-out infinite alternate;
    }
    .shield {
      fill: #00C9A7;
      animation: pulse 1.5s infinite ease-in-out;
    }
    .background {
      fill: #1a1a1a;
    }
    @keyframes fadein {
      0% { opacity: 0.4; }
      100% { opacity: 1; }
    }
    @keyframes pulse {
      0% { transform: scale(1); }
      50% { transform: scale(1.05); }
      100% { transform: scale(1); }
    }
  </style>
  <rect class="background" width="600" height="150" rx="10" />
  <g transform="translate(50,75)">
    <polygon class="shield" points="0,-40 30,-20 30,20 0,40 -30,20 -30,-20" />
    <circle cx="0" cy="0" r="10" fill="#ffffff" />
  </g>
  <text x="120" y="90" class="text">SecureAccess</text>
</svg>


 


## Overview
A SecureAccess monitoring platform built with Flask that provides real-time system monitoring, network traffic analysis, application scanning, and advanced security tools. The platform implements AI-enhanced threat detection, real-time monitoring, and automated security analysis capabilities.

### Core Monitoring Capabilities
- **Real-time System Monitoring**: CPU, memory, disk usage tracking with performance metrics
- **Advanced Process Monitoring**: Malicious activity detection with risk assessment algorithms
- **Network Traffic Analysis**: Connection monitoring with security threat evaluation
- **Application Security Scanning**: APK/EXE file analysis with comprehensive threat detection
- **Browser Security Monitoring**: Automatic website security checks and activity tracking
- **Application Permissions Analysis**: Hidden permission detection and risk assessment


### Security Intelligence
- **SecurityAI Tools Collection**: AI-enhanced cybersecurity tools including subdomain enumeration
- **Real-time Threat Detection**: Automated analysis of suspicious activities
- **Comprehensive Alert System**: Multi-level notification system with severity classification
- **API Security Monitoring**: Detailed usage statistics and vulnerability scanning

## Technology Stack

- **Backend**: Python Flask with SQLAlchemy ORM
- **Frontend**: Bootstrap 5 with real-time JavaScript updates
- **Database**: SQLite with comprehensive data models
- **Security Libraries**: psutil, requests, dns, cryptography
- **Real-time Communication**: WebSocket integration for live updates





# SecureAccess – Prototype Workflow 


![SEcure New](https://github.com/user-attachments/assets/88815e17-44d5-44ee-be78-4793df5ad976)



---

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Initialize the database:
   ```bash
   python main.py
   ```

3. Access the platform at http://localhost:5000



See individual documentation files for each component:
- [Dashboard](./Doc/dashboard.md)
- [Application Permissions - Permission Tracking and Analysis](./Doc/app-permissions.md)
- [API Monitor - Comprehensive API Security and Monitoring](./Doc/api-monitor.md)
- [Application Scanner - Advanced File and Application Analysis](./Doc/app-scanner.md)
- [Process Monitor - Advanced Process Analysis and Threat Detection](./Doc/process-monitor.md)
- [System Monitor - Real-time System Metrics](./Doc/system-monitor.md)
- [Browser Monitor - Web Security Monitoring](./Doc/browser-monitor.md)
- [SecurityAI Tools - AI-Enhanced Security Tools Collection](./Doc/security-ai-scan.md)
- [Network Monitor - Advanced Network Traffic Analysis](./Doc/network-monitor.md)
- [Alerts System - Notification and Alert Management](./Doc/alerts.md)
 

--- 
# Projec Work Flow 
# System Monitor

![System Monitor - visual selection](https://github.com/user-attachments/assets/0e7259a6-f298-42fe-968f-6e304e98090b)


# Process Monitor
![Process Monitor](https://github.com/user-attachments/assets/d3c42edb-cf3f-4e8f-88c9-88afca60d97f)


# Network Monitor

![Network Monitor](https://github.com/user-attachments/assets/8b80f263-f5c7-4eb2-846c-585ce6b6c553)


# 





---


## Security Features
- Real-time threat detection
- Automated response systems
- Comprehensive logging
- Privacy protection mechanisms
- Multi-layered security analysis
