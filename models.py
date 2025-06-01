from app import db
from datetime import datetime
from sqlalchemy import func

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    category = db.Column(db.String(50), nullable=False)  # process, network, file, browser, api
    status = db.Column(db.String(20), default='active')  # active, resolved, dismissed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)

class ProcessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pid = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    cpu_percent = db.Column(db.Float)
    memory_percent = db.Column(db.Float)
    status = db.Column(db.String(50))
    risk_level = db.Column(db.String(20))  # safe, suspicious, malicious
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class NetworkLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    connection_type = db.Column(db.String(20))  # incoming, outgoing
    local_address = db.Column(db.String(100))
    remote_address = db.Column(db.String(100))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))
    status = db.Column(db.String(20))
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_recv = db.Column(db.BigInteger, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FileScanning(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(500), nullable=False)
    file_hash = db.Column(db.String(64))
    file_size = db.Column(db.BigInteger)
    file_type = db.Column(db.String(100))
    scan_result = db.Column(db.String(20))  # clean, suspicious, malicious
    threat_level = db.Column(db.Integer, default=0)  # 0-10 scale
    scan_details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class APILog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    endpoint = db.Column(db.String(500), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    status_code = db.Column(db.Integer)
    response_time = db.Column(db.Float)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    payload_size = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BrowserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    title = db.Column(db.String(500))
    security_score = db.Column(db.Integer)  # 0-100 scale
    has_ssl = db.Column(db.Boolean, default=False)
    risk_factors = db.Column(db.Text)  # JSON string of detected risks
    visit_duration = db.Column(db.Integer)  # seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SystemMetrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cpu_percent = db.Column(db.Float, nullable=False)
    memory_percent = db.Column(db.Float, nullable=False)
    disk_percent = db.Column(db.Float, nullable=False)
    network_sent = db.Column(db.BigInteger, nullable=False)
    network_recv = db.Column(db.BigInteger, nullable=False)
    active_processes = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
