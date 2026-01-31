from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class Device(db.Model):
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=True, index=True)
    device_name = db.Column(db.String(255))
    device_type = db.Column(db.String(50))
    os = db.Column(db.String(100))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ip_addresses = db.Column(db.Text)
    policy_level = db.Column(db.String(20), default='medium')
    is_trusted = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    # Browser fingerprinting fields for hybrid identification
    browser_fingerprint = db.Column(db.String(500), unique=True, nullable=True, index=True)
    ip_address = db.Column(db.String(15), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    hostname = db.Column(db.String(255), nullable=True)
    
    alerts = db.relationship('Alert', backref='device', lazy=True, cascade='all, delete-orphan')
    traffic_logs = db.relationship('TrafficLog', backref='device', lazy=True, cascade='all, delete-orphan')
    
    def get_ips(self):
        if self.ip_addresses:
            return json.loads(self.ip_addresses)
        return []
    
    def set_ips(self, ips):
        self.ip_addresses = json.dumps(ips)

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    alert_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    source_ip = db.Column(db.String(15))
    dest_ip = db.Column(db.String(15))
    source_port = db.Column(db.Integer)
    dest_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    payload_snippet = db.Column(db.Text)
    detection_method = db.Column(db.String(50))
    confidence_score = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.String(100))
    acknowledged_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)

class TrafficLog(db.Model):
    __tablename__ = 'traffic_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(15), index=True)
    dest_ip = db.Column(db.String(15), index=True)
    source_port = db.Column(db.Integer)
    dest_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    packet_size = db.Column(db.Integer)
    packet_count = db.Column(db.Integer, default=1)
    http_method = db.Column(db.String(10))
    http_url = db.Column(db.Text)
    http_status = db.Column(db.Integer)
    hostname = db.Column(db.String(255))
    user_agent = db.Column(db.Text)
    tls_version = db.Column(db.String(10))
    tls_cipher = db.Column(db.String(100))
    is_anomalous = db.Column(db.Boolean, default=False)
    anomaly_score = db.Column(db.Float)
    payload = db.Column(db.LargeBinary)
    payload_size = db.Column(db.Integer)
    payload_format = db.Column(db.String(50))
    payload_encoding = db.Column(db.String(50))
    payload_characteristics = db.Column(db.Text)
    sensitive_data = db.Column(db.Text)

class PolicyRule(db.Model):
    __tablename__ = 'policy_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(255), unique=True, nullable=False)
    policy_level = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    action = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    conditions = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SignatureDetection(db.Model):
    __tablename__ = 'signature_detections'
    
    id = db.Column(db.Integer, primary_key=True)
    signature_id = db.Column(db.String(100), unique=True, nullable=False)
    rule_name = db.Column(db.String(255), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20))
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    match_count = db.Column(db.Integer, default=0)

class AnomalyModel(db.Model):
    __tablename__ = 'anomaly_models'
    
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(255), unique=True, nullable=False)
    model_version = db.Column(db.String(20))
    model_path = db.Column(db.String(500))
    model_type = db.Column(db.String(50))
    input_features = db.Column(db.Integer)
    output_dimension = db.Column(db.Integer)
    threshold = db.Column(db.Float, default=0.85)
    training_accuracy = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
