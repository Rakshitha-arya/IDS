from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import logging
import os
from datetime import datetime
from config import config
from models import db, Device, Alert, TrafficLog, PolicyRule, SignatureDetection
from api import create_api
from packet_capture import PacketCapture
from protocol_analyzer import ProtocolAnalyzer
from signature_engine import SignatureEngine
from anomaly_detection import AnomalyDetector
from alert_manager import AlertManager
from device_manager import DeviceIdentifier, PolicyManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

env = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(config[env])

db.init_app(app)
CORS(app)

packet_capture = None
protocol_analyzer = ProtocolAnalyzer()
signature_engine = SignatureEngine()
anomaly_detector = AnomalyDetector()
alert_manager = AlertManager()
device_identifier = DeviceIdentifier()
policy_manager = PolicyManager()

def packet_callback(packet_data):
    try:
        if not packet_data.get('dst_ip'):
            return

        # Analyze packet first to determine if it's a web browser packet
        analysis = protocol_analyzer.analyze_packet(packet_data)

        # Only identify devices for web browser packets (HTTP/HTTPS)
        device_id = None
        device = None

        is_web_packet = (analysis.get('http') and analysis['http'].get('is_http')) or \
                       (analysis.get('https') and analysis['https'].get('is_https'))

        if is_web_packet:
            # Use hybrid identification for web browser packets
            hostname = None
            user_agent = None

            if analysis.get('http') and analysis['http'].get('is_http'):
                hostname = analysis['http'].get('hostname')
                user_agent = analysis['http'].get('user_agent')
            elif analysis.get('https') and analysis['https'].get('is_https'):
                hostname = analysis['https'].get('hostname')
                user_agent = analysis['https'].get('user_agent')

            if user_agent:  # Only identify if we have user agent (browser fingerprint)
                device = device_identifier.identify_device_by_browser_fingerprint(
                    packet_data.get('src_ip'),
                    user_agent,
                    hostname
                )
                device_id = device.id if device else None

        sig_detections = signature_engine.detect(packet_data)
        for detection in sig_detections:
            if device_id:
                alert_manager.create_alert(
                    device_id=device_id,
                    alert_type='Signature Detection',
                    severity=detection['severity'],
                    title=detection['description'],
                    packet_info=detection['packet_info'],
                    detection_method='Signature',
                    confidence_score=0.95
                )

        anomaly_result = anomaly_detector.predict(packet_data)

        if device_id:
            http_method = None
            http_url = None
            tls_version = None
            hostname = None
            user_agent = None

            if analysis.get('http') and analysis['http'].get('is_http'):
                hostname = analysis['http'].get('hostname')
                http_method = analysis['http'].get('method')
                http_url = analysis['http'].get('url')
                user_agent = analysis['http'].get('user_agent')

            if analysis.get('https') and analysis['https'].get('is_https'):
                hostname = analysis['https'].get('hostname')
                user_agent = analysis['https'].get('user_agent')
                tls_version = analysis['https'].get('tls_version')

            traffic_log = TrafficLog(
                device_id=device_id,
                timestamp=datetime.utcnow(),
                source_ip=packet_data.get('src_ip'),
                dest_ip=packet_data.get('dst_ip'),
                source_port=packet_data.get('src_port'),
                dest_port=packet_data.get('dst_port'),
                protocol=packet_data.get('protocol'),
                packet_size=packet_data.get('payload_size', 0),
                hostname=hostname,
                http_method=http_method,
                http_url=http_url,
                user_agent=user_agent,
                tls_version=tls_version,
                is_anomalous=anomaly_result.get('is_anomalous', False),
                anomaly_score=anomaly_result.get('anomaly_score', 0.0)
            )

            db.session.add(traffic_log)
            db.session.commit()

        if anomaly_result.get('is_anomalous') and device_id:
            alert_manager.create_alert(
                device_id=device_id,
                alert_type='Anomaly Detected',
                severity='high',
                title='Anomalous traffic pattern detected',
                packet_info=packet_data,
                detection_method='Anomaly Detection',
                confidence_score=anomaly_result.get('confidence', 0.0)
            )

    except Exception as e:
        logger.error(f"Error in packet callback: {e}")

@app.before_request
def before_request():
    pass

@app.teardown_appcontext
def shutdown_session(exception=None):
    pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def alerts():
    return render_template('alerts.html')

@app.route('/devices')
def devices():
    return render_template('devices.html')

@app.route('/traffic')
def traffic():
    return render_template('traffic.html')

@app.route('/payloads')
def payloads():
    return render_template('payloads.html')

@app.route('/policies')
def policies():
    return render_template('policies.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/dashboard')
def dashboard():
    try:
        total_devices = Device.query.count()
        total_alerts = Alert.query.count()
        critical_alerts = Alert.query.filter_by(severity='critical', acknowledged=False).count()
        
        recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
        
        alerts_data = [{
            'id': a.id,
            'severity': a.severity,
            'title': a.title,
            'timestamp': a.timestamp.isoformat()
        } for a in recent_alerts]
        
        stats = {
            'total_devices': total_devices,
            'total_alerts': total_alerts,
            'critical_alerts': critical_alerts,
            'recent_alerts': alerts_data,
            'packet_stats': packet_capture.get_stats() if packet_capture else {},
            'signature_stats': signature_engine.get_statistics(),
            'anomaly_stats': anomaly_detector.get_statistics()
        }
        
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    try:
        global packet_capture
        
        interface = request.json.get('interface', 'Wi-Fi') if request.json else 'Wi-Fi'
        
        if packet_capture is None:
            packet_capture = PacketCapture(
                interface=interface,
                callback=packet_callback
            )
        
        packet_capture.start()
        
        return jsonify({'message': 'Packet capture started', 'interface': interface})
    
    except Exception as e:
        logger.error(f"Error starting capture: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    try:
        if packet_capture:
            packet_capture.stop()
        
        return jsonify({'message': 'Packet capture stopped'})
    
    except Exception as e:
        logger.error(f"Error stopping capture: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/capture/status', methods=['GET'])
def capture_status():
    try:
        status = {
            'is_capturing': packet_capture.is_capturing if packet_capture else False,
            'stats': packet_capture.get_stats() if packet_capture else {}
        }
        
        return jsonify(status)
    
    except Exception as e:
        logger.error(f"Error getting capture status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/packets', methods=['GET'])
def get_packets():
    try:
        limit = request.args.get('limit', 50, type=int)
        
        if not packet_capture:
            return jsonify({'packets': [], 'total': 0})
        
        packets = packet_capture.get_recent_packets(limit)
        
        packets_data = []
        for p in packets:
            packet_entry = {
                'timestamp': p.get('timestamp'),
                'src_ip': p.get('src_ip'),
                'dst_ip': p.get('dst_ip'),
                'src_port': p.get('src_port'),
                'dst_port': p.get('dst_port'),
                'protocol': p.get('protocol'),
                'payload_size': p.get('payload_size'),
                'service': p.get('service', 'Other'),
            }
            packets_data.append(packet_entry)
        
        return jsonify({'packets': packets_data, 'total': len(packets_data)})
    
    except Exception as e:
        logger.error(f"Error getting packets: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report', methods=['GET'])
def generate_report():
    try:
        device_id = request.args.get('device_id', type=int)
        days = request.args.get('days', 7, type=int)
        
        report = alert_manager.generate_report(device_id=device_id, days=days)
        
        return jsonify(report)
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': str(e)}), 500

def create_app():
    with app.app_context():
        db.create_all()
        create_api(app)
        
        _init_policies()
        _init_signatures()
    
    return app

def _init_policies():
    try:
        if db.session.query(PolicyRule).count() == 0:
            policies = [
                PolicyRule(
                    rule_name='Block Known Malware',
                    policy_level='high',
                    action='block',
                    conditions='{"category": "malware"}',
                    description='Block devices attempting malware connections'
                ),
                PolicyRule(
                    rule_name='Alert on SQL Injection',
                    policy_level='medium',
                    action='alert',
                    conditions='{"pattern": "sql_injection"}',
                    description='Alert on SQL injection attempts'
                ),
            ]
            
            for policy in policies:
                db.session.add(policy)
            
            db.session.commit()
            logger.info("Default policies initialized")
    
    except Exception as e:
        logger.error(f"Error initializing policies: {e}")

def _init_signatures():
    try:
        sig_count = SignatureDetection.query.count()
        if sig_count == 0:
            
            sig_engine = signature_engine
            for sig_id, sig_data in sig_engine.get_signatures().items():
                sig = SignatureDetection(
                    signature_id=sig_id,
                    rule_name=sig_data['category'],
                    pattern=sig_data['pattern'],
                    severity=sig_data['severity'],
                    category=sig_data['category'],
                    description=sig_data['description']
                )
                db.session.add(sig)
            
            db.session.commit()
            logger.info("Default signatures initialized")
    
    except Exception as e:
        logger.warning(f"Signature initialization skipped: {e}")

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
