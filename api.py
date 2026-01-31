from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
from functools import wraps
import logging
import json
from datetime import datetime
from models import db, Device, Alert, TrafficLog, PolicyRule, SignatureDetection, AnomalyModel
from alert_manager import AlertManager
from device_manager import DeviceIdentifier, PolicyManager
from signature_engine import SignatureEngine
from anomaly_detection import AnomalyDetector
from protocol_analyzer import ProtocolAnalyzer
from packet_capture import PacketCapture
import os

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Missing Authorization header'}), 401
        
        try:
            scheme, token = auth_header.split()
            if scheme.lower() != 'bearer':
                return jsonify({'error': 'Invalid authorization scheme'}), 401
        except ValueError:
            return jsonify({'error': 'Invalid Authorization header'}), 401
        
        return f(*args, **kwargs)
    return decorated

@api_bp.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@api_bp.route('/devices', methods=['GET'])
def get_devices():
    try:
        policy_level = request.args.get('policy_level')
        device_type = request.args.get('device_type')
        is_trusted = request.args.get('is_trusted', type=lambda x: x.lower() == 'true')
        
        query = Device.query
        
        if policy_level:
            query = query.filter_by(policy_level=policy_level)
        if device_type:
            query = query.filter_by(device_type=device_type)
        if is_trusted is not None:
            query = query.filter_by(is_trusted=is_trusted)
        
        devices = query.all()
        
        devices_data = [{
            'id': d.id,
            'mac_address': d.mac_address,
            'device_name': d.device_name,
            'device_type': d.device_type,
            'os': d.os,
            'policy_level': d.policy_level,
            'is_trusted': d.is_trusted,
            'first_seen': d.first_seen.isoformat(),
            'last_seen': d.last_seen.isoformat(),
            'ip_addresses': d.get_ips()
        } for d in devices]
        
        return jsonify({'devices': devices_data, 'total': len(devices_data)})
    
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/devices/<int:device_id>', methods=['GET'])
def get_device(device_id):
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        device_data = {
            'id': device.id,
            'mac_address': device.mac_address,
            'device_name': device.device_name,
            'device_type': device.device_type,
            'os': device.os,
            'policy_level': device.policy_level,
            'is_trusted': device.is_trusted,
            'first_seen': device.first_seen.isoformat(),
            'last_seen': device.last_seen.isoformat(),
            'ip_addresses': device.get_ips(),
            'notes': device.notes
        }
        
        return jsonify(device_data)
    
    except Exception as e:
        logger.error(f"Error getting device: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/devices/<int:device_id>', methods=['PUT'])
def update_device(device_id):
    try:
        device = Device.query.get(device_id)
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        data = request.get_json()
        
        if 'device_name' in data:
            device.device_name = data['device_name']
        if 'device_type' in data:
            device.device_type = data['device_type']
        if 'policy_level' in data:
            device.policy_level = data['policy_level']
        if 'is_trusted' in data:
            device.is_trusted = data['is_trusted']
        if 'notes' in data:
            device.notes = data['notes']
        
        db.session.commit()
        
        return jsonify({'message': 'Device updated successfully'})
    
    except Exception as e:
        logger.error(f"Error updating device: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/alerts', methods=['GET'])
def get_alerts():
    try:
        device_id = request.args.get('device_id', type=int)
        severity = request.args.get('severity')
        acknowledged = request.args.get('acknowledged', type=lambda x: x.lower() == 'true')
        limit = request.args.get('limit', 100, type=int)
        
        query = Alert.query
        
        if device_id:
            query = query.filter_by(device_id=device_id)
        if severity:
            query = query.filter_by(severity=severity)
        if acknowledged is not None:
            query = query.filter_by(acknowledged=acknowledged)
        
        alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
        
        alerts_data = [{
            'id': a.id,
            'device_id': a.device_id,
            'alert_type': a.alert_type,
            'severity': a.severity,
            'title': a.title,
            'description': a.description,
            'source_ip': a.source_ip,
            'dest_ip': a.dest_ip,
            'source_port': a.source_port,
            'dest_port': a.dest_port,
            'protocol': a.protocol,
            'detection_method': a.detection_method,
            'confidence_score': a.confidence_score,
            'timestamp': a.timestamp.isoformat(),
            'acknowledged': a.acknowledged
        } for a in alerts]
        
        return jsonify({'alerts': alerts_data, 'total': len(alerts_data)})
    
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    try:
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        data = request.get_json()
        acknowledged_by = data.get('acknowledged_by', 'API')
        notes = data.get('notes')
        
        alert.acknowledged = True
        alert.acknowledged_by = acknowledged_by
        alert.acknowledged_at = datetime.utcnow()
        alert.notes = notes
        
        db.session.commit()
        
        return jsonify({'message': 'Alert acknowledged'})
    
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/alerts/statistics', methods=['GET'])
def get_alert_statistics():
    try:
        device_id = request.args.get('device_id', type=int)
        
        query = Alert.query
        if device_id:
            query = query.filter_by(device_id=device_id)
        
        total = query.count()
        
        stats = {
            'total_alerts': total,
            'by_severity': {
                'critical': query.filter_by(severity='critical').count(),
                'high': query.filter_by(severity='high').count(),
                'medium': query.filter_by(severity='medium').count(),
                'low': query.filter_by(severity='low').count(),
            },
            'acknowledged': query.filter_by(acknowledged=True).count(),
            'unacknowledged': query.filter_by(acknowledged=False).count(),
        }
        
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting alert statistics: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/policies', methods=['GET'])
def get_policies():
    try:
        policy_level = request.args.get('policy_level')
        action = request.args.get('action')
        
        query = PolicyRule.query.filter_by(is_active=True)
        if policy_level:
            query = query.filter_by(policy_level=policy_level)
        if action:
            query = query.filter_by(action=action)
        
        policies = query.all()
        
        policies_data = [{
            'id': p.id,
            'rule_name': p.rule_name,
            'policy_level': p.policy_level,
            'action': p.action,
            'description': p.description,
            'conditions': p.conditions,
            'created_at': p.created_at.isoformat()
        } for p in policies]
        
        return jsonify({'policies': policies_data, 'total': len(policies_data)})
    
    except Exception as e:
        logger.error(f"Error getting policies: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/policies/<int:policy_id>', methods=['GET'])
def get_policy(policy_id):
    try:
        policy = PolicyRule.query.get(policy_id)
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        
        policy_data = {
            'id': policy.id,
            'rule_name': policy.rule_name,
            'policy_level': policy.policy_level,
            'action': policy.action,
            'description': policy.description,
            'conditions': policy.conditions,
            'created_at': policy.created_at.isoformat()
        }
        
        return jsonify({'policy': policy_data})
    
    except Exception as e:
        logger.error(f"Error getting policy: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/policies', methods=['POST'])
def create_policy():
    try:
        data = request.get_json()
        
        if not data.get('rule_name') or not data.get('conditions'):
            return jsonify({'error': 'Missing required fields'}), 400
        
        policy = PolicyRule(
            rule_name=data.get('rule_name'),
            policy_level=data.get('policy_level', 'medium'),
            action=data.get('action', 'alert'),
            description=data.get('description'),
            conditions=data.get('conditions'),
            is_active=True
        )
        
        db.session.add(policy)
        db.session.commit()
        
        return jsonify({
            'message': 'Policy created successfully',
            'policy': {
                'id': policy.id,
                'rule_name': policy.rule_name,
                'policy_level': policy.policy_level,
                'action': policy.action
            }
        }), 201
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating policy: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/policies/<int:policy_id>', methods=['PUT'])
def update_policy(policy_id):
    try:
        policy = PolicyRule.query.get(policy_id)
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        
        data = request.get_json()
        
        if 'rule_name' in data:
            policy.rule_name = data['rule_name']
        if 'policy_level' in data:
            policy.policy_level = data['policy_level']
        if 'action' in data:
            policy.action = data['action']
        if 'description' in data:
            policy.description = data['description']
        if 'conditions' in data:
            policy.conditions = data['conditions']
        
        db.session.commit()
        
        return jsonify({'message': 'Policy updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating policy: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/policies/<int:policy_id>', methods=['DELETE'])
def delete_policy(policy_id):
    try:
        policy = PolicyRule.query.get(policy_id)
        if not policy:
            return jsonify({'error': 'Policy not found'}), 404
        
        db.session.delete(policy)
        db.session.commit()
        
        return jsonify({'message': 'Policy deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting policy: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/traffic-logs', methods=['GET'])
def get_traffic_logs():
    try:
        device_id = request.args.get('device_id', type=int)
        is_anomalous = request.args.get('is_anomalous', type=lambda x: x.lower() == 'true')
        limit = request.args.get('limit', 100, type=int)
        
        query = TrafficLog.query
        
        if device_id:
            query = query.filter_by(device_id=device_id)
        if is_anomalous is not None:
            query = query.filter_by(is_anomalous=is_anomalous)
        
        logs = query.order_by(TrafficLog.timestamp.desc()).limit(limit).all()
        
        logs_data = [{
            'id': l.id,
            'device_id': l.device_id,
            'timestamp': l.timestamp.isoformat(),
            'source_ip': l.source_ip,
            'dest_ip': l.dest_ip,
            'source_port': l.source_port,
            'dest_port': l.dest_port,
            'protocol': l.protocol,
            'packet_size': l.packet_size,
            'hostname': l.hostname,
            'is_anomalous': l.is_anomalous,
            'anomaly_score': l.anomaly_score
        } for l in logs]
        
        return jsonify({'logs': logs_data, 'total': len(logs_data)})
    
    except Exception as e:
        logger.error(f"Error getting traffic logs: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/signatures', methods=['GET'])
def get_signatures():
    try:
        signatures = SignatureDetection.query.filter_by(is_active=True).all()
        
        sigs_data = [{
            'id': s.id,
            'signature_id': s.signature_id,
            'rule_name': s.rule_name,
            'severity': s.severity,
            'category': s.category,
            'match_count': s.match_count
        } for s in signatures]
        
        return jsonify({'signatures': sigs_data, 'total': len(sigs_data)})
    
    except Exception as e:
        logger.error(f"Error getting signatures: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/payloads', methods=['GET'])
def get_payloads():
    try:
        device_id = request.args.get('device_id', type=int)
        format_type = request.args.get('format')
        has_sensitive = request.args.get('has_sensitive', type=lambda x: x.lower() == 'true')
        limit = request.args.get('limit', 100, type=int)
        
        query = TrafficLog.query.filter(TrafficLog.payload.isnot(None))
        
        if device_id:
            query = query.filter_by(device_id=device_id)
        
        if format_type:
            query = query.filter_by(payload_format=format_type)
        
        if has_sensitive is not None:
            if has_sensitive:
                query = query.filter(TrafficLog.sensitive_data.isnot(None))
            else:
                query = query.filter(TrafficLog.sensitive_data.is_(None))
        
        logs = query.order_by(TrafficLog.timestamp.desc()).limit(limit).all()
        
        logs_data = [{
            'id': l.id,
            'device_id': l.device_id,
            'timestamp': l.timestamp.isoformat(),
            'source_ip': l.source_ip,
            'dest_ip': l.dest_ip,
            'source_port': l.source_port,
            'dest_port': l.dest_port,
            'protocol': l.protocol,
            'payload_size': l.payload_size,
            'payload_format': l.payload_format,
            'payload_encoding': l.payload_encoding,
            'hostname': l.hostname,
            'http_method': l.http_method,
            'http_url': l.http_url
        } for l in logs]
        
        return jsonify({'payloads': logs_data, 'total': len(logs_data)})
    
    except Exception as e:
        logger.error(f"Error getting payloads: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/payloads/<int:traffic_id>', methods=['GET'])
def get_payload_details(traffic_id):
    try:
        log = TrafficLog.query.get(traffic_id)
        if not log:
            return jsonify({'error': 'Traffic log not found'}), 404
        
        payload_display = ''
        if log.payload:
            try:
                payload_display = log.payload[:1000].decode('utf-8', errors='ignore')
            except:
                payload_display = str(log.payload[:500])
        
        characteristics = {}
        if log.payload_characteristics:
            try:
                characteristics = json.loads(log.payload_characteristics)
            except:
                pass
        
        sensitive_data = {}
        if log.sensitive_data:
            try:
                sensitive_data = json.loads(log.sensitive_data)
            except:
                pass
        
        details = {
            'id': log.id,
            'timestamp': log.timestamp.isoformat(),
            'source_ip': log.source_ip,
            'dest_ip': log.dest_ip,
            'source_port': log.source_port,
            'dest_port': log.dest_port,
            'protocol': log.protocol,
            'hostname': log.hostname,
            'http_method': log.http_method,
            'http_url': log.http_url,
            'user_agent': log.user_agent,
            'tls_version': log.tls_version,
            'payload_size': log.payload_size,
            'payload_format': log.payload_format,
            'payload_encoding': log.payload_encoding,
            'payload_display': payload_display,
            'characteristics': characteristics,
            'sensitive_data': sensitive_data
        }
        
        return jsonify(details)
    
    except Exception as e:
        logger.error(f"Error getting payload details: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/payloads/search', methods=['POST'])
def search_payloads():
    try:
        data = request.get_json()
        keyword = data.get('keyword', '')
        device_id = data.get('device_id', type=int)
        limit = data.get('limit', 50)
        
        query = TrafficLog.query.filter(TrafficLog.payload.isnot(None))
        
        if device_id:
            query = query.filter_by(device_id=device_id)
        
        logs = query.order_by(TrafficLog.timestamp.desc()).limit(limit).all()
        
        results = []
        for log in logs:
            if log.payload:
                try:
                    payload_str = log.payload.decode('utf-8', errors='ignore')
                    if keyword.lower() in payload_str.lower():
                        results.append({
                            'id': log.id,
                            'timestamp': log.timestamp.isoformat(),
                            'source_ip': log.source_ip,
                            'dest_ip': log.dest_ip,
                            'payload_size': log.payload_size,
                            'format': log.payload_format,
                            'matched': True
                        })
                except:
                    pass
        
        return jsonify({'results': results, 'total': len(results)})
    
    except Exception as e:
        logger.error(f"Error searching payloads: {e}")
        return jsonify({'error': str(e)}), 500

def create_api(app):
    app.register_blueprint(api_bp)
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({'error': 'Internal server error'}), 500
