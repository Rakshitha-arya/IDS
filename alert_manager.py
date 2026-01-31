import logging
import json
from datetime import datetime
from typing import List, Dict
from models import db, Alert, Device
import os

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, log_dir='logs/alerts/'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.alert_handlers = []
    
    def create_alert(self, device_id, alert_type, severity, title, description=None, 
                     packet_info=None, detection_method=None, confidence_score=None):
        try:
            alert = Alert(
                device_id=device_id,
                alert_type=alert_type,
                severity=severity,
                title=title,
                description=description,
                source_ip=packet_info.get('src_ip') if packet_info else None,
                dest_ip=packet_info.get('dst_ip') if packet_info else None,
                source_port=packet_info.get('src_port') if packet_info else None,
                dest_port=packet_info.get('dst_port') if packet_info else None,
                protocol=packet_info.get('protocol') if packet_info else None,
                payload_snippet=packet_info.get('payload')[:200] if packet_info and packet_info.get('payload') else None,
                detection_method=detection_method,
                confidence_score=confidence_score,
                timestamp=datetime.utcnow()
            )
            
            db.session.add(alert)
            db.session.commit()
            
            self._log_alert(alert)
            self._trigger_handlers(alert)
            
            logger.info(f"Alert created: {title} (Severity: {severity})")
            return alert
        
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            db.session.rollback()
            return None
    
    def _log_alert(self, alert):
        try:
            log_file = os.path.join(
                self.log_dir,
                f"alerts_{datetime.utcnow().strftime('%Y%m%d')}.json"
            )
            
            alert_data = {
                'id': alert.id,
                'device_id': alert.device_id,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'title': alert.title,
                'description': alert.description,
                'source_ip': alert.source_ip,
                'dest_ip': alert.dest_ip,
                'source_port': alert.source_port,
                'dest_port': alert.dest_port,
                'protocol': alert.protocol,
                'detection_method': alert.detection_method,
                'confidence_score': alert.confidence_score,
                'timestamp': alert.timestamp.isoformat()
            }
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(alert_data) + '\n')
        
        except Exception as e:
            logger.error(f"Error logging alert: {e}")
    
    def register_handler(self, handler_func):
        self.alert_handlers.append(handler_func)
    
    def _trigger_handlers(self, alert):
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")
    
    def acknowledge_alert(self, alert_id, acknowledged_by, notes=None):
        try:
            alert = Alert.query.get(alert_id)
            if alert:
                alert.acknowledged = True
                alert.acknowledged_by = acknowledged_by
                alert.acknowledged_at = datetime.utcnow()
                alert.notes = notes
                db.session.commit()
                logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
                return alert
        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}")
            db.session.rollback()
        return None
    
    def get_alerts(self, device_id=None, alert_type=None, severity=None, 
                   acknowledged=False, limit=100):
        try:
            query = Alert.query
            
            if device_id:
                query = query.filter_by(device_id=device_id)
            
            if alert_type:
                query = query.filter_by(alert_type=alert_type)
            
            if severity:
                query = query.filter_by(severity=severity)
            
            query = query.filter_by(acknowledged=acknowledged)
            
            alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
            return alerts
        
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def get_alert_statistics(self, device_id=None):
        try:
            query = Alert.query
            
            if device_id:
                query = query.filter_by(device_id=device_id)
            
            total_alerts = query.count()
            
            stats = {
                'total_alerts': total_alerts,
                'by_severity': {
                    'critical': query.filter_by(severity='critical').count(),
                    'high': query.filter_by(severity='high').count(),
                    'medium': query.filter_by(severity='medium').count(),
                    'low': query.filter_by(severity='low').count(),
                },
                'by_type': {},
                'acknowledged': query.filter_by(acknowledged=True).count(),
                'unacknowledged': query.filter_by(acknowledged=False).count(),
            }
            
            alert_types = db.session.query(Alert.alert_type, db.func.count(Alert.id)).group_by(
                Alert.alert_type
            ).all()
            
            for alert_type, count in alert_types:
                stats['by_type'][alert_type] = count
            
            return stats
        
        except Exception as e:
            logger.error(f"Error getting alert statistics: {e}")
            return {}
    
    def generate_report(self, device_id=None, days=7):
        try:
            from datetime import timedelta
            
            start_date = datetime.utcnow() - timedelta(days=days)
            query = Alert.query.filter(Alert.timestamp >= start_date)
            
            if device_id:
                query = query.filter_by(device_id=device_id)
            
            alerts = query.all()
            
            report = {
                'report_date': datetime.utcnow().isoformat(),
                'period_days': days,
                'device_id': device_id,
                'total_alerts': len(alerts),
                'severity_breakdown': {
                    'critical': sum(1 for a in alerts if a.severity == 'critical'),
                    'high': sum(1 for a in alerts if a.severity == 'high'),
                    'medium': sum(1 for a in alerts if a.severity == 'medium'),
                    'low': sum(1 for a in alerts if a.severity == 'low'),
                },
                'type_breakdown': {},
                'top_sources': {},
                'alerts': []
            }
            
            for alert in alerts:
                if alert.alert_type not in report['type_breakdown']:
                    report['type_breakdown'][alert.alert_type] = 0
                report['type_breakdown'][alert.alert_type] += 1
                
                if alert.source_ip:
                    if alert.source_ip not in report['top_sources']:
                        report['top_sources'][alert.source_ip] = 0
                    report['top_sources'][alert.source_ip] += 1
                
                report['alerts'].append({
                    'id': alert.id,
                    'timestamp': alert.timestamp.isoformat(),
                    'severity': alert.severity,
                    'type': alert.alert_type,
                    'title': alert.title,
                    'source_ip': alert.source_ip,
                    'dest_ip': alert.dest_ip,
                })
            
            report['top_sources'] = dict(sorted(
                report['top_sources'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
            
            return report
        
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return {}
