import re
import logging
from datetime import datetime
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)

class SignatureEngine:
    def __init__(self):
        self.signatures = {}
        self.detection_history = {}
        self.load_default_signatures()
    
    def load_default_signatures(self):
        default_sigs = {
            'sql_injection_1': {
                'pattern': r"(\bunion\b.*\bselect\b)|(\bor\b.*\b1=1\b)",
                'severity': 'critical',
                'category': 'SQL Injection',
                'description': 'Potential SQL injection attempt'
            },
            'xss_script_tag': {
                'pattern': r'<script[^>]*>|javascript:',
                'severity': 'high',
                'category': 'XSS',
                'description': 'Potential XSS attack with script tag'
            },
            'directory_traversal': {
                'pattern': r'\.\.\/|\.\.\\',
                'severity': 'high',
                'category': 'Directory Traversal',
                'description': 'Potential directory traversal attempt'
            },
            'command_injection': {
                'pattern': r';\s*(cat|ls|rm|chmod|curl|wget|nc|bash|sh)\s+',
                'severity': 'critical',
                'category': 'Command Injection',
                'description': 'Potential command injection attempt'
            },
            'ldap_injection': {
                'pattern': r'\(\*\)|ldap:\/\/.*\*',
                'severity': 'high',
                'category': 'LDAP Injection',
                'description': 'Potential LDAP injection attempt'
            },
            'xxe_attack': {
                'pattern': r'<!DOCTYPE.*ENTITY.*SYSTEM|<\?xml.*<!DOCTYPE',
                'severity': 'high',
                'category': 'XXE',
                'description': 'Potential XXE (XML External Entity) attack'
            },
            'path_traversal_encoded': {
                'pattern': r'%2e%2e|%252e%252e|\.\./|\.\.',
                'severity': 'medium',
                'category': 'Path Traversal',
                'description': 'Encoded path traversal attempt'
            },
            'suspicious_user_agent': {
                'pattern': r'(sqlmap|nikto|nmap|masscan|metasploit)',
                'severity': 'medium',
                'category': 'Reconnaissance',
                'description': 'Suspicious user agent detected'
            },
            'port_scanning': {
                'pattern': r'(nmap|masscan|zmap)',
                'severity': 'medium',
                'category': 'Port Scanning',
                'description': 'Possible port scanning activity'
            },
            'malware_c2': {
                'pattern': r'(emotet|trickbot|mirai|botnet)',
                'severity': 'critical',
                'category': 'Malware C2',
                'description': 'Potential malware C2 communication detected'
            },
        }
        
        for sig_id, sig_data in default_sigs.items():
            self.add_signature(sig_id, sig_data)
    
    def add_signature(self, signature_id: str, signature_data: Dict):
        try:
            pattern = signature_data.get('pattern')
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            
            self.signatures[signature_id] = {
                'pattern': pattern,
                'compiled_pattern': compiled_pattern,
                'severity': signature_data.get('severity', 'medium'),
                'category': signature_data.get('category', 'Unknown'),
                'description': signature_data.get('description', ''),
                'enabled': signature_data.get('enabled', True),
                'match_count': 0
            }
            
            self.detection_history[signature_id] = []
            logger.info(f"Added signature: {signature_id}")
        except Exception as e:
            logger.error(f"Error adding signature {signature_id}: {e}")
    
    def remove_signature(self, signature_id: str):
        if signature_id in self.signatures:
            del self.signatures[signature_id]
            if signature_id in self.detection_history:
                del self.detection_history[signature_id]
            logger.info(f"Removed signature: {signature_id}")
    
    def detect(self, packet_data: Dict) -> List[Dict]:
        detections = []
        
        try:
            payload = packet_data.get('payload')
            if not payload:
                return detections
            
            payload_str = payload if isinstance(payload, str) else str(payload)
            
            for sig_id, sig_info in self.signatures.items():
                if not sig_info.get('enabled', True):
                    continue
                
                try:
                    if sig_info['compiled_pattern'].search(payload_str):
                        sig_info['match_count'] += 1
                        
                        detection = {
                            'signature_id': sig_id,
                            'pattern': sig_info['pattern'],
                            'severity': sig_info['severity'],
                            'category': sig_info['category'],
                            'description': sig_info['description'],
                            'timestamp': datetime.utcnow().isoformat(),
                            'packet_info': {
                                'src_ip': packet_data.get('src_ip'),
                                'dst_ip': packet_data.get('dst_ip'),
                                'src_port': packet_data.get('src_port'),
                                'dst_port': packet_data.get('dst_port'),
                                'protocol': packet_data.get('protocol'),
                            },
                            'match_position': sig_info['compiled_pattern'].search(payload_str).start()
                        }
                        
                        detections.append(detection)
                        self.detection_history[sig_id].append(detection)
                        
                except Exception as e:
                    logger.error(f"Error applying signature {sig_id}: {e}")
        
        except Exception as e:
            logger.error(f"Error in signature detection: {e}")
        
        return detections
    
    def detect_batch(self, packets: List[Dict]) -> List[Dict]:
        all_detections = []
        for packet in packets:
            detections = self.detect(packet)
            all_detections.extend(detections)
        return all_detections
    
    def get_statistics(self) -> Dict:
        stats = {
            'total_signatures': len(self.signatures),
            'enabled_signatures': sum(1 for s in self.signatures.values() if s.get('enabled', True)),
            'total_detections': sum(s['match_count'] for s in self.signatures.values()),
            'signatures_by_severity': {
                'critical': sum(1 for s in self.signatures.values() if s['severity'] == 'critical'),
                'high': sum(1 for s in self.signatures.values() if s['severity'] == 'high'),
                'medium': sum(1 for s in self.signatures.values() if s['severity'] == 'medium'),
                'low': sum(1 for s in self.signatures.values() if s['severity'] == 'low'),
            }
        }
        return stats
    
    def get_detection_history(self, signature_id: str = None, limit: int = 100) -> List[Dict]:
        if signature_id:
            if signature_id in self.detection_history:
                return self.detection_history[signature_id][-limit:]
            return []
        
        all_history = []
        for histories in self.detection_history.values():
            all_history.extend(histories)
        
        all_history.sort(key=lambda x: x['timestamp'], reverse=True)
        return all_history[:limit]
    
    def enable_signature(self, signature_id: str):
        if signature_id in self.signatures:
            self.signatures[signature_id]['enabled'] = True
            logger.info(f"Enabled signature: {signature_id}")
    
    def disable_signature(self, signature_id: str):
        if signature_id in self.signatures:
            self.signatures[signature_id]['enabled'] = False
            logger.info(f"Disabled signature: {signature_id}")
    
    def get_signatures(self) -> Dict:
        return {
            sig_id: {
                'pattern': sig['pattern'],
                'severity': sig['severity'],
                'category': sig['category'],
                'description': sig['description'],
                'enabled': sig.get('enabled', True),
                'match_count': sig['match_count']
            }
            for sig_id, sig in self.signatures.items()
        }
