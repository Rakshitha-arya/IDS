from scapy.all import IP, TCP, UDP, IPv6
from scapy.packet import Raw
import re
import logging
from urllib.parse import urlparse, parse_qs
from datetime import datetime

logger = logging.getLogger(__name__)

class ProtocolAnalyzer:
    def __init__(self):
        self.http_headers_regex = re.compile(r'^([^:]+):\s*(.+)$', re.MULTILINE)
        self.url_regex = re.compile(r'GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS')
        self.suspicious_patterns = {
            'sql_injection': [
                r"(\bunion\b.*\bselect\b)",
                r"(\b(and|or)\b.*\b(1=1|1=2)\b)",
                r"(';.*--|--.*')",
                r"(\bexec\b|\bexecute\b)",
            ],
            'xss': [
                r"(<script[^>]*>|javascript:|onerror=|onload=|onclick=)",
                r"(<iframe|<embed|<object)",
                r"(alert\(|eval\(|innerHTML\s*=)",
            ],
            'command_injection': [
                r"(\$\(|`.*`|\|.*&|\|.*;)",
                r"(;\s*(cat|ls|rm|chmod|curl|wget)\s+)",
                r"(\bnc\b|\bnetcat\b|\bsh\b|\bbash\b)",
            ],
            'directory_traversal': [
                r"(\.\./|\.\.\\)",
                r"(%2e%2e|%252e%252e)",
            ],
        }
    
    def analyze_http(self, packet_data):
        http_info = {
            'is_http': False,
            'method': None,
            'url': None,
            'hostname': None,
            'headers': {},
            'user_agent': None,
            'cookies': None,
            'content_type': None,
            'status_code': None,
        }
        
        try:
            raw_packet = packet_data.get('raw_packet')
            if not raw_packet or not raw_packet.haslayer(Raw):
                return http_info
            
            payload = bytes(raw_packet[Raw].load)
            payload_str = payload.decode('utf-8', errors='ignore')
            
            if 'HTTP/' in payload_str:
                http_info['is_http'] = True
                
                lines = payload_str.split('\r\n')
                if lines[0]:
                    first_line = lines[0].split(' ')
                    if len(first_line) >= 2:
                        http_info['method'] = first_line[0]
                        http_info['url'] = first_line[1]
                
                for line in lines[1:]:
                    if ':' in line:
                        header_name, header_value = line.split(':', 1)
                        header_name = header_name.strip()
                        header_value = header_value.strip()
                        http_info['headers'][header_name] = header_value
                        
                        if header_name.lower() == 'host':
                            http_info['hostname'] = header_value
                        elif header_name.lower() == 'user-agent':
                            http_info['user_agent'] = header_value
                        elif header_name.lower() == 'cookie':
                            http_info['cookies'] = header_value
                        elif header_name.lower() == 'content-type':
                            http_info['content_type'] = header_value
        
        except Exception as e:
            logger.error(f"Error analyzing HTTP: {e}")
        
        return http_info
    
    def analyze_https(self, packet_data):
        https_info = {
            'is_https': False,
            'tls_version': None,
            'cipher_suite': None,
            'certificate_info': None,
            'sni': None,
        }
        
        try:
            raw_packet = packet_data.get('raw_packet')
            if not raw_packet or not raw_packet.haslayer(Raw):
                return https_info
            
            payload = bytes(raw_packet[Raw].load)
            
            if len(payload) >= 5:
                content_type = payload[0]
                version = (payload[1], payload[2])
                
                if content_type == 0x16 and version == (3, 1):
                    https_info['is_https'] = True
                    https_info['tls_version'] = 'TLS 1.0'
                elif content_type == 0x16 and version == (3, 3):
                    https_info['is_https'] = True
                    https_info['tls_version'] = 'TLS 1.2'
                elif content_type == 0x16 and version == (3, 4):
                    https_info['is_https'] = True
                    https_info['tls_version'] = 'TLS 1.3'
                
                if https_info['is_https']:
                    try:
                        sni_start = payload.find(b'\x00')
                        if sni_start > 0:
                            sni_end = payload.find(b'\x00', sni_start + 1)
                            if sni_end > sni_start:
                                https_info['sni'] = payload[sni_start+1:sni_end].decode('utf-8', errors='ignore')
                    except:
                        pass
        
        except Exception as e:
            logger.error(f"Error analyzing HTTPS: {e}")
        
        return https_info
    
    def analyze_dns(self, packet_data):
        dns_info = {
            'is_dns': False,
            'query_name': None,
            'query_type': None,
            'response_code': None,
        }
        
        try:
            if packet_data.get('dst_port') == 53 or packet_data.get('src_port') == 53:
                dns_info['is_dns'] = True
                
                raw_packet = packet_data.get('raw_packet')
                if raw_packet and raw_packet.haslayer(Raw):
                    payload = bytes(raw_packet[Raw].load)
                    
                    if len(payload) >= 12:
                        dns_id = (payload[0] << 8) | payload[1]
                        flags = (payload[2] << 8) | payload[3]
                        qcount = (payload[4] << 8) | payload[5]
                        
                        dns_info['query_id'] = dns_id
                        dns_info['is_response'] = bool(flags & 0x8000)
                        dns_info['query_count'] = qcount
        
        except Exception as e:
            logger.error(f"Error analyzing DNS: {e}")
        
        return dns_info
    
    def detect_suspicious_patterns(self, payload_data):
        findings = {
            'suspicious': False,
            'patterns_found': [],
            'risk_level': 'low',
            'details': []
        }
        
        if not payload_data:
            return findings
        
        try:
            payload_str = payload_data if isinstance(payload_data, str) else str(payload_data)
            payload_lower = payload_str.lower()
            
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    try:
                        if re.search(pattern, payload_lower, re.IGNORECASE):
                            findings['suspicious'] = True
                            findings['patterns_found'].append(category)
                            findings['details'].append(f"Found {category} pattern")
                    except:
                        pass
            
            if findings['suspicious']:
                if 'sql_injection' in findings['patterns_found']:
                    findings['risk_level'] = 'critical'
                elif 'xss' in findings['patterns_found']:
                    findings['risk_level'] = 'high'
                elif 'command_injection' in findings['patterns_found']:
                    findings['risk_level'] = 'critical'
                else:
                    findings['risk_level'] = 'medium'
        
        except Exception as e:
            logger.error(f"Error detecting suspicious patterns: {e}")
        
        return findings
    
    def analyze_packet(self, packet_data):
        analysis = {
            'timestamp': datetime.utcnow().isoformat(),
            'src_ip': packet_data.get('src_ip'),
            'dst_ip': packet_data.get('dst_ip'),
            'src_port': packet_data.get('src_port'),
            'dst_port': packet_data.get('dst_port'),
            'protocol': packet_data.get('protocol'),
            'http': None,
            'https': None,
            'dns': None,
            'suspicious_patterns': None,
        }
        
        try:
            if packet_data.get('service') == 'HTTP':
                analysis['http'] = self.analyze_http(packet_data)
            
            if packet_data.get('service') == 'HTTPS':
                analysis['https'] = self.analyze_https(packet_data)
            
            if packet_data.get('service') == 'DNS':
                analysis['dns'] = self.analyze_dns(packet_data)
            
            if packet_data.get('has_payload'):
                payload = packet_data.get('payload')
                analysis['suspicious_patterns'] = self.detect_suspicious_patterns(payload)
        
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
        
        return analysis
