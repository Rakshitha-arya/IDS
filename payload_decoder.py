import base64
import json
import re
import logging
from urllib.parse import unquote
from datetime import datetime

logger = logging.getLogger(__name__)

class PayloadDecoder:
    def __init__(self):
        self.max_display_length = 2000
        self.encoding_patterns = {
            'base64': r'^[A-Za-z0-9+/]*={0,2}$',
            'hex': r'^[0-9a-fA-F]*$',
        }
    
    def decode_payload(self, payload_bytes, content_type=None, protocol='TCP'):
        try:
            if not payload_bytes:
                return {
                    'raw': '',
                    'decoded': {},
                    'encoding': 'empty',
                    'size': 0
                }
            
            if isinstance(payload_bytes, str):
                payload_bytes = payload_bytes.encode()
            
            result = {
                'raw': self._truncate_display(payload_bytes[:512]),
                'decoded': {},
                'encoding': self._detect_encoding(payload_bytes),
                'size': len(payload_bytes),
                'protocol': protocol,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if content_type:
                if 'application/json' in content_type:
                    result['decoded'] = self._decode_json(payload_bytes)
                    result['format'] = 'JSON'
                elif 'application/x-www-form-urlencoded' in content_type:
                    result['decoded'] = self._decode_form_urlencoded(payload_bytes)
                    result['format'] = 'FORM'
                elif 'text/html' in content_type:
                    result['decoded'] = self._decode_html(payload_bytes)
                    result['format'] = 'HTML'
                elif 'text/plain' in content_type or 'text' in content_type:
                    result['decoded'] = self._decode_text(payload_bytes)
                    result['format'] = 'TEXT'
            else:
                try:
                    result['decoded'] = self._decode_json(payload_bytes)
                    result['format'] = 'JSON'
                except:
                    result['decoded'] = self._decode_text(payload_bytes)
                    result['format'] = 'TEXT'
            
            return result
        
        except Exception as e:
            logger.error(f"Error decoding payload: {e}")
            return {
                'raw': 'ERROR',
                'decoded': {},
                'encoding': 'unknown',
                'size': len(payload_bytes) if isinstance(payload_bytes, bytes) else 0,
                'error': str(e)
            }
    
    def _detect_encoding(self, data):
        if isinstance(data, bytes):
            try:
                data.decode('utf-8')
                return 'utf-8'
            except:
                pass
            
            try:
                data.decode('ascii')
                return 'ascii'
            except:
                pass
            
            return 'binary'
        return 'string'
    
    def _decode_json(self, payload_bytes):
        try:
            if isinstance(payload_bytes, bytes):
                payload_str = payload_bytes.decode('utf-8', errors='ignore')
            else:
                payload_str = str(payload_bytes)
            
            json_match = re.search(r'\{.*\}', payload_str, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                return json.loads(json_str)
            
            json_match = re.search(r'\[.*\]', payload_str, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                return json.loads(json_str)
        except Exception as e:
            logger.debug(f"JSON decode error: {e}")
        
        return {}
    
    def _decode_form_urlencoded(self, payload_bytes):
        try:
            if isinstance(payload_bytes, bytes):
                payload_str = payload_bytes.decode('utf-8', errors='ignore')
            else:
                payload_str = str(payload_bytes)
            
            form_data = {}
            for pair in payload_str.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    form_data[unquote(key)] = unquote(value)
            
            return form_data
        except Exception as e:
            logger.debug(f"Form decode error: {e}")
            return {}
    
    def _decode_html(self, payload_bytes):
        try:
            if isinstance(payload_bytes, bytes):
                payload_str = payload_bytes.decode('utf-8', errors='ignore')
            else:
                payload_str = str(payload_bytes)
            
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', payload_str, re.IGNORECASE | re.DOTALL)
            forms = re.findall(r'<form[^>]*>.*?</form>', payload_str, re.IGNORECASE | re.DOTALL)
            inputs = re.findall(r'<input[^>]*>', payload_str, re.IGNORECASE)
            
            return {
                'scripts_found': len(scripts),
                'forms_found': len(forms),
                'input_fields': len(inputs),
                'sample_scripts': scripts[:3] if scripts else [],
                'preview': payload_str[:500]
            }
        except Exception as e:
            logger.debug(f"HTML decode error: {e}")
            return {}
    
    def _decode_text(self, payload_bytes):
        try:
            if isinstance(payload_bytes, bytes):
                text = payload_bytes.decode('utf-8', errors='ignore')
            else:
                text = str(payload_bytes)
            
            lines = text.split('\n')
            
            return {
                'lines': len(lines),
                'preview': '\n'.join(lines[:10]),
                'total_chars': len(text)
            }
        except Exception as e:
            logger.debug(f"Text decode error: {e}")
            return {}
    
    def _truncate_display(self, data, length=512):
        try:
            if isinstance(data, bytes):
                try:
                    return data.decode('utf-8', errors='ignore')[:length]
                except:
                    return str(data)[:length]
            return str(data)[:length]
        except:
            return 'BINARY_DATA'
    
    def extract_sensitive_data(self, decoded_payload, content_type=None):
        sensitive = {
            'api_keys': [],
            'credentials': [],
            'email_addresses': [],
            'credit_cards': [],
            'urls': [],
            'suspicious_keywords': []
        }
        
        try:
            payload_str = json.dumps(decoded_payload) if isinstance(decoded_payload, dict) else str(decoded_payload)
            payload_lower = payload_str.lower()
            
            api_key_patterns = [
                r'api[_-]?key["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})',
                r'token["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})',
                r'secret["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})',
            ]
            
            for pattern in api_key_patterns:
                matches = re.findall(pattern, payload_str, re.IGNORECASE)
                sensitive['api_keys'].extend(matches[:5])
            
            credential_patterns = [
                r'(username|user)["\']?\s*[=:]\s*["\']?([^"\',}\s]+)',
                r'(password|pwd|pass)["\']?\s*[=:]\s*["\']?([^"\',}\s]+)',
            ]
            
            for pattern in credential_patterns:
                matches = re.findall(pattern, payload_str, re.IGNORECASE)
                sensitive['credentials'].extend([(m[0], m[1][:20]) for m in matches[:5]])
            
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            sensitive['email_addresses'] = re.findall(email_pattern, payload_str)[:10]
            
            cc_pattern = r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
            sensitive['credit_cards'] = re.findall(cc_pattern, payload_str)[:5]
            
            url_pattern = r'https?://[^\s\'"<>]+'
            sensitive['urls'] = re.findall(url_pattern, payload_str, re.IGNORECASE)[:10]
            
            suspicious_keywords = ['union', 'select', 'script', 'eval', 'exec', 'system', 'chmod', 'admin', 'debug']
            for keyword in suspicious_keywords:
                if keyword in payload_lower:
                    sensitive['suspicious_keywords'].append(keyword)
            
            return sensitive
        
        except Exception as e:
            logger.error(f"Error extracting sensitive data: {e}")
            return sensitive
    
    def analyze_payload_characteristics(self, payload_bytes):
        try:
            if isinstance(payload_bytes, bytes):
                length = len(payload_bytes)
                
                entropy = self._calculate_entropy(payload_bytes)
                
                printable_ratio = sum(1 for b in payload_bytes if 32 <= b < 127) / length if length > 0 else 0
                
                null_byte_count = payload_bytes.count(b'\x00')
                
                return {
                    'length': length,
                    'entropy': entropy,
                    'printable_ratio': printable_ratio,
                    'null_bytes': null_byte_count,
                    'is_mostly_printable': printable_ratio > 0.8,
                    'is_compressed': entropy > 7.5
                }
            
            return {
                'length': len(str(payload_bytes)),
                'entropy': 0,
                'printable_ratio': 1.0,
                'is_mostly_printable': True
            }
        
        except Exception as e:
            logger.error(f"Error analyzing payload characteristics: {e}")
            return {}
    
    def _calculate_entropy(self, data):
        try:
            if not data:
                return 0.0
            
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            length = len(data)
            entropy = 0.0
            
            for count in byte_counts.values():
                probability = count / length
                entropy -= probability * (probability and __import__('math').log2(probability) or 0)
            
            return entropy
        except:
            return 0.0
