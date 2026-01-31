import logging
import re
from datetime import datetime
from typing import Dict, List, Optional
from models import db, Device, PolicyRule
import json

logger = logging.getLogger(__name__)

class DeviceIdentifier:
    def __init__(self):
        self.mac_to_device = {}
        self.ip_to_mac = {}
        self.vendor_oui_map = self._load_vendor_oui()
    
    def _load_vendor_oui(self):
        oui_map = {
            '00:1A:2B': 'Cisco',
            '00:08:74': 'Dell',
            '08:00:27': 'Cadence Design',
            'AC:DE:48': 'NVIDIA',
            'B8:27:EB': 'Raspberry Pi',
            '52:54:00': 'QEMU',
            'FA:16:3E': 'OpenStack',
            '00:50:F2': 'Microsoft',
            '00:1F:5B': 'Apple',
            '00:23:6C': 'Apple',
            '28:25:A1': 'Apple',
            '90:A2:DA': 'Apple',
            'D4:6D:6D': 'Apple',
            '44:55:66': 'Samsung',
            'A0:AB:CD': 'Google',
            'DC:A6:32': 'Nest',
        }
        return oui_map
    
    def identify_device_by_mac(self, mac_address):
        try:
            device = Device.query.filter_by(mac_address=mac_address).first()
            if device:
                device.last_seen = datetime.utcnow()
                db.session.commit()
                return device
            
            device = Device(
                mac_address=mac_address,
                device_type=self._guess_device_type(mac_address),
                policy_level='medium'
            )
            db.session.add(device)
            db.session.commit()
            
            logger.info(f"New device discovered: {mac_address}")
            return device
        
        except Exception as e:
            logger.error(f"Error identifying device: {e}")
            return None
    
    def identify_device_by_ip(self, ip_address, mac_address=None):
        try:
            if mac_address:
                self.ip_to_mac[ip_address] = mac_address
                return self.identify_device_by_mac(mac_address)
            
            if ip_address in self.ip_to_mac:
                mac_address = self.ip_to_mac[ip_address]
                return self.identify_device_by_mac(mac_address)
            
            return None
        
        except Exception as e:
            logger.error(f"Error identifying device by IP: {e}")
            return None
    
    def _guess_device_type(self, mac_address):
        try:
            oui = mac_address[:8].upper()
            
            for prefix, vendor in self.vendor_oui_map.items():
                if mac_address.upper().startswith(prefix):
                    if 'Raspberry' in vendor:
                        return 'IoT Device'
                    elif 'Apple' in vendor:
                        return 'Mobile Device'
                    elif 'Google' in vendor or 'Nest' in vendor:
                        return 'Smart Home'
                    elif 'Microsoft' in vendor:
                        return 'Computer'
                    elif 'Samsung' in vendor:
                        return 'Mobile Device'
            
            return 'Unknown Device'
        
        except Exception as e:
            logger.error(f"Error guessing device type: {e}")
            return 'Unknown Device'
    
    def update_device_info(self, mac_address, device_name=None, device_type=None, os=None):
        try:
            device = Device.query.filter_by(mac_address=mac_address).first()
            if device:
                if device_name:
                    device.device_name = device_name
                if device_type:
                    device.device_type = device_type
                if os:
                    device.os = os
                
                db.session.commit()
                logger.info(f"Device {mac_address} updated")
                return device
        
        except Exception as e:
            logger.error(f"Error updating device info: {e}")
            db.session.rollback()
        
        return None
    
    def set_device_policy(self, mac_address, policy_level, is_trusted=None):
        try:
            device = Device.query.filter_by(mac_address=mac_address).first()
            if device:
                device.policy_level = policy_level
                if is_trusted is not None:
                    device.is_trusted = is_trusted
                
                db.session.commit()
                logger.info(f"Device {mac_address} policy set to {policy_level}")
                return device
        
        except Exception as e:
            logger.error(f"Error setting device policy: {e}")
            db.session.rollback()
        
        return None
    
    def identify_device_by_browser_fingerprint(self, ip_address, user_agent, hostname=None):
        """Hybrid identification for web browser packets using IP + browser fingerprint"""
        try:
            # Create a unique fingerprint combining IP, user agent, and hostname
            fingerprint_parts = [ip_address, user_agent]
            if hostname:
                fingerprint_parts.append(hostname)

            browser_fingerprint = "|".join(fingerprint_parts)

            # Look for existing device with this fingerprint
            device = Device.query.filter_by(browser_fingerprint=browser_fingerprint).first()
            if device:
                device.last_seen = datetime.utcnow()
                db.session.commit()
                return device

            # Create new device for this browser session
            device = Device(
                mac_address=None,  # No MAC for browser-based identification
                browser_fingerprint=browser_fingerprint,
                device_type='Web Browser',
                policy_level='medium',
                ip_address=ip_address,
                user_agent=user_agent,
                hostname=hostname
            )
            db.session.add(device)
            db.session.commit()

            logger.info(f"New browser session identified: {browser_fingerprint}")
            return device

        except Exception as e:
            logger.error(f"Error identifying device by browser fingerprint: {e}")
            return None

    def get_devices(self, policy_level=None, device_type=None, is_trusted=None):
        try:
            query = Device.query

            if policy_level:
                query = query.filter_by(policy_level=policy_level)

            if device_type:
                query = query.filter_by(device_type=device_type)

            if is_trusted is not None:
                query = query.filter_by(is_trusted=is_trusted)

            devices = query.all()
            return devices

        except Exception as e:
            logger.error(f"Error getting devices: {e}")
            return []


class PolicyManager:
    def __init__(self):
        self.policies = {}
    
    def create_policy(self, rule_name, policy_level, action, conditions, description=None):
        try:
            policy = PolicyRule(
                rule_name=rule_name,
                policy_level=policy_level,
                action=action,
                conditions=json.dumps(conditions) if isinstance(conditions, dict) else conditions,
                description=description,
                is_active=True
            )
            
            db.session.add(policy)
            db.session.commit()
            
            self.policies[rule_name] = {
                'policy_level': policy_level,
                'action': action,
                'conditions': conditions
            }
            
            logger.info(f"Policy created: {rule_name}")
            return policy
        
        except Exception as e:
            logger.error(f"Error creating policy: {e}")
            db.session.rollback()
            return None
    
    def apply_policy(self, device, packet_info):
        try:
            rules = PolicyRule.query.filter_by(
                policy_level=device.policy_level,
                is_active=True
            ).all()
            
            for rule in rules:
                if self._matches_conditions(packet_info, rule.conditions):
                    action_result = self._execute_action(rule.action, device, packet_info)
                    return {
                        'rule_name': rule.rule_name,
                        'action': rule.action,
                        'result': action_result
                    }
            
            return None
        
        except Exception as e:
            logger.error(f"Error applying policy: {e}")
            return None
    
    def _matches_conditions(self, packet_info, conditions_str):
        try:
            conditions = json.loads(conditions_str) if isinstance(conditions_str, str) else conditions_str
            
            for key, value in conditions.items():
                if key == 'port' and packet_info.get('dst_port') != value:
                    return False
                elif key == 'protocol' and packet_info.get('protocol') != value:
                    return False
                elif key == 'ip_pattern' and not self._matches_ip_pattern(packet_info.get('dst_ip', ''), value):
                    return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error matching conditions: {e}")
            return False
    
    def _matches_ip_pattern(self, ip, pattern):
        try:
            if '*' in pattern:
                pattern = pattern.replace('.', r'\.')
                pattern = pattern.replace('*', r'\d+')
                return bool(re.match(f'^{pattern}$', ip))
            return ip == pattern
        except:
            return False
    
    def _execute_action(self, action, device, packet_info):
        actions = {
            'alert': f"Alert for device {device.mac_address}",
            'block': f"Block traffic to {packet_info.get('dst_ip')}",
            'log': f"Log traffic from {device.mac_address}",
            'throttle': f"Throttle bandwidth for {device.mac_address}",
        }
        
        return actions.get(action, f"Execute action: {action}")
    
    def get_policies(self, policy_level=None):
        try:
            query = PolicyRule.query.filter_by(is_active=True)
            
            if policy_level:
                query = query.filter_by(policy_level=policy_level)
            
            policies = query.all()
            return policies
        
        except Exception as e:
            logger.error(f"Error getting policies: {e}")
            return []
    
    def update_policy(self, rule_id, **kwargs):
        try:
            policy = PolicyRule.query.get(rule_id)
            if policy:
                for key, value in kwargs.items():
                    if hasattr(policy, key):
                        setattr(policy, key, value)
                
                db.session.commit()
                logger.info(f"Policy {rule_id} updated")
                return policy
        
        except Exception as e:
            logger.error(f"Error updating policy: {e}")
            db.session.rollback()
        
        return None
    
    def delete_policy(self, rule_id):
        try:
            policy = PolicyRule.query.get(rule_id)
            if policy:
                db.session.delete(policy)
                db.session.commit()
                logger.info(f"Policy {rule_id} deleted")
                return True
        
        except Exception as e:
            logger.error(f"Error deleting policy: {e}")
            db.session.rollback()
        
        return False
