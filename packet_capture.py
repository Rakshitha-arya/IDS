from scapy.all import sniff, IP, TCP, UDP, ICMP, IPv6
from scapy.layers.http import HTTP, HTTPRequest
from threading import Thread, Event
from collections import deque
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self, interface=None, buffer_size=10000, callback=None):
        self.interface = interface
        self.buffer_size = buffer_size
        self.packet_buffer = deque(maxlen=buffer_size)
        self.is_capturing = False
        self.capture_thread = None
        self.stop_event = Event()
        self.callback = callback
        self.packet_filters = {
            'protocols': ['TCP'],
            'ports': [80, 443, 8080, 8443],
            'ips': [],
            'mac_addresses': []
        }
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'http_packets': 0,
            'https_packets': 0,
            'other_web_packets': 0
        }
    
    def set_filter(self, filter_type, values):
        if filter_type in self.packet_filters:
            self.packet_filters[filter_type] = values if isinstance(values, list) else [values]
    
    def _packet_handler(self, packet):
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info and self._matches_filter(packet_info):
                self.stats['total_packets'] += 1
                self.packet_buffer.append(packet_info)
                
                if self.callback:
                    self.callback(packet_info)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet):
        try:
            packet_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'raw_packet': packet,
                'layers': []
            }
            
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_data['src_ip'] = ip_layer.src
                packet_data['dst_ip'] = ip_layer.dst
                packet_data['ttl'] = ip_layer.ttl
                packet_data['ip_version'] = 4
                packet_data['layers'].append('IP')
            
            if packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                packet_data['src_ip'] = ipv6_layer.src
                packet_data['dst_ip'] = ipv6_layer.dst
                packet_data['ip_version'] = 6
                packet_data['layers'].append('IPv6')
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_data['src_port'] = tcp_layer.sport
                packet_data['dst_port'] = tcp_layer.dport
                packet_data['protocol'] = 'TCP'
                packet_data['tcp_flags'] = tcp_layer.flags
                self.stats['tcp_packets'] += 1
                packet_data['layers'].append('TCP')
                
                if tcp_layer.dport in [80, 8080]:
                    self.stats['http_packets'] += 1
                    packet_data['service'] = 'HTTP'
                elif tcp_layer.dport in [443, 8443]:
                    self.stats['https_packets'] += 1
                    packet_data['service'] = 'HTTPS'
                else:
                    self.stats['other_web_packets'] += 1
            
            packet_data['payload_size'] = len(packet)
            
            if packet.haslayer('Raw'):
                packet_data['has_payload'] = True
                try:
                    full_payload = bytes(packet['Raw'].load)
                    packet_data['payload'] = full_payload
                    packet_data['payload_display'] = full_payload[:512]
                except:
                    pass
            
            return packet_data
        except Exception as e:
            logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _matches_filter(self, packet_info):
        if 'protocols' in self.packet_filters and self.packet_filters['protocols']:
            protocol = packet_info.get('protocol')
            if protocol and protocol not in self.packet_filters['protocols']:
                return False
        
        if 'ports' in self.packet_filters and self.packet_filters['ports']:
            src_port = packet_info.get('src_port')
            dst_port = packet_info.get('dst_port')
            if not (src_port in self.packet_filters['ports'] or 
                   dst_port in self.packet_filters['ports']):
                return False
        
        if 'ips' in self.packet_filters and self.packet_filters['ips']:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            if not (src_ip in self.packet_filters['ips'] or 
                   dst_ip in self.packet_filters['ips']):
                return False
        
        return True
    
    def start(self):
        if not self.is_capturing:
            self.is_capturing = True
            self.stop_event.clear()
            self.capture_thread = Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()
            logger.info(f"Packet capture started on interface: {self.interface}")
    
    def _capture_loop(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                stop_filter=lambda x: self.stop_event.is_set(),
                store=False
            )
        except Exception as e:
            logger.error(f"Capture loop error: {e}")
            self.is_capturing = False
    
    def stop(self):
        if self.is_capturing:
            self.stop_event.set()
            self.is_capturing = False
            logger.info("Packet capture stopped")
    
    def get_recent_packets(self, count=100):
        packets = list(self.packet_buffer)
        return packets[-count:] if count else packets
    
    def get_stats(self):
        return self.stats.copy()
    
    def clear_buffer(self):
        self.packet_buffer.clear()
