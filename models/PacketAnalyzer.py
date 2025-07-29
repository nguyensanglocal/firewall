import socket
import struct
import os
from datetime import datetime, timedelta
import threading
import binascii
import re
import ssl
import json
from collections import defaultdict, Counter
import ipaddress
from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.tls.handshake import _TLSHandshake
from scapy.layers.dns import DNS
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTP
from scapy.layers.inet6 import IPv6
from scapy.contrib.coap import CoAP
from scapy.layers.l2 import Ether
from scapy.all import ARP, UDP, TCP, Raw, IP

from database import *

class ProtocolAnalyzer:
    """Lớp phân tích chi tiết cho từng giao thức"""
    
    @staticmethod
    def analyze_tls(packet):
        """
        Phân tích chi tiết TLS/SSL packets
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Thông tin chi tiết về TLS packet hoặc None nếu không phải TLS
        """
        try:
            if TLS not in packet:
                return None
                
            tls_info = {
                'version': None,
                'version_name': None,
                'type': None,
                'type_name': None,
                'length': None,
                'has_handshake': False,
                'has_certificate': False,
                'has_application_data': False,
                'cipher_suite': None,
                'cipher_suite_name': None,
                'server_name': None,
                'supported_groups': [],
                'signature_algorithms': [],
                'certificate_info': [],
                'handshake_type': None,
                'compression_method': None,
                'extensions': [],
                'alert_level': None,
                'alert_description': None,
                'session_id': None,
                'random_client': None,
                'random_server': None
            }
            
            # Basic TLS information
            tls_layer = packet[TLS]
            tls_info['version'] = tls_layer.version
            tls_info['type'] = tls_layer.type
            tls_info['length'] = len(tls_layer)
            
            # Map version numbers to names
            version_map = {
                0x0301: 'TLS 1.0',
                0x0302: 'TLS 1.1', 
                0x0303: 'TLS 1.2',
                0x0304: 'TLS 1.3',
                0x0300: 'SSL 3.0'
            }
            tls_info['version_name'] = version_map.get(tls_layer.version, f'Unknown (0x{tls_layer.version:04x})')
            
            # Map content types to names
            type_map = {
                20: 'Change Cipher Spec',
                21: 'Alert',
                22: 'Handshake',
                23: 'Application Data',
                24: 'Heartbeat'
            }
            tls_info['type_name'] = type_map.get(tls_layer.type, f'Unknown ({tls_layer.type})')
            
            # Check for different TLS message types
            tls_info['has_handshake'] = _TLSHandshake in packet
            tls_info['has_certificate'] = TLSCertificate in packet
            tls_info['has_application_data'] = TLSApplicationData in packet
            
            # Analyze Client Hello
            if TLSClientHello in packet:
                client_hello = packet[TLSClientHello]
                tls_info['handshake_type'] = 'Client Hello'
                
                # Session ID
                if hasattr(client_hello, 'session_id') and client_hello.session_id:
                    tls_info['session_id'] = client_hello.session_id.hex()
                
                # Client random
                if hasattr(client_hello, 'random_bytes'):
                    tls_info['random_client'] = client_hello.random_bytes.hex()
                
                # Cipher suites
                if hasattr(client_hello, 'cipher_suites'):
                    tls_info['cipher_suites'] = client_hello.cipher_suites
                
                # Compression methods
                if hasattr(client_hello, 'compression_methods'):
                    tls_info['compression_method'] = client_hello.compression_methods
                
                # Parse extensions
                if hasattr(client_hello, 'extensions') and client_hello.extensions:
                    for ext in client_hello.extensions:
                        ext_info = {'type': ext.type, 'length': ext.length}
                        
                        # Server Name Indication (SNI)
                        if hasattr(ext, 'servernames') and ext.servernames:
                            try:
                                server_name = ext.servernames[0].servername
                                if isinstance(server_name, bytes):
                                    tls_info['server_name'] = server_name.decode('utf-8')
                                else:
                                    tls_info['server_name'] = str(server_name)
                                ext_info['server_name'] = tls_info['server_name']
                            except (UnicodeDecodeError, AttributeError, IndexError):
                                pass
                        
                        # Supported Groups (formerly Elliptic Curves)
                        if hasattr(ext, 'groups'):
                            tls_info['supported_groups'] = ext.groups
                            ext_info['supported_groups'] = ext.groups
                        
                        # Signature Algorithms
                        if hasattr(ext, 'signature_algorithms'):
                            tls_info['signature_algorithms'] = ext.signature_algorithms
                            ext_info['signature_algorithms'] = ext.signature_algorithms
                        
                        # ALPN (Application Layer Protocol Negotiation)
                        if hasattr(ext, 'protocols'):
                            ext_info['alpn_protocols'] = [p.decode() if isinstance(p, bytes) else str(p) for p in ext.protocols]
                        
                        tls_info['extensions'].append(ext_info)
            
            # Analyze Server Hello
            if TLSServerHello in packet:
                server_hello = packet[TLSServerHello]
                tls_info['handshake_type'] = 'Server Hello'
                tls_info['cipher_suite'] = server_hello.cipher_suite
                
                # Server random
                if hasattr(server_hello, 'random_bytes'):
                    tls_info['random_server'] = server_hello.random_bytes.hex()
                
                # Session ID
                if hasattr(server_hello, 'session_id') and server_hello.session_id:
                    tls_info['session_id'] = server_hello.session_id.hex()
                
                # Compression method
                if hasattr(server_hello, 'compression_method'):
                    tls_info['compression_method'] = server_hello.compression_method
                
                # Map common cipher suites
                cipher_suite_map = {
                    0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
                    0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
                    0x003C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
                    0x003D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
                    0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
                    0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
                    0xC013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
                    0xC014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
                    0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
                    0xC028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
                    0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    0x1301: 'TLS_AES_128_GCM_SHA256',
                    0x1302: 'TLS_AES_256_GCM_SHA384',
                    0x1303: 'TLS_CHACHA20_POLY1305_SHA256'
                }
                tls_info['cipher_suite_name'] = cipher_suite_map.get(
                    server_hello.cipher_suite, 
                    f'Unknown (0x{server_hello.cipher_suite:04x})'
                )
                
                # Parse server extensions
                if hasattr(server_hello, 'extensions') and server_hello.extensions:
                    for ext in server_hello.extensions:
                        ext_info = {'type': ext.type, 'length': ext.length}
                        
                        # ALPN selected protocol
                        if hasattr(ext, 'protocols') and ext.protocols:
                            ext_info['selected_alpn'] = ext.protocols[0].decode() if isinstance(ext.protocols[0], bytes) else str(ext.protocols[0])
                        
                        tls_info['extensions'].append(ext_info)
            
            # Analyze Certificate
            if TLSCertificate in packet:
                tls_info['handshake_type'] = 'Certificate'
                cert_layer = packet[TLSCertificate]
                
                try:
                    # Extract certificate information
                    if hasattr(cert_layer, 'certificates') and cert_layer.certificates:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        
                        for cert_data in cert_layer.certificates:
                            try:
                                # Parse certificate
                                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                                
                                cert_info = {
                                    'subject': str(cert.subject),
                                    'issuer': str(cert.issuer),
                                    'serial_number': str(cert.serial_number),
                                    'not_before': cert.not_valid_before.isoformat(),
                                    'not_after': cert.not_valid_after.isoformat(),
                                    'signature_algorithm': cert.signature_algorithm_oid._name,
                                    'version': cert.version.name,
                                    'san': []
                                }
                                
                                # Extract Subject Alternative Names
                                try:
                                    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                    cert_info['san'] = [name.value for name in san_ext.value]
                                except x509.ExtensionNotFound:
                                    pass
                                
                                tls_info['certificate_info'].append(cert_info)
                            except Exception as cert_error:
                                tls_info['certificate_info'].append({'error': str(cert_error)})
                                
                except ImportError:
                    tls_info['certificate_info'].append({'error': 'cryptography library not available'})
                except Exception as cert_error:
                    tls_info['certificate_info'].append({'error': str(cert_error)})
            
            # Analyze other handshake types
            if TLSServerHelloDone in packet:
                tls_info['handshake_type'] = 'Server Hello Done'
            elif TLSClientKeyExchange in packet:
                tls_info['handshake_type'] = 'Client Key Exchange'
            elif TLSServerKeyExchange in packet:
                tls_info['handshake_type'] = 'Server Key Exchange'
            elif TLSFinished in packet:
                tls_info['handshake_type'] = 'Finished'
            
            # Analyze Alert messages
            if TLSAlert in packet:
                alert = packet[TLSAlert]
                tls_info['alert_level'] = alert.level
                tls_info['alert_description'] = alert.description
                
                # Map alert descriptions
                alert_map = {
                    0: 'close_notify',
                    10: 'unexpected_message',
                    20: 'bad_record_mac',
                    21: 'decryption_failed',
                    22: 'record_overflow',
                    30: 'decompression_failure',
                    40: 'handshake_failure',
                    41: 'no_certificate',
                    42: 'bad_certificate',
                    43: 'unsupported_certificate',
                    44: 'certificate_revoked',
                    45: 'certificate_expired',
                    46: 'certificate_unknown',
                    47: 'illegal_parameter',
                    48: 'unknown_ca',
                    49: 'access_denied',
                    50: 'decode_error',
                    51: 'decrypt_error',
                    60: 'export_restriction',
                    70: 'protocol_version',
                    71: 'insufficient_security',
                    80: 'internal_error',
                    90: 'user_canceled',
                    100: 'no_renegotiation'
                }
                tls_info['alert_description_name'] = alert_map.get(alert.description, f'Unknown ({alert.description})')
            
            # Analyze Change Cipher Spec
            if TLSChangeCipherSpec in packet:
                tls_info['handshake_type'] = 'Change Cipher Spec'
            
            # Analyze Application Data
            if TLSApplicationData in packet:
                app_data = packet[TLSApplicationData]
                tls_info['handshake_type'] = 'Application Data'
                tls_info['application_data_length'] = len(app_data.data) if hasattr(app_data, 'data') else 0
            
            return tls_info
            
        except Exception as e:
            return {'error': f'TLS analysis failed: {str(e)}'}

    @staticmethod
    def analyze_dns(packet):
        """Phân tích DNS packets"""
        try:
            if DNS in packet:
                dns_info = {
                    'transaction_id': packet[DNS].id,
                    'flags': str(packet[DNS].flags),
                    'questions': packet[DNS].qdcount,
                    'answers': packet[DNS].ancount,
                    'authority': packet[DNS].nscount,
                    'additional': packet[DNS].arcount,
                    'queries': [],
                    'responses': []
                }
                
                # Extract DNS queries
                if packet[DNS].qd:
                    for q in packet[DNS].qd:
                        dns_info['queries'].append({
                            'name': q.qname.decode() if q.qname else '',
                            'type': q.qtype,
                            'class': q.qclass
                        })
                
                # Extract DNS responses
                if packet[DNS].an:
                    for a in packet[DNS].an:
                        dns_info['responses'].append({
                            'name': a.rrname.decode() if a.rrname else '',
                            'type': a.type,
                            'class': a.rclass,
                            'ttl': a.ttl,
                            'data': str(a.rdata)
                        })
                
                return dns_info
                
        except Exception as e:
            return {'error': str(e)}
        return None
    
    @staticmethod
    def analyze_dhcp(packet):
        """Phân tích DHCP packets"""
        try:
            if DHCP in packet:
                dhcp_info = {
                    'message_type': packet[DHCP].options[0][1],
                    'client_mac': packet[Ether].src if Ether in packet else None,
                    'client_ip': packet[IP].src if IP in packet else None,
                    'server_ip': packet[IP].dst if IP in packet else None,
                    'options': []
                }
                
                # Extract DHCP options
                for option in packet[DHCP].options:
                    if isinstance(option, tuple):
                        dhcp_info['options'].append({
                            'code': option[0],
                            'value': option[1]
                        })
                
                return dhcp_info
                
        except Exception as e:
            return {'error': str(e)}
        return None
    
    @staticmethod
    def analyze_http(packet):
        """Phân tích HTTP packets"""
        try:
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                if any(payload.startswith(method) for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ']):
                    lines = payload.split('\n')
                    request_line = lines[0].split(' ')
                    
                    http_info = {
                        'method': request_line[0],
                        'path': request_line[1] if len(request_line) > 1 else '',
                        'version': request_line[2] if len(request_line) > 2 else '',
                        'headers': {},
                        'user_agent': '',
                        'host': '',
                        'content_length': 0
                    }
                    
                    # Parse headers
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            http_info['headers'][key.strip()] = value.strip()
                    
                    # Extract common headers
                    http_info['user_agent'] = http_info['headers'].get('User-Agent', '')
                    http_info['host'] = http_info['headers'].get('Host', '')
                    http_info['content_length'] = int(http_info['headers'].get('Content-Length', 0))
                    
                    return http_info
                
        except Exception as e:
            return {'error': str(e)}
        return None
    
    @staticmethod
    def analyze_quic(packet):
        """Phân tích QUIC packets (UDP-based)"""
        try:
            if UDP in packet and packet[UDP].dport == 443:
                payload = bytes(packet[UDP].payload)
                if len(payload) > 0:
                    # Basic QUIC header analysis
                    first_byte = payload[0]
                    quic_info = {
                        'version': None,
                        'packet_type': 'Initial' if (first_byte & 0x30) == 0x00 else 'Other',
                        'connection_id': None,
                        'payload_length': len(payload)
                    }
                    
                    # Try to extract version (for long header packets)
                    if first_byte & 0x80:  # Long header
                        if len(payload) >= 5:
                            quic_info['version'] = struct.unpack('>I', payload[1:5])[0]
                    
                    return quic_info
                    
        except Exception as e:
            return {'error': str(e)}
        return None
    
    @staticmethod
    def analyze_arp(packet):
        """Phân tích ARP packets"""
        try:
            if ARP in packet:
                arp_info = {
                    'hardware_type': packet[ARP].hwtype,
                    'protocol_type': packet[ARP].ptype,
                    'hardware_size': packet[ARP].hwlen,
                    'protocol_size': packet[ARP].plen,
                    'operation': packet[ARP].op,
                    'sender_mac': packet[ARP].hwsrc,
                    'sender_ip': packet[ARP].psrc,
                    'target_mac': packet[ARP].hwdst,
                    'target_ip': packet[ARP].pdst,
                    'operation_name': 'Request' if packet[ARP].op == 1 else 'Reply'
                }
                
                return arp_info
                
        except Exception as e:
            return {'error': str(e)}
        return None

class PacketAnalyzer:
    def __init__(self, interface="eth0"):
        self.is_capturing = False
        self.packets = []
        self.packet_count = 0
        self.capture_thread = None
        self.interface = interface
        self.protocol_analyzer = ProtocolAnalyzer()
        
        # Enhanced stats tracking
        self.packet_stats = defaultdict(lambda: {
            'total_packets': 0,
            'bytes_received': 0,
            'bytes_sent': 0,
            'protocols': Counter(),
            'ports': Counter(),
            'connection_attempts': 0,
            'http_requests': 0,
            'dns_queries': 0,
            'tls_handshakes': 0,
            'suspicious_patterns': [],
            'last_activity': None,
            'rate_limit_counter': 0,
            'rate_limit_window': datetime.now(),
            'geographic_info': None,
            'threat_score': 0
        })
        
        # Enhanced threat patterns
        self.threat_patterns = {
            'sql_injection': [
                r'union\s+select', r'drop\s+table', r'insert\s+into',
                r'delete\s+from', r'exec\s*\(', r'xp_cmdshell'
            ],
            'xss': [
                r'<script[^>]*>', r'javascript:', r'on\w+\s*=',
                r'<iframe[^>]*>', r'<object[^>]*>', r'eval\s*\('
            ],
            'path_traversal': [
                r'\.\./', r'\.\.\\', r'/etc/passwd', r'/proc/version',
                r'\\windows\\system32', r'\.\.%2f', r'\.\.%5c'
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*whoami', r';\s*id\s*;',
                r'\|\s*nc\s+', r'&&\s*cat\s+', r'`.*`', r'\$\(.*\)'
            ],
            'ldap_injection': [
                r'\*\)\(\|', r'\*\)\(&', r'\)\(\|', r'\)\(&'
            ],
            'xxe': [
                r'<!ENTITY', r'SYSTEM\s+["\']', r'<!DOCTYPE.*\[.*<!ENTITY'
            ]
        }
        
        
        self.WHITELIST = {'127.0.0.1', '192.168.1.1', '10.0.0.1'}


        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

        
    def get_port_classification(self, port):
        """Phân loại cổng"""
        # Port classifications
        self.port_classifications = {
            'web': [80, 443, 8080, 8443],
            'email': [25, 110, 143, 993, 995],
            'file_transfer': [21, 22, 69, 115],
            'database': [1433, 1521, 3306, 5432],
            'remote_access': [23, 3389, 5900],
            'dns': [53],
            'dhcp': [67, 68],
            'suspicious': [1337, 31337, 4444, 5555, 6666, 7777]
        }
        for category, ports in self.port_classifications.items():
            if port in ports:
                return category
        return 'other'
    
    def analyze_packet_deep(self, packet):
        """Phân tích sâu packet với nhiều giao thức"""
        try:
            self.packet_count += 1
            timestamp = datetime.now()
            
            # Basic packet info
            packet_info = {
                'id': self.packet_count,
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'size': len(packet),
                'protocols': [],
                'layers': {},
                'port': None,
                
            }
            
            # Analyze each layer
            current_layer = packet
            while current_layer:
                layer_name = current_layer.__class__.__name__
                packet_info['protocols'].append(layer_name)

                # Get port if available
                if hasattr(current_layer, 'dport'):
                    packet_info['port'] = current_layer.dport
                    port_classification = self.get_port_classification(current_layer.dport)
                    packet_info['port_classification'] = port_classification
                
                # Store layer info
                if hasattr(current_layer, 'fields_desc'):
                    layer_info = {}
                    for field in current_layer.fields_desc:
                        if hasattr(current_layer, field.name):
                            value = getattr(current_layer, field.name)
                            if value is not None:
                                layer_info[field.name] = str(value)
                    packet_info['layers'][layer_name] = layer_info
                
                current_layer = current_layer.payload if hasattr(current_layer, 'payload') else None
            
            # Specific protocol analysis
            self.analyze_specific_protocols(packet, packet_info)
            
            # Threat analysis
            self.analyze_advanced_threats(packet, packet_info)
            
            # Update statistics
            self.update_enhanced_stats(packet_info)
            
            return packet_info
            
        except Exception as e:
            return {'error': f'Deep analysis failed: {str(e)}'}
    
    def analyze_specific_protocols(self, packet, packet_info):
        """Phân tích các giao thức cụ thể"""
        # IP Analysis
        if IP in packet:
            ip_info = {
                'version': packet[IP].version,
                'ihl': packet[IP].ihl,
                'tos': packet[IP].tos,
                'len': packet[IP].len,
                'id': packet[IP].id,
                'flags': str(packet[IP].flags),
                'frag': packet[IP].frag,
                'ttl': packet[IP].ttl,
                'proto': packet[IP].proto,
                'chksum': packet[IP].chksum,
                'src': packet[IP].src,
                'dst': packet[IP].dst
            }
            packet_info['ip'] = ip_info
        
        # IPv6 Analysis
        if IPv6 in packet:
            ipv6_info = {
                'version': packet[IPv6].version,
                'tc': packet[IPv6].tc,
                'fl': packet[IPv6].fl,
                'plen': packet[IPv6].plen,
                'nh': packet[IPv6].nh,
                'hlim': packet[IPv6].hlim,
                'src': packet[IPv6].src,
                'dst': packet[IPv6].dst
            }
            packet_info['ipv6'] = ipv6_info
        
        # Protocol-specific analysis
        protocols = {
            'tls': self.protocol_analyzer.analyze_tls,
            'dns': self.protocol_analyzer.analyze_dns,
            'dhcp': self.protocol_analyzer.analyze_dhcp,
            'http': self.protocol_analyzer.analyze_http,
            'quic': self.protocol_analyzer.analyze_quic,
            'arp': self.protocol_analyzer.analyze_arp
        }
        
        for proto_name, analyzer_func in protocols.items():
            result = analyzer_func(packet)
            if result:
                packet_info[proto_name] = result
    
    def analyze_advanced_threats(self, packet, packet_info):
        """Phân tích threats nâng cao"""
        threats = []
        
        # DDoS detection
        if IP in packet:
            src_ip = packet[IP].src
            if self.detect_ddos_pattern(src_ip):
                threats.append({
                    'type': 'DDOS_ATTACK',
                    'severity': 5,
                    'details': f'DDoS pattern detected from {src_ip}'
                })
                create_alert(
                    ip=src_ip, 
                    alert_type='DDoS Attack', 
                    severity=5, 
                    message='DDoS pattern detected'
                )
        
        # Port scanning detection
        if TCP in packet:
            if self.detect_port_scan(packet[IP].src, packet[TCP].dport):
                threats.append({
                    'type': 'PORT_SCAN',
                    'severity': 3,
                    'details': f'Port scanning detected'
                })
                create_alert(
                    ip= packet[IP].src,
                    alert_type='Port Scan',
                    severity=3,
                    message='Port scanning detected'
                )
        
        # Malformed packet detection
        if self.detect_malformed_packet(packet):
            threats.append({
                'type': 'MALFORMED_PACKET',
                'severity': 2,
                'details': 'Potentially malformed packet'
            })
            create_alert(
                ip=packet[IP].src if IP in packet else 'Unknown',
                alert_type='Malformed Packet',
                severity=2,
                message='Potentially malformed packet detected'
            )
        
        # DNS tunneling detection
        if DNS in packet:
            if self.detect_dns_tunneling(packet):
                threats.append({
                    'type': 'DNS_TUNNELING',
                    'severity': 4,
                    'details': 'Suspicious DNS activity'
                })
                create_alert(
                    ip=packet[IP].src if IP in packet else 'Unknown',
                    alert_type='DNS Tunneling',
                    severity=4,
                    message='Suspicious DNS activity detected'
                )
        
        packet_info['threats'] = threats
    
    def detect_ddos_pattern(self, src_ip, limit_packet_rate=500, connection_limit=20):
        """Phát hiện pattern DDoS"""
        stats = self.packet_stats[src_ip]
        current_time = datetime.now()
        
        # Check packet rate
        if stats['rate_limit_counter'] > limit_packet_rate:  # 200 packets/minute
            return True
        
        # Check connection attempts
        if stats['connection_attempts'] > connection_limit:
            return True
        
        return False
    
    def detect_port_scan(self, src_ip, dest_port, limit_ports=20):
        """Phát hiện port scanning"""
        stats = self.packet_stats[src_ip]
        
        # Track unique ports accessed
        stats['ports'][dest_port] += 1
        
        # If accessing too many different ports
        if len(stats['ports']) > limit_ports:
            return True
        
        return False
    
    def detect_malformed_packet(self, packet):
        """Phát hiện gói tin malformed"""
        try:
            # Check for unusual packet sizes
            if len(packet) < 20 or len(packet) > 9000:
                return True
            
            # Check for invalid IP header
            if IP in packet:
                if packet[IP].len != len(packet[IP]):
                    return True
            
            # Check for TCP flag combinations
            if TCP in packet:
                flags = packet[TCP].flags
                # Invalid flag combinations
                if flags & 0x06 == 0x06:  # SYN+RST
                    return True
                if flags & 0x05 == 0x05:  # FIN+RST
                    return True
            
            return False
            
        except Exception:
            return True
    
    def detect_dns_tunneling(self, packet):
        """Phát hiện DNS tunneling"""
        try:
            if DNS in packet and packet[DNS].qd:
                query_name = packet[DNS].qd[0].qname.decode()
                
                # Check for unusually long domain names
                if len(query_name) > 100:
                    return True
                
                # Check for high entropy in domain name
                if self.calculate_entropy(query_name) > 4.5:
                    return True
                
                # Check for suspicious TLD patterns
                if any(tld in query_name for tld in ['.tk', '.ml', '.ga', '.cf']):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def calculate_entropy(self, string):
        """Tính entropy của string"""
        from math import log2
        
        if not string:
            return 0
        
        entropy = 0
        for char in set(string):
            p = string.count(char) / len(string)
            if p > 0:
                entropy -= p * log2(p)
        
        return entropy
    
    def update_enhanced_stats(self, packet_info):
        """Cập nhật thống kê nâng cao"""
        if 'ip' in packet_info:
            src_ip = packet_info['ip']['src']
            stats = self.packet_stats[src_ip]
            
            # Update basic stats
            stats['total_packets'] += 1
            stats['bytes_received'] += packet_info['size']
            stats['last_activity'] = datetime.now()
            
            # Update protocol stats
            for protocol in packet_info['protocols']:
                stats['protocols'][protocol] += 1
            
            # Update threat score
            if packet_info.get('threats'):
                threat_score = sum(t['severity'] for t in packet_info['threats'])
                stats['threat_score'] += threat_score
            
            # Rate limiting
            now = datetime.now()
            if (now - stats['rate_limit_window']).seconds > 60:
                stats['rate_limit_counter'] = 0
                stats['rate_limit_window'] = now
            stats['rate_limit_counter'] += 1
    
    def process_packet_scapy(self, packet):
        """Xử lý packet với phân tích nâng cao"""
        try:
            packet_info = self.analyze_packet_deep(packet)
            
            if 'flags' in packet_info:
                packet_info['flags'] = str(packet_info['flags'])
            # Store packet
            self.packets.append(packet_info)
            if len(self.packets) > 2000:  # Increased buffer
                self.packets.pop(0)
            
            # Log to database
            self.log_enhanced_packet(packet_info)
            
            # Emit if socketio available
            if hasattr(self, 'socketio'):
                self.socketio.emit('new_packet', packet_info)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def log_enhanced_packet(self, packet_info):
        """Log packet với thông tin nâng cao"""
        try:
            if 'ip' in packet_info:
                src_ip = packet_info['ip']['src']
                dest_ip = packet_info['ip']['dst']
                method = str(packet_info['protocols'][-1])
                path = packet_info.get('dns', {}).get('queries', [{}])[0].get('name', 'N/A')
                port = packet_info.get('port', None)
            

                
                # Calculate suspicion level
                threat_count = len(packet_info.get('threats', []))
                is_suspicious = threat_count > 0
                threat_level = sum(t['severity'] for t in packet_info.get('threats', []))
                
                log_request_to_db(
                    src_ip, dest_ip, port, 
                    packet_info.get('http', {}).get('user_agent', 'N/A'),
                    200 if not is_suspicious else 403,
                    is_suspicious, threat_level
                )
                
        except Exception as e:
            print(f"Error logging enhanced packet: {e}")
    
    def capture_packets(self):
        """Capture packets với filter nâng cao"""
        print(f"Starting enhanced packet capture on {self.interface}")
        
        # Enhanced filtering
        filter_rule = getattr(self, 'capture_filter', None)
        
        while 1:
            try:    
                sniff(
                    iface=self.interface,
                    prn=self.process_packet_scapy,
                    filter=filter_rule,
                    # stop_filter=lambda x: not self.is_capturing,
                    stop_filter=lambda x: True,  # Always capture
                    store=False,
                    timeout=1
                )
                
            except Exception as e:
                error_msg = f'Enhanced capture error: {str(e)}'
                if hasattr(self, 'socketio'):
                    self.socketio.emit('error', {'message': error_msg})
                else:
                    print(f'Error: {error_msg}')
        print("Packet capture stopped.")
    
    def get_protocol_statistics(self):
        """Lấy thống kê giao thức"""
        protocol_stats = Counter()
        threat_stats = Counter()
        
        for stats in self.packet_stats.values():
            protocol_stats.update(stats['protocols'])
            if stats['threat_score'] > 0:
                threat_stats['high_threat'] += 1
            else:
                threat_stats['normal'] += 1
        
        return {
            'protocols': dict(protocol_stats),
            'threats': dict(threat_stats),
            'total_ips': len(self.packet_stats)
        }
    
    def get_traffic_summary(self):
        """Lấy tóm tắt traffic"""
        summary = {
            'total_packets': sum(stats['total_packets'] for stats in self.packet_stats.values()),
            'total_bytes': sum(stats['bytes_received'] for stats in self.packet_stats.values()),
            'active_ips': len(self.packet_stats),
            'protocol_distribution': self.get_protocol_statistics(),
            'top_talkers': self.get_top_talkers(),
            'threat_overview': self.get_threat_overview()
        }
        return summary
    
    def get_top_talkers(self, limit=10):
        """Lấy top IP có traffic cao nhất"""
        sorted_ips = sorted(
            self.packet_stats.items(),
            key=lambda x: x[1]['total_packets'],
            reverse=True
        )[:limit]
        
        return [
            {
                'ip': ip,
                'packets': stats['total_packets'],
                'bytes': stats['bytes_received'],
                'protocols': dict(stats['protocols']),
                'threat_score': stats['threat_score']
            }
            for ip, stats in sorted_ips
        ]
    
    def get_threat_overview(self):
        """Lấy tổng quan về threats"""
        high_threat_ips = []
        total_threats = 0
        
        for ip, stats in self.packet_stats.items():
            if stats['threat_score'] > 5:
                high_threat_ips.append({
                    'ip': ip,
                    'threat_score': stats['threat_score'],
                    'packets': stats['total_packets'],
                    'last_activity': stats['last_activity']
                })
                total_threats += stats['threat_score']
        
        return {
            'high_threat_ips': high_threat_ips,
            'total_threat_score': total_threats,
            'threat_count': len(high_threat_ips)
        }
    
    # Existing methods remain the same...
    def start_capture(self, filter_str=None):
        if not self.is_capturing:
            if filter_str:
                self.capture_filter = filter_str
            self.is_capturing = True
            # self.capture_thread = threading.Thread(target=self.capture_packets)
            # self.capture_thread.daemon = True
            # self.capture_thread.start()
            return True
        return False
    
    def start_monitoring(self):
        """Bắt đầu monitoring packets"""
        self.start_capture()
    
    def stop_capture(self):
        self.is_capturing = False
        # if self.capture_thread:
        #     self.capture_thread.join(timeout=1)
        return True
    
    def clear_packets(self):
        self.packets.clear()
        self.packet_count = 0
        self.packet_stats.clear()

# Global instance
packet_analyzer = None

def get_packet_analyzer():
    global packet_analyzer
    if packet_analyzer is None:
        packet_analyzer = PacketAnalyzer(interface="Wi-Fi")
    return packet_analyzer