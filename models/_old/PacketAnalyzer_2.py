import socket
import struct
import os
from datetime import datetime, timedelta
import threading
import binascii
import re
from collections import defaultdict, Counter
import ipaddress
from scapy.all import sniff, IP, TCP, UDP, Raw, ICMP

from database import *

class PacketAnalyzer:
    def __init__(self, interface="eth0"):
        self.is_capturing = False
        self.packets = []
        self.packet_count = 0
        self.capture_thread = None
        self.interface = interface
        
        self.packet_stats = defaultdict(lambda: {
            'total_packets': 0,
            'bytes_received': 0,
            'bytes_sent': 0,
            'connection_attempts': 0,
            'http_requests': 0,
            'suspicious_patterns': [],
            'last_activity': None,
            'rate_limit_counter': 0,
            'rate_limit_window': datetime.now()
        })
        
        # Pattern matching for HTTP threats
        self.http_patterns = {
            'sql_injection': [
                r'union\s+select', r'drop\s+table', r'insert\s+into',
                r'delete\s+from', r'exec\s*\(', r'script\s*>', r'<\s*script'
            ],
            'xss': [
                r'<script[^>]*>', r'javascript:', r'on\w+\s*=',
                r'<iframe[^>]*>', r'<object[^>]*>'
            ],
            'path_traversal': [
                r'\.\./', r'\.\.\\', r'/etc/passwd', r'/proc/version',
                r'\\windows\\system32'
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*whoami', r';\s*id\s*;',
                r'\|\s*nc\s+', r'&&\s*cat\s+'
            ]
        }
        
        # Whitelist for trusted IPs (example)
        self.WHITELIST = {'127.0.0.1', '192.168.1.1', '15.235.229.239'}
        
    def parse_ethernet_header(self, data):
        """Phân tích Ethernet header"""
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_type = socket.ntohs(eth_header[2])
        
        return {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'type': hex(eth_type),
            'type_name': self.get_ethernet_type_name(eth_type)
        }
    
    def get_ethernet_type_name(self, eth_type):
        """Lấy tên loại Ethernet"""
        types = {
            0x0800: 'IPv4',
            0x86DD: 'IPv6',
            0x0806: 'ARP',
            0x8035: 'RARP'
        }
        return types.get(eth_type, 'Unknown')
    
    def parse_ip_header(self, data):
        """Phân tích IP header"""
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        
        version = (ip_header[0] >> 4) & 0xF
        ihl = ip_header[0] & 0xF
        tos = ip_header[1]
        total_length = ip_header[2]
        identification = ip_header[3]
        flags = ip_header[4] >> 13
        fragment_offset = ip_header[4] & 0x1FFF
        ttl = ip_header[5]
        protocol = ip_header[6]
        checksum = ip_header[7]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return {
            'version': version,
            'header_length': ihl * 4,
            'tos': tos,
            'total_length': total_length,
            'identification': identification,
            'flags': flags,
            'fragment_offset': fragment_offset,
            'ttl': ttl,
            'protocol': protocol,
            'protocol_name': self.get_protocol_name(protocol),
            'checksum': hex(checksum),
            'src_ip': src_ip,
            'dest_ip': dest_ip
        }
    
    def get_protocol_name(self, protocol):
        """Lấy tên giao thức"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            89: 'OSPF'
        }
        return protocols.get(protocol, f'Unknown ({protocol})')
    
    def parse_tcp_header(self, data):
        """Phân tích TCP header"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        data_offset = (tcp_header[4] >> 4) * 4
        flags = tcp_header[5]
        window_size = tcp_header[6]
        checksum = tcp_header[7]
        urgent_ptr = tcp_header[8]
        
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'data_offset': data_offset,
            'flags': flags,
            'flag_names': flag_names,
            'window_size': window_size,
            'checksum': hex(checksum),
            'urgent_ptr': urgent_ptr
        }
    
    def parse_udp_header(self, data):
        """Phân tích UDP header"""
        udp_header = struct.unpack('!HHHH', data[:8])
        
        return {
            'src_port': udp_header[0],
            'dest_port': udp_header[1],
            'length': udp_header[2],
            'checksum': hex(udp_header[3])
        }
    
    def parse_icmp_header(self, data):
        """Phân tích ICMP header"""
        icmp_header = struct.unpack('!BBH', data[:4])
        
        icmp_types = {
            0: 'Echo Reply',
            8: 'Echo Request',
            3: 'Destination Unreachable',
            11: 'Time Exceeded',
            12: 'Parameter Problem'
        }
        
        return {
            'type': icmp_header[0],
            'type_name': icmp_types.get(icmp_header[0], 'Unknown'),
            'code': icmp_header[1],
            'checksum': hex(icmp_header[2])
        }
    
    def analyze_packet_threats(self, packet_info, payload=None):
        """Phân tích từng packet để phát hiện threats"""
        try:
            if 'ip' not in packet_info:
                return
                
            src_ip = packet_info['ip']['src_ip']
            dest_ip = packet_info['ip']['dest_ip']
            
            # Check for public IPs
            for ip in [src_ip, dest_ip]:
                if not ipaddress.ip_address(ip).is_private:
                    pass
                    # print(f"[ALERT] Public IP detected: {ip}")
                    # Here you would call lookup_ip(ip) if database functions are available
            
            # Update packet statistics
            stats = self.packet_stats[src_ip]
            stats['total_packets'] += 1
            stats['bytes_received'] += packet_info['size']
            stats['last_activity'] = datetime.now()
            
            # Check for connection attempts (TCP SYN)
            if 'tcp' in packet_info and 'SYN' in packet_info['tcp']['flag_names']:
                stats['connection_attempts'] += 1
            
            # Analyze HTTP payload if available
            if payload:
                self.analyze_http_payload(src_ip, payload)
            
            # Check packet rate limiting
            self.check_packet_rate_limit(src_ip)
            
            # Detect threat indicators
            threat_indicators = self.detect_packet_threats(src_ip, packet_info)
            
            # Handle threats
            self.handle_packet_threats(src_ip, threat_indicators)
            
        except Exception as e:
            print(f"Error analyzing packet threats: {e}")
    
    def analyze_http_payload(self, src_ip, payload):
        """Phân tích HTTP payload"""
        try:
            stats = self.packet_stats[src_ip]
            
            # Check if it's an HTTP request
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                stats['http_requests'] += 1
                
                # Extract method and path
                lines = payload.split('\n')
                if lines:
                    request_line = lines[0]
                    parts = request_line.split(' ')
                    if len(parts) >= 2:
                        method = parts[0]
                        path = parts[1]
                        
                        # Check for suspicious patterns
                        suspicious_found = []
                        for pattern_type, patterns in self.http_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, payload, re.IGNORECASE):
                                    suspicious_found.append(pattern_type)
                                    break
                        
                        if suspicious_found:
                            stats['suspicious_patterns'].extend(suspicious_found)
                            print(f"[THREAT] Suspicious patterns found from {src_ip}: {suspicious_found}")
                        
                        # Log to database
                        # self.log_packet_to_db(src_ip, method, path, payload, suspicious_found)
                        
        except Exception as e:
            print(f"Error analyzing HTTP payload: {e}")
    
    def check_packet_rate_limit(self, src_ip):
        """Kiểm tra rate limit dựa trên packets"""
        stats = self.packet_stats[src_ip]
        now = datetime.now()
        
        # Reset counter every minute
        if (now - stats['rate_limit_window']).seconds > 60:
            stats['rate_limit_counter'] = 0
            stats['rate_limit_window'] = now
        
        stats['rate_limit_counter'] += 1
    
    def detect_packet_threats(self, src_ip, packet_info):
        """Phát hiện threats từ packet analysis"""
        stats = self.packet_stats[src_ip]
        threats = []
        
        # High packet rate
        if stats['rate_limit_counter'] > 100:  # 100 packets/minute
            threats.append({
                'type': 'HIGH_PACKET_RATE',
                'severity': 3,
                'details': f"Rate: {stats['rate_limit_counter']} packets/min"
            })
        
        # Suspicious patterns in payload
        if stats['suspicious_patterns']:
            unique_patterns = set(stats['suspicious_patterns'])
            threats.append({
                'type': 'MALICIOUS_PAYLOAD',
                'severity': 4,
                'details': f"Patterns found: {list(unique_patterns)}"
            })
        
        # Too many connection attempts
        if stats['connection_attempts'] > 50:
            threats.append({
                'type': 'EXCESSIVE_CONNECTIONS',
                'severity': 2,
                'details': f"Connection attempts: {stats['connection_attempts']}"
            })
        
        # Unusual packet sizes
        if packet_info['size'] > 8000:  # Large packets
            threats.append({
                'type': 'LARGE_PACKET',
                'severity': 1,
                'details': f"Packet size: {packet_info['size']} bytes"
            })
        
        return threats
    
    def handle_packet_threats(self, src_ip, threats):
        """Xử lý threats phát hiện từ packets"""
        if not threats:
            return
            
        # Calculate threat level
        threat_level = sum(threat['severity'] for threat in threats)
        
        # Check whitelist
        if src_ip in self.WHITELIST:
            return
        
        # Handle threats based on severity
        if threat_level >= 5:
            threat_types = [t['type'] for t in threats]
            message = f"CRITICAL packet-level threats from {src_ip}: {threat_types}"
            print(f"[CRITICAL] {message}")
            # Here you would call create_alert() and add_to_blacklist() if database functions are available
            
        elif threat_level >= 3:
            threat_types = [t['type'] for t in threats]
            message = f"HIGH packet-level threats from {src_ip}: {threat_types}"
            print(f"[HIGH] {message}")
        
        # Handle rate limiting
        stats = self.packet_stats[src_ip]
        if stats['rate_limit_counter'] > 100:
            message = f"Packet rate limit exceeded for IP {src_ip}: {stats['rate_limit_counter']} packets/min"
            print(f"[RATE_LIMIT] {message}")
    
    def extract_user_agent(self, payload):
        """Extract User-Agent từ HTTP payload"""
        try:
            match = re.search(r'User-Agent:\s*([^\r\n]+)', payload, re.IGNORECASE)
            return match.group(1) if match else 'Unknown'
        except:
            return 'Unknown'
    
    def get_ip_analysis(self, ip):
        """Lấy phân tích chi tiết cho một IP"""
        return self.packet_stats.get(ip, {})
    
    def cleanup_old_stats(self, hours=24):
        """Dọn dẹp stats cũ"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        for ip in list(self.packet_stats.keys()):
            stats = self.packet_stats[ip]
            if stats.get('last_activity') and stats['last_activity'] < cutoff_time:
                del self.packet_stats[ip]
    
    def capture_packets(self):
        """Bắt gói tin sử dụng Scapy"""
        try:
            print(f"Starting packet capture on interface: {self.interface}")
            
            # Lấy filter nếu có
            filter_rule = getattr(self, 'capture_filter', None)
            if filter_rule:
                print(f"Using filter: {filter_rule}")
            
            # Sử dụng Scapy sniff
            sniff(
                iface=self.interface,
                prn=self.process_packet_scapy,
                filter=filter_rule,  # Có thể thêm filter như "tcp port 80"
                stop_filter=lambda x: not self.is_capturing,
                store=False,
                timeout=1
            )
            
        except PermissionError:
            if hasattr(self, 'socketio'):
                self.socketio.emit('error', {'message': 'Cần quyền administrator/root để bắt gói tin'})
            else:
                print('Error: Cần quyền administrator/root để bắt gói tin')
        except Exception as e:
            if hasattr(self, 'socketio'):
                self.socketio.emit('error', {'message': f'Lỗi khi bắt gói tin: {str(e)}'})
            else:
                print(f'Error: Lỗi khi bắt gói tin: {str(e)}')
    
    def process_packet_scapy(self, packet):
        """Xử lý packet từ Scapy - hiệu quả hơn raw socket parsing"""
        try:
            self.packet_count += 1
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            
            # Tạo packet info từ Scapy packet
            packet_info = {
                'id': self.packet_count,
                'timestamp': timestamp,
                'size': len(packet),
                'raw_data': bytes(packet).hex(),
                # 'raw_data': packet.hexdump() if hasattr(packet, 'hexdump') else str(packet)
            }
            
            # Phân tích IP layer
            if IP in packet:
                ip_layer = packet[IP]
                packet_info['ip'] = {
                    'version': ip_layer.version,
                    'header_length': ip_layer.ihl * 4,
                    'tos': ip_layer.tos,
                    'total_length': ip_layer.len,
                    'identification': ip_layer.id,
                    'flags': str(ip_layer.flags),
                    'fragment_offset': ip_layer.frag,
                    'ttl': ip_layer.ttl,
                    'protocol': ip_layer.proto,
                    'protocol_name': self.get_protocol_name(ip_layer.proto),
                    'checksum': hex(ip_layer.chksum),
                    'src_ip': ip_layer.src,
                    'dest_ip': ip_layer.dst
                }
                
                # Phân tích TCP layer
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    flag_names = []
                    if tcp_layer.flags & 0x01: flag_names.append('FIN')
                    if tcp_layer.flags & 0x02: flag_names.append('SYN')
                    if tcp_layer.flags & 0x04: flag_names.append('RST')
                    if tcp_layer.flags & 0x08: flag_names.append('PSH')
                    if tcp_layer.flags & 0x10: flag_names.append('ACK')
                    if tcp_layer.flags & 0x20: flag_names.append('URG')
                    
                    packet_info['tcp'] = {
                        'src_port': tcp_layer.sport,
                        'dest_port': tcp_layer.dport,
                        'seq_num': tcp_layer.seq,
                        'ack_num': tcp_layer.ack,
                        'data_offset': tcp_layer.dataofs * 4,
                        'flags': str(tcp_layer.flags),
                        'flag_names': flag_names,
                        'window_size': tcp_layer.window,
                        'checksum': hex(tcp_layer.chksum),
                        'urgent_ptr': tcp_layer.urgptr
                    }
                    packet_info['protocol'] = 'TCP'
                
                # Phân tích UDP layer
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info['udp'] = {
                        'src_port': udp_layer.sport,
                        'dest_port': udp_layer.dport,
                        'length': udp_layer.len,
                        'checksum': hex(udp_layer.chksum)
                    }
                    packet_info['protocol'] = 'UDP'
                
                # Phân tích ICMP layer
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    icmp_types = {
                        0: 'Echo Reply',
                        8: 'Echo Request',
                        3: 'Destination Unreachable',
                        11: 'Time Exceeded',
                        12: 'Parameter Problem'
                    }
                    
                    packet_info['icmp'] = {
                        'type': icmp_layer.type,
                        'type_name': icmp_types.get(icmp_layer.type, 'Unknown'),
                        'code': icmp_layer.code,
                        'checksum': hex(icmp_layer.chksum)
                    }
                    packet_info['protocol'] = 'ICMP'
            
            # Trích xuất payload
            payload = None
            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                except:
                    payload = None
            
            # Thực hiện phân tích threats
            self.analyze_packet_threats(packet_info, payload)
            
            # Log packet to database
            try:
                src_ip = packet_info['ip']['src_ip'] if 'ip' in packet_info else 'Unknown'
                method = packet_info['protocol']
                path = 'NA' #packet_info.get('ip', {}).get('dest_ip', 'Unknown')
                suspicious_patterns =  []
                # self.packet_stats[src_ip]['suspicious_patterns']
                self.log_packet_to_db(src_ip, method, path, payload, suspicious_patterns)
            except Exception as e:
                print(f"Error logging packet to DB: {e}")
            # Lưu packet
            self.packets.append(packet_info)
            if len(self.packets) > 1000:  # Giới hạn số gói tin lưu trữ
                self.packets.pop(0)
            
            # Emit packet info if socketio is available
            if hasattr(self, 'socketio'):
                self.socketio.emit('new_packet', packet_info)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
            
    def capture_packets_legacy(self):
        """Phương pháp cũ sử dụng raw socket - giữ lại để tham khảo"""
        try:
            # Tạo raw socket (cần quyền admin/root)
            if os.name == 'nt':  # Windows
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Linux/Unix
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            while self.is_capturing:
                try:
                    data, addr = sock.recvfrom(65535)
                    if not data:
                        continue
                    print(f"Received packet from {addr[0]}:{addr[1]} with size {len(data)} bytes")
                    self.process_packet_legacy(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving packet: {e}")
                    break
                    
        except PermissionError:
            if hasattr(self, 'socketio'):
                self.socketio.emit('error', {'message': 'Cần quyền administrator/root để bắt gói tin'})
            else:
                print('Error: Cần quyền administrator/root để bắt gói tin')
        except Exception as e:
            if hasattr(self, 'socketio'):
                self.socketio.emit('error', {'message': f'Lỗi khi bắt gói tin: {str(e)}'})
            else:
                print(f'Error: Lỗi khi bắt gói tin: {str(e)}')
    
    def process_packet_legacy(self, data):
        """Phương pháp cũ xử lý packet từ raw socket - giữ lại để tham khảo"""
        self.packet_count += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        packet_info = {
            'id': self.packet_count,
            'timestamp': timestamp,
            'size': len(data),
            'raw_data': binascii.hexlify(data).decode('utf-8')
        }
        
        payload = None
        
        try:
            # Phân tích theo hệ điều hành
            if os.name == 'nt':  # Windows - bắt đầu từ IP header
                if len(data) >= 20:
                    ip_info = self.parse_ip_header(data)
                    packet_info['ip'] = ip_info
                    
                    # Phân tích header tầng transport
                    ip_header_len = ip_info['header_length']
                    if ip_info['protocol'] == 6 and len(data) >= ip_header_len + 20:  # TCP
                        tcp_info = self.parse_tcp_header(data[ip_header_len:])
                        packet_info['tcp'] = tcp_info
                        packet_info['protocol'] = 'TCP'
                        
                        # Extract TCP payload
                        tcp_header_len = tcp_info['data_offset']
                        if len(data) > ip_header_len + tcp_header_len:
                            payload_data = data[ip_header_len + tcp_header_len:]
                            try:
                                payload = payload_data.decode('utf-8', errors='ignore')
                            except:
                                payload = None
                                
                    elif ip_info['protocol'] == 17 and len(data) >= ip_header_len + 8:  # UDP
                        udp_info = self.parse_udp_header(data[ip_header_len:])
                        packet_info['udp'] = udp_info
                        packet_info['protocol'] = 'UDP'
                        
                        # Extract UDP payload
                        if len(data) > ip_header_len + 8:
                            payload_data = data[ip_header_len + 8:]
                            try:
                                payload = payload_data.decode('utf-8', errors='ignore')
                            except:
                                payload = None
                                
                    elif ip_info['protocol'] == 1 and len(data) >= ip_header_len + 4:  # ICMP
                        icmp_info = self.parse_icmp_header(data[ip_header_len:])
                        packet_info['icmp'] = icmp_info
                        packet_info['protocol'] = 'ICMP'
                        
            else:  # Linux - bắt đầu từ Ethernet header
                if len(data) >= 14:
                    eth_info = self.parse_ethernet_header(data)
                    packet_info['ethernet'] = eth_info
                    
                    if eth_info['type_name'] == 'IPv4' and len(data) >= 34:
                        ip_info = self.parse_ip_header(data[14:])
                        packet_info['ip'] = ip_info
                        
                        ip_header_len = ip_info['header_length']
                        if ip_info['protocol'] == 6 and len(data) >= 14 + ip_header_len + 20:  # TCP
                            tcp_info = self.parse_tcp_header(data[14 + ip_header_len:])
                            packet_info['tcp'] = tcp_info
                            packet_info['protocol'] = 'TCP'
                            
                            # Extract TCP payload
                            tcp_header_len = tcp_info['data_offset']
                            if len(data) > 14 + ip_header_len + tcp_header_len:
                                payload_data = data[14 + ip_header_len + tcp_header_len:]
                                try:
                                    payload = payload_data.decode('utf-8', errors='ignore')
                                except:
                                    payload = None
                                    
                        elif ip_info['protocol'] == 17 and len(data) >= 14 + ip_header_len + 8:  # UDP
                            udp_info = self.parse_udp_header(data[14 + ip_header_len:])
                            packet_info['udp'] = udp_info
                            packet_info['protocol'] = 'UDP'
                            
                            # Extract UDP payload
                            if len(data) > 14 + ip_header_len + 8:
                                payload_data = data[14 + ip_header_len + 8:]
                                try:
                                    payload = payload_data.decode('utf-8', errors='ignore')
                                except:
                                    payload = None
                                    
                        elif ip_info['protocol'] == 1 and len(data) >= 14 + ip_header_len + 4:  # ICMP
                            icmp_info = self.parse_icmp_header(data[14 + ip_header_len:])
                            packet_info['icmp'] = icmp_info
                            packet_info['protocol'] = 'ICMP'
            
            # Perform threat analysis
            self.analyze_packet_threats(packet_info, payload)
            
        except Exception as e:
            packet_info['parse_error'] = str(e)
        
        # Lưu gói tin và gửi qua WebSocket
        self.packets.append(packet_info)
        if len(self.packets) > 1000:  # Giới hạn số gói tin lưu trữ
            self.packets.pop(0)
        
        # Emit packet info if socketio is available
        if hasattr(self, 'socketio'):
            self.socketio.emit('new_packet', packet_info)
    
    def set_capture_filter(self, filter_str):
        """Thiết lập BPF filter cho packet capture
        
        Ví dụ filters:
        - "tcp port 80" - chỉ HTTP traffic
        - "host 192.168.1.1" - chỉ traffic từ/đến IP cụ thể
        - "tcp and (port 80 or port 443)" - HTTP và HTTPS
        - "icmp" - chỉ ICMP packets
        """
        self.capture_filter = filter_str
    
    def start_capture(self, filter_str=None):
        """Bắt đầu bắt gói tin với optional filter"""
        if not self.is_capturing:
            if filter_str:
                self.set_capture_filter(filter_str)
            
            self.is_capturing = True
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            return True
        return False
    
    def start_monitoring(self):
        """Bắt đầu monitoring packets"""
        self.start_capture()

    def stop_capture(self):
        """Dừng bắt gói tin"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=1)
        return True
    
    def clear_packets(self):
        """Xóa tất cả gói tin"""
        self.packets.clear()
        self.packet_count = 0
        self.packet_stats.clear()
    
    def get_threat_summary(self):
        """Lấy tóm tắt các threats đã phát hiện"""
        summary = {
            'total_ips': len(self.packet_stats),
            'high_risk_ips': [],
            'total_threats': 0,
            'threat_types': Counter()
        }
        
        for ip, stats in self.packet_stats.items():
            if stats['suspicious_patterns']:
                summary['high_risk_ips'].append({
                    'ip': ip,
                    'patterns': list(set(stats['suspicious_patterns'])),
                    'packet_count': stats['total_packets'],
                    'last_activity': stats['last_activity']
                })
                summary['total_threats'] += len(stats['suspicious_patterns'])
                
                for pattern in stats['suspicious_patterns']:
                    summary['threat_types'][pattern] += 1
        
        return summary
    
    def log_packet_to_db(self, src_ip, method, path, payload, suspicious_patterns):
        """Log thông tin từ packet analysis thay vì request"""
        
        user_agent = self.extract_user_agent(payload)
        is_suspicious = bool(suspicious_patterns)
        threat_level = len(suspicious_patterns) * 2
        status_code = 200 if not is_suspicious else 403

        log_request_to_db(
            src_ip, path, method, user_agent, status_code, is_suspicious, threat_level
        )


packet_analyzer = None

def get_packet_analyzer():
    """Lấy instance của PacketAnalyzer, khởi tạo nếu chưa có"""
    global packet_analyzer
    if packet_analyzer is None:
        packet_analyzer = PacketAnalyzer(interface="Wi-Fi")
    return packet_analyzer