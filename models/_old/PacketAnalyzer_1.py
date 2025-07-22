import socket
import struct
import os
from datetime import datetime
import threading
import binascii

class PacketAnalyzer:
    def __init__(self):
        self.is_capturing = False
        self.packets = []
        self.packet_count = 0
        self.capture_thread = None
        
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
    
    def capture_packets(self):
        """Bắt gói tin"""
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
                    self.process_packet(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving packet: {e}")
                    break
                    
        except PermissionError:
            self.socketio.emit('error', {'message': 'Cần quyền administrator/root để bắt gói tin'})
        except Exception as e:
            self.socketio.emit('error', {'message': f'Lỗi khi bắt gói tin: {str(e)}'})
    
    def process_packet(self, data):
        """Xử lý gói tin đã bắt"""
        self.packet_count += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        packet_info = {
            'id': self.packet_count,
            'timestamp': timestamp,
            'size': len(data),
            'raw_data': binascii.hexlify(data).decode('utf-8')
        }
        
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
                    elif ip_info['protocol'] == 17 and len(data) >= ip_header_len + 8:  # UDP
                        udp_info = self.parse_udp_header(data[ip_header_len:])
                        packet_info['udp'] = udp_info
                        packet_info['protocol'] = 'UDP'
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
                        elif ip_info['protocol'] == 17 and len(data) >= 14 + ip_header_len + 8:  # UDP
                            udp_info = self.parse_udp_header(data[14 + ip_header_len:])
                            packet_info['udp'] = udp_info
                            packet_info['protocol'] = 'UDP'
                        elif ip_info['protocol'] == 1 and len(data) >= 14 + ip_header_len + 4:  # ICMP
                            icmp_info = self.parse_icmp_header(data[14 + ip_header_len:])
                            packet_info['icmp'] = icmp_info
                            packet_info['protocol'] = 'ICMP'
            
        except Exception as e:
            packet_info['parse_error'] = str(e)
        
        # Lưu gói tin và gửi qua WebSocket
        self.packets.append(packet_info)
        if len(self.packets) > 1000:  # Giới hạn số gói tin lưu trữ
            self.packets.pop(0)
        
        self.socketio.emit('new_packet', packet_info)
    
    def start_capture(self):
        """Bắt đầu bắt gói tin"""
        if not self.is_capturing:
            self.is_capturing = True
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            return True
        return False
    
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

    