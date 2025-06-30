#!/usr/bin/env python3
"""
Network Packet Analyzer - Wireshark-like Tool
Công cụ phân tích gói tin mạng tương tự Wireshark
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import socket
import struct
import threading
import time
import json
from datetime import datetime
import binascii
import sys
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

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
            socketio.emit('error', {'message': 'Cần quyền administrator/root để bắt gói tin'})
        except Exception as e:
            socketio.emit('error', {'message': f'Lỗi khi bắt gói tin: {str(e)}'})
    
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
        
        socketio.emit('new_packet', packet_info)
    
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

# Khởi tạo analyzer
analyzer = PacketAnalyzer()

@app.route('/')
def index():
    """Trang chủ"""
    return render_template('index.html')

@app.route('/api/start_capture', methods=['POST'])
def start_capture():
    """API bắt đầu bắt gói tin"""
    if analyzer.start_capture():
        return jsonify({'status': 'success', 'message': 'Bắt đầu bắt gói tin'})
    else:
        return jsonify({'status': 'error', 'message': 'Đã đang bắt gói tin'})

@app.route('/api/stop_capture', methods=['POST'])
def stop_capture():
    """API dừng bắt gói tin"""
    analyzer.stop_capture()
    return jsonify({'status': 'success', 'message': 'Đã dừng bắt gói tin'})

@app.route('/api/clear_packets', methods=['POST'])
def clear_packets():
    """API xóa gói tin"""
    analyzer.clear_packets()
    return jsonify({'status': 'success', 'message': 'Đã xóa tất cả gói tin'})

@app.route('/api/packets')
def get_packets():
    """API lấy danh sách gói tin"""
    return jsonify(analyzer.packets)

@app.route('/api/packet/<int:packet_id>')
def get_packet_detail(packet_id):
    """API lấy chi tiết gói tin"""
    for packet in analyzer.packets:
        if packet['id'] == packet_id:
            return jsonify(packet)
    return jsonify({'error': 'Packet not found'}), 404

@app.route('/api/stats')
def get_stats():
    """API thống kê"""
    protocol_stats = {}
    for packet in analyzer.packets:
        protocol = packet.get('protocol', 'Unknown')
        protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
    
    return jsonify({
        'total_packets': len(analyzer.packets),
        'protocol_stats': protocol_stats,
        'is_capturing': analyzer.is_capturing
    })

if __name__ == '__main__':
    # Tạo thư mục templates nếu chưa có
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Tạo file HTML template
    html_template = '''<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Packet Analyzer</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.0/socket.io.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        .controls {
            display: flex;
            gap: 10px;
        }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .btn-start { background-color: #28a745; color: white; }
        .btn-stop { background-color: #dc3545; color: white; }
        .btn-clear { background-color: #6c757d; color: white; }
        .btn:hover { opacity: 0.8; }
        .stats {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }
        .stat-item {
            text-align: center;
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        .stat-label {
            font-size: 12px;
            color: #666;
        }
        .packet-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        .packet-table th, .packet-table td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            font-size: 12px;
        }
        .packet-table th {
            background-color: #f8f9fa;
            font-weight: bold;
            position: sticky;
            top: 0;
        }
        .packet-table tr:hover {
            background-color: #f5f5f5;
            cursor: pointer;
        }
        .packet-detail {
            margin-top: 20px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 4px;
            display: none;
        }
        .detail-section {
            margin-bottom: 15px;
        }
        .detail-title {
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
            font-size: 14px;
        }
        .detail-content {
            background-color: white;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
        }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 5px;
        }
        .status-capturing { background-color: #28a745; }
        .status-stopped { background-color: #dc3545; }
        .hex-dump {
            font-family: monospace;
            font-size: 11px;
            line-height: 1.4;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            max-height: 200px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Network Packet Analyzer</h1>
            <div class="controls">
                <button class="btn btn-start" onclick="startCapture()">Bắt đầu</button>
                <button class="btn btn-stop" onclick="stopCapture()">Dừng</button>
                <button class="btn btn-clear" onclick="clearPackets()">Xóa</button>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-item">
                <div class="stat-number" id="totalPackets">0</div>
                <div class="stat-label">Tổng gói tin</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" id="tcpPackets">0</div>
                <div class="stat-label">TCP</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" id="udpPackets">0</div>
                <div class="stat-label">UDP</div>
            </div>
            <div class="stat-item">
                <div class="stat-number" id="icmpPackets">0</div>
                <div class="stat-label">ICMP</div>
            </div>
            <div class="stat-item">
                <span class="status-indicator" id="statusIndicator"></span>
                <span id="statusText">Đã dừng</span>
            </div>
        </div>
        
        <div style="max-height: 400px; overflow-y: auto;">
            <table class="packet-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Thời gian</th>
                        <th>Nguồn</th>
                        <th>Đích</th>
                        <th>Giao thức</th>
                        <th>Kích thước</th>
                        <th>Thông tin</th>
                    </tr>
                </thead>
                <tbody id="packetTableBody">
                </tbody>
            </table>
        </div>
        
        <div class="packet-detail" id="packetDetail">
            <h3>Chi tiết gói tin</h3>
            <div id="detailContent"></div>
        </div>
    </div>

    <script>
        const socket = io();
        let packets = [];
        let stats = { total_packets: 0, protocol_stats: {}, is_capturing: false };

        // Kết nối WebSocket
        socket.on('connect', function() {
            console.log('Connected to server');
            updateStats();
        });

        socket.on('new_packet', function(packet) {
            packets.push(packet);
            if (packets.length > 1000) {
                packets.shift();
            }
            addPacketToTable(packet);
            updateStats();
        });

        socket.on('error', function(data) {
            alert('Lỗi: ' + data.message);
        });

        function startCapture() {
            fetch('/api/start_capture', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        updateStatus(true);
                    } else {
                        alert(data.message);
                    }
                });
        }

        function stopCapture() {
            fetch('/api/stop_capture', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    updateStatus(false);
                });
        }

        function clearPackets() {
            fetch('/api/clear_packets', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    packets = [];
                    document.getElementById('packetTableBody').innerHTML = '';
                    document.getElementById('packetDetail').style.display = 'none';
                    updateStats();
                });
        }

        function addPacketToTable(packet) {
            const tbody = document.getElementById('packetTableBody');
            const row = tbody.insertRow(0);
            
            const srcInfo = packet.ip ? packet.ip.src_ip : 'N/A';
            const destInfo = packet.ip ? packet.ip.dest_ip : 'N/A';
            const protocol = packet.protocol || 'Unknown';
            
            let info = '';
            if (packet.tcp) {
                info = `${packet.tcp.src_port} → ${packet.tcp.dest_port} [${packet.tcp.flag_names.join(',')}]`;
            } else if (packet.udp) {
                info = `${packet.udp.src_port} → ${packet.udp.dest_port}`;
            } else if (packet.icmp) {
                info = packet.icmp.type_name;
            }
            
            row.innerHTML = `
                <td>${packet.id}</td>
                <td>${packet.timestamp}</td>
                <td>${srcInfo}</td>
                <td>${destInfo}</td>
                <td>${protocol}</td>
                <td>${packet.size}</td>
                <td>${info}</td>
            `;
            
            row.onclick = () => showPacketDetail(packet);
        }

        function showPacketDetail(packet) {
            const detail = document.getElementById('packetDetail');
            const content = document.getElementById('detailContent');
            
            let html = '';
            
            if (packet.ethernet) {
                html += `
                    <div class="detail-section">
                        <div class="detail-title">Ethernet Header</div>
                        <div class="detail-content">
                            Source MAC: ${packet.ethernet.src_mac}<br>
                            Destination MAC: ${packet.ethernet.dest_mac}<br>
                            Type: ${packet.ethernet.type_name} (${packet.ethernet.type})
                        </div>
                    </div>
                `;
            }
            
            if (packet.ip) {
                html += `
                    <div class="detail-section">
                        <div class="detail-title">IP Header</div>
                        <div class="detail-content">
                            Version: ${packet.ip.version}<br>
                            Header Length: ${packet.ip.header_length} bytes<br>
                            Type of Service: ${packet.ip.tos}<br>
                            Total Length: ${packet.ip.total_length}<br>
                            Identification: ${packet.ip.identification}<br>
                            Flags: ${packet.ip.flags}<br>
                            Fragment Offset: ${packet.ip.fragment_offset}<br>
                            TTL: ${packet.ip.ttl}<br>
                            Protocol: ${packet.ip.protocol_name} (${packet.ip.protocol})<br>
                            Checksum: ${packet.ip.checksum}<br>
                            Source IP: ${packet.ip.src_ip}<br>
                            Destination IP: ${packet.ip.dest_ip}
                        </div>
                    </div>
                `;
            }
            
            if (packet.tcp) {
                html += `
                    <div class="detail-section">
                        <div class="detail-title">TCP Header</div>
                        <div class="detail-content">
                            Source Port: ${packet.tcp.src_port}<br>
                            Destination Port: ${packet.tcp.dest_port}<br>
                            Sequence Number: ${packet.tcp.seq_num}<br>
                            Acknowledgment Number: ${packet.tcp.ack_num}<br>
                            Data Offset: ${packet.tcp.data_offset} bytes<br>
                            Flags: ${packet.tcp.flag_names.join(', ')} (${packet.tcp.flags})<br>
                            Window Size: ${packet.tcp.window_size}<br>
                            Checksum: ${packet.tcp.checksum}<br>
                            Urgent Pointer: ${packet.tcp.urgent_ptr}
                        </div>
                    </div>
                `;
            } else if (packet.udp) {
                html += `
                    <div class="detail-section">
                        <div class="detail-title">UDP Header</div>
                        <div class="detail-content">
                            Source Port: ${packet.udp.src_port}<br>
                            Destination Port: ${packet.udp.dest_port}<br>
                            Length: ${packet.udp.length}<br>
                            Checksum: ${packet.udp.checksum}
                        </div>
                    </div>
                `;
            } else if (packet.icmp) {
                html += `
                    <div class="detail-section">
                        <div class="detail-title">ICMP Header</div>
                        <div class="detail-content">
                            Type: ${packet.icmp.type_name} (${packet.icmp.type})<br>
                            Code: ${packet.icmp.code}<br>
                            Checksum: ${packet.icmp.checksum}
                        </div>
                    </div>
                `;
            }
            
            // Hex dump
            html += `
                <div class="detail-section">
                    <div class="detail-title">Raw Data (Hex)</div>
                    <div class="hex-dump">${formatHexDump(packet.raw_data)}</div>
                </div>
            `;
            
            content.innerHTML = html;
            detail.style.display = 'block';
        }

        function formatHexDump(hexString) {
            let result = '';
            for (let i = 0; i < hexString.length; i += 32) {
                const line = hexString.substr(i, 32);
                const offset = (i / 2).toString(16).padStart(4, '0');
                const hex = line.match(/.{1,2}/g).join(' ');
                result += `${offset}: ${hex}\n`;
            }
            return result;
        }

        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    stats = data;
                    document.getElementById('totalPackets').textContent = stats.total_packets;
                    document.getElementById('tcpPackets').textContent = stats.protocol_stats.TCP || 0;
                    document.getElementById('udpPackets').textContent = stats.protocol_stats.UDP || 0;
                    document.getElementById('icmpPackets').textContent = stats.protocol_stats.ICMP || 0;
                    updateStatus(stats.is_capturing);
                });
        }

        function updateStatus(isCapturing) {
            const indicator = document.getElementById('statusIndicator');
            const text = document.getElementById('statusText');
            
            if (isCapturing) {
                indicator.className = 'status-indicator status-capturing';
                text.textContent = 'Đang bắt gói tin';
            } else {
                indicator.className = 'status-indicator status-stopped';
                text.textContent = 'Đã dừng';
            }
        }

        // Cập nhật stats định kỳ
        setInterval(updateStats, 2000);
        
        // Load packets ban đầu
        fetch('/api/packets')
            .then(response => response.json())
            .then(data => {
                packets = data;
                const tbody = document.getElementById('packetTableBody');
                tbody.innerHTML = '';
                packets.forEach(packet => addPacketToTable(packet));
                updateStats();
            });
    </script>
</body>
</html>'''
    
    with open('templates/wireshark.html', 'w', encoding='utf-8') as f:
        f.write(html_template)
    
    print("🌐 Network Packet Analyzer")
    print("=" * 50)
    print("🚀 Khởi động server tại: http://localhost:5000")
    print("⚠️  Lưu ý: Cần chạy với quyền Administrator/Root để bắt gói tin")
    print("📋 Các tính năng:")
    print("   • Bắt và phân tích gói tin mạng real-time")
    print("   • Hiển thị thông tin chi tiết các protocol (TCP/UDP/ICMP)")
    print("   • Giao diện web tương tác")
    print("   • Thống kê gói tin theo protocol")
    print("   • Hex dump của raw data")
    print()
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n👋 Đang thoát...")
        if analyzer.is_capturing:
            analyzer.stop_capture()
        print("✅ Đã dừng packet analyzer")