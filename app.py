from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import re
import requests
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import threading
import time
import ipaddress
from functools import wraps
from scapy.all import sniff, IP, TCP, UDP, Raw
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


# from create_templates import create_templates
# create_templates()

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

import sqlite3

def init_db_geoip():
    conn = sqlite3.connect('geoip_cache.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            region TEXT,
            city TEXT,
            org TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Gọi init
init_db_geoip()
def lookup_ip(ip):
    with sqlite3.connect('geoip_cache.db', timeout=5) as conn:
        c = conn.cursor()
        c.execute("SELECT country, region, city, org FROM ip_cache WHERE ip = ?", (ip,))
        row = c.fetchone()
        if row:
            return {"source": "cache", "country": row[0], "region": row[1], "city": row[2], "org": row[3]}

        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,org"
        resp = requests.get(url).json()

        if resp['status'] == 'success':
            data = (ip, resp['country'], resp['regionName'], resp['city'], resp['org'])
            c.execute("INSERT OR IGNORE INTO ip_cache (ip, country, region, city, org) VALUES (?, ?, ?, ?, ?)", data)
            return {"source": "api", "country": resp['country'], "region": resp['regionName'], "city": resp['city'], "org": resp['org']}
        else:
            return {"source": "api", "error": "lookup failed"}

class PacketBasedAnalyzer:
    def __init__(self, interface="eth0", server_port=80):
        self.interface = interface
        self.server_port = server_port
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
        
        # Pattern matching cho HTTP
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
        
        self.running = False
        
    def start_monitoring(self):
        """Bắt đầu monitoring packets"""
        self.running = True
        monitor_thread = threading.Thread(target=self._packet_monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
    def stop_monitoring(self):
        """Dừng monitoring"""
        self.running = False
        
    def _packet_monitor_loop(self):
        """Loop chính để monitor packets"""
        try:
            # Bắt tất cả packets
            # Bắt tất cả packets (không filter)
            filter_rule = None
            sniff(
                iface=self.interface,
                prn=self._analyze_packet,
                filter=filter_rule,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            print(f"Error in packet monitoring: {e}")
            
    def _analyze_packet(self, packet):
        """Phân tích từng packet thay vì HTTP request"""
        try:
            if IP in packet and TCP in packet:
                ip_layer = packet[IP]
                tcp_layer = packet[TCP]
                src_ip = ip_layer.src

                # print(f"Analyzing packet from {src_ip} to {ip_layer.dst}, TCP port {tcp_layer.dport:6d} (flags: {tcp_layer.flags})")
                for ip in [src_ip, ip_layer.dst]:
                    if not ipaddress.ip_address(ip).is_private:
                        # print(f"[ALERT] Public IP detected: {ip}")
                        try:
                            res = lookup_ip(ip)
                            # if res.get('error'):
                            #     print(f"Error looking up IP {ip}: {res['error']}")
                            # else:
                            #     print(f"IP {ip} - Country: {res['country']}, Region: {res['region']}, City: {res['city']}, Org: {res['org']}")
                        except Exception as e:
                            print(f"Error looking up IP {ip}: {e}")
                            exit(1)
                
                # Cập nhật stats cơ bản
                stats = self.packet_stats[src_ip]
                stats['total_packets'] += 1
                stats['bytes_received'] += len(packet)
                stats['last_activity'] = datetime.now()
                
                # Kiểm tra connection attempts
                if tcp_layer.flags & 0x02:  # SYN flag
                    stats['connection_attempts'] += 1
                
                # Phân tích payload nếu có
                if Raw in packet:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    self._analyze_http_payload(src_ip, payload)
                else:
                    log_request_to_db(
                        src_ip, tcp_layer.dport, 'TCP', 'Unknow', 200, True, datetime.now().microsecond%3
                    )
                # Kiểm tra rate limiting
                self._check_packet_rate_limit(src_ip)
                
                # Phân tích patterns đáng nghi
                threat_indicators = self._detect_packet_threats(src_ip, packet)
                
                # Xử lý theo threat level
                self._handle_packet_threats(src_ip, threat_indicators)
                
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    
    def _analyze_http_payload(self, src_ip, payload):
        """Phân tích HTTP payload thay vì request headers"""
        stats = self.packet_stats[src_ip]
        
        # Kiểm tra nếu là HTTP request
        if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
            stats['http_requests'] += 1
            
            # Extract method và path từ payload
            lines = payload.split('\n')
            if lines:
                request_line = lines[0]
                parts = request_line.split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    
                    # Phân tích suspicious patterns trong payload
                    suspicious_found = []
                    for pattern_type, patterns in self.http_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, payload, re.IGNORECASE):
                                suspicious_found.append(pattern_type)
                                break
                    
                    if suspicious_found:
                        stats['suspicious_patterns'].extend(suspicious_found)
                        
                    # Log thông tin từ packet thay vì request object
                    self._log_packet_to_db(src_ip, method, path, payload, suspicious_found)
    
    def _check_packet_rate_limit(self, src_ip):
        """Kiểm tra rate limit dựa trên packets thay vì requests"""
        stats = self.packet_stats[src_ip]
        now = datetime.now()
        
        # Reset counter mỗi phút
        if (now - stats['rate_limit_window']).seconds > 60:
            stats['rate_limit_counter'] = 0
            stats['rate_limit_window'] = now
        
        stats['rate_limit_counter'] += 1
        
    def _detect_packet_threats(self, src_ip, packet):
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
        
        # Suspicious patterns trong payload
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
        if len(packet) > 8000:  # Large packets
            threats.append({
                'type': 'LARGE_PACKET',
                'severity': 1,
                'details': f"Packet size: {len(packet)} bytes"
            })
        
        return threats
    
    def _handle_packet_threats(self, src_ip, threats):
        """Xử lý threats phát hiện từ packets"""
        if not threats:
            return
            
        # Tính threat level
        threat_level = sum(threat['severity'] for threat in threats)
        
        # Kiểm tra whitelist
        if src_ip in WHITELIST:
            return
            
        # Kiểm tra và xử lý blacklist
        if is_blacklisted(src_ip):
            create_alert(src_ip, 'BLOCKED', f'Blocked packets from blacklisted IP: {src_ip}', severity=3)
            return
        
        # Tạo alerts dựa trên threat level
        if threat_level >= 5:
            threat_types = [t['type'] for t in threats]
            message = f"Critical packet-level threats from {src_ip}: {threat_types}"
            create_alert(src_ip, 'CRITICAL_PACKET_THREAT', message, severity=1)
            
            # Auto-blacklist cho critical threats
            add_to_blacklist(src_ip, f'Critical packet threats: {threat_types}')
            
        elif threat_level >= 3:
            threat_types = [t['type'] for t in threats]
            message = f"High packet-level threats from {src_ip}: {threat_types}"
            create_alert(src_ip, 'HIGH_PACKET_THREAT', message, severity=2)
        
        # Xử lý rate limiting
        stats = self.packet_stats[src_ip]
        if stats['rate_limit_counter'] > 100:
            message = f"Packet rate limit exceeded for IP {src_ip}: {stats['rate_limit_counter']} packets/min"
            create_alert(src_ip, 'PACKET_RATE_LIMIT', message, severity=2)
            add_to_blacklist(src_ip, 'Packet rate limit exceeded')
    
    def _log_packet_to_db(self, src_ip, method, path, payload, suspicious_patterns):
        """Log thông tin từ packet analysis thay vì request"""
        
        user_agent = self._extract_user_agent(payload)
        is_suspicious = bool(suspicious_patterns)
        threat_level = len(suspicious_patterns) * 2
        log_request_to_db(
            src_ip, path, method, user_agent, 200, is_suspicious, threat_level
        )
    
    def _extract_user_agent(self, payload):
        """Extract User-Agent từ HTTP payload"""
        match = re.search(r'User-Agent:\s*([^\r\n]+)', payload, re.IGNORECASE)
        return match.group(1) if match else 'Unknown'
    
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

class FirewallAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            r'.*\.(php|asp|jsp|cgi)',  # File extensions đáng nghi
            r'admin|phpmyadmin|wp-admin',  # Admin paths
            r'\.\./',  # Directory traversal
            r'<script|javascript:|eval\(',  # XSS attempts
            r'union.*select|drop.*table',  # SQL injection
        ]
        self.rate_limits = defaultdict(list)
        
    def is_suspicious_request(self, path, user_agent=''):
        """Kiểm tra request có đáng nghi hay không"""
        combined = f"{path} {user_agent}".lower()
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in self.suspicious_patterns)
    
    def check_rate_limit(self, ip, limit=100, window=300):  # 100 requests trong 5 phút
        """Kiểm tra rate limiting"""
        now = time.time()
        self.rate_limits[ip] = [req_time for req_time in self.rate_limits[ip] if now - req_time < window]
        self.rate_limits[ip].append(now)
        return len(self.rate_limits[ip]) > limit

analyzer = FirewallAnalyzer()

# Khởi tạo packet analyzer
packet_analyzer = PacketBasedAnalyzer(interface="Wi-Fi", server_port=80)

from modules.FirewallManager import *
socketio = SocketIO(app, cors_allowed_origins="*")


manage_process = FirewallManager(app=app, socketio=socketio, prefix_url='/firewall')


def monitor_requests():
    """Middleware chuyển sang theo dõi packets thay vì HTTP requests"""
    
    # Khởi động packet monitoring
    packet_analyzer.start_monitoring()
    
    @app.before_request
    def before_request():
        # Chỉ giữ lại phần xử lý cơ bản
        # Việc phân tích chính được thực hiện trong packet analyzer
        
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
       
        # Bỏ qua whitelist (đã check trong packet analyzer)
        if ip in WHITELIST:
            return
           
        # Kiểm tra blacklist (đã check trong packet analyzer)
        if is_blacklisted(ip):
            return jsonify({'error': 'Access denied'}), 403
        
        # Lấy analysis từ packet analyzer thay vì phân tích request
        packet_analysis = packet_analyzer.get_ip_analysis(ip)
        
        # Thông tin này đã được xử lý ở packet level
        # Chỉ cần return hoặc thực hiện logging bổ sung nếu cần
        return
    
    # Cleanup task
    def start_cleanup_task():
        def cleanup_loop():
            while True:
                time.sleep(3600)  # Mỗi giờ
                packet_analyzer.cleanup_old_stats(hours=24)
                
        cleanup_thread = threading.Thread(target=cleanup_loop)
        cleanup_thread.daemon = True
        cleanup_thread.start()
    
    start_cleanup_task()

monitor_requests()
from database import *
@app.route('/')
def dashboard():
    """Dashboard chính"""
    total_requests_24h = get_total_requests_24h()
    suspicious_requests_24h = get_suspicious_requests_24h()
    total_blacklisted = get_total_blacklisted()
    active_alerts = get_active_alerts()
    top_suspicious_ips = get_top_suspicious_ips()
    recent_alerts = get_recent_alerts()
    
    return render_template('dashboard.html',
                          total_requests_24h=total_requests_24h,
                          suspicious_requests_24h=suspicious_requests_24h,
                          total_blacklisted=total_blacklisted,
                          active_alerts=active_alerts,
                          top_suspicious_ips=top_suspicious_ips,
                          recent_alerts=recent_alerts)

@app.route('/logs')
def view_logs():
    """Xem logs chi tiết"""
    page = request.args.get('page', 1, type=int)
    per_page = 500
    
    logs, total_logs = get_log_page(page, per_page)
    
    return render_template('logs.html', logs=logs, page=page, per_page=per_page, total_logs=total_logs)

@app.route('/suspicious')
def view_suspicious():
    """Xem các IP đáng nghi nhất"""
    top_suspicious_ips = get_top_suspicious_ips(limit=50)

    return render_template('suspicious.html', top_suspicious_ips=top_suspicious_ips)

@app.route('/blacklist')
def manage_blacklist():
    """Quản lý blacklist"""
    blacklist_entries = get_blacklist_entries()
    domain_blacklist_entries = get_domain_blacklist_entries()
    
    return render_template('blacklist.html', blacklist_entries=blacklist_entries, 
                           domain_blacklist_entries=domain_blacklist_entries)

@app.route('/add_blacklist', methods=['POST'])
def add_blacklist_entry():
    """Thêm IP vào blacklist"""
    ip = request.form.get('ip')
    reason = request.form.get('reason', 'Manual addition')
    print(f"Adding IP to blacklist: {ip}, Reason: {reason}")
    try:
        # Validate IP
        ipaddress.ip_address(ip)
        add_to_blacklist(ip, reason)
        create_alert(ip, 'BLACKLISTED', f'IP {ip} added to blacklist: {reason}', severity=1)
    except ValueError:
        pass  # Invalid IP
    
    return redirect(url_for('manage_blacklist'))

@app.route('/submit_blacklist', methods=['POST'])
def submit_blacklist():
    """Nhận danh sách IP/dải IP từ pending list và thêm vào blacklist"""
    entries_json = request.form.get('entries')
    if not entries_json:
        return redirect(url_for('manage_blacklist'))

    try:
        entries = json.loads(entries_json)
    except json.JSONDecodeError:
        return redirect(url_for('manage_blacklist'))

    for entry in entries:
        reason = entry.get("reason", "Manual addition")
        try:
            if entry["type"] == "single":
                ipaddress.ip_address(entry["ip"])
                add_to_blacklist(entry["ip"], reason)
                create_alert(entry["ip"], 'BLACKLISTED', f'IP {entry["ip"]} added to blacklist: {reason}', severity=1)
            elif entry["type"] == "range":
                start = ipaddress.ip_address(entry["start_ip"])
                end = ipaddress.ip_address(entry["end_ip"])
                for ip in [start, end]:
                    ipaddress.ip_address(ip)
                # Loop all IPs in range if needed — or store range as a string
                ip_range_str = f"{start}-{end}"
                add_to_blacklist(ip_range_str, reason)
                create_alert(ip_range_str, 'BLACKLISTED', f'IP range {ip_range_str} added to blacklist: {reason}', severity=1)
        except ValueError:
            continue  # Skip invalid IPs

    return redirect(url_for('manage_blacklist'))

@app.route('/submit_domain_blacklist', methods=['POST'])
def submit_domain_blacklist():
    """Nhận danh sách domain từ pending list và thêm vào blacklist"""
    domains_json = request.form.get('domains')
    if not domains_json:
        return redirect(url_for('manage_blacklist'))

    try:
        entries = json.loads(domains_json)
    except json.JSONDecodeError:
        return redirect(url_for('manage_blacklist'))

    for entry in entries:
        domain = entry.get("domain", "").strip().lower()
        reason = entry.get("reason", "Manual addition")
        if domain:
            # add_to_blacklist(domain, reason, entry_type="domain")
            block_domains(domain=domain)
            create_alert(domain, 'BLACKLISTED', f'Domain {domain} added to blacklist: {reason}', severity=1)

    return redirect(url_for('manage_blacklist'))

@app.route('/remove_blacklist/<ip>')
def remove_blacklist_entry(ip):
    """Xóa IP khỏi blacklist"""
    update_blacklist(ip, is_active=0)
    return redirect(url_for('manage_blacklist'))

@app.route('/remove_blacklist/<ip>', methods=['POST'])
def remove_blacklist_entry_(ip):
    """Xóa IP khỏi blacklist"""
    try:
        update_blacklist(ip, is_active=0)
        print(f"Removing IP {ip} from blacklist...")
        return jsonify({'success': True, 'ip': ip})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/block_blacklist/<ip>')
def block_blacklist_entry(ip):
    """Update IP in blacklist"""
    update_blacklist(ip, is_active=1)
    return redirect(url_for('manage_blacklist'))

@app.route('/alerts')
def view_alerts():
    """Xem cảnh báo"""
    alerts = get_alerts(limit=100)
    return render_template('alerts.html', alerts=alerts)

@app.route('/resolve_alert/<int:alert_id>')
def resolve_alert(alert_id):
    """Đánh dấu cảnh báo đã xử lý"""
    update_alert_resolved(alert_id)
    return redirect(url_for('view_alerts'))

@app.route('/api/stats')
def api_stats():
    """API lấy thống kê real-time"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Requests theo giờ trong 24h qua
    cursor.execute('''
        SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
        FROM access_logs 
        WHERE timestamp > datetime("now", "-24 hours")
        GROUP BY strftime('%H', timestamp)
        ORDER BY hour
    ''')
    hourly_stats = dict(cursor.fetchall())
    
    # Top countries (giả lập - trong thực tế cần GeoIP)
    cursor.execute('''
        SELECT ip_address, COUNT(*) as count
        FROM access_logs 
        WHERE timestamp > datetime("now", "-24 hours")
        GROUP BY ip_address
        ORDER BY count DESC
        LIMIT 10
    ''')
    top_ips = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'hourly_stats': hourly_stats,
        'top_ips': top_ips
    })


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

@app.route('/wireshark')
def index():
    """Trang chủ"""
    return render_template('wireshark.html')

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

@app.route('/api/stats_wireshark')
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

@app.route('/about')
def home():
    """Trang chủ"""
    return render_template('about.html')
if __name__ == '__main__':
    
    # Khởi tạo database
    init_db()
    
    print("🔥 Firewall Monitor đang khởi động...")
    print("📊 Dashboard: http://localhost:5000")
    print("🔍 Logs: http://localhost:5000/logs")
    print("🚫 Blacklist: http://localhost:5000/blacklist")
    print("⚠️  Alerts: http://localhost:5000/alerts")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    
    # app.run(debug=True, host='0.0.0.0', port=5000)