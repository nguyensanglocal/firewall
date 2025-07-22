
from collections import defaultdict
from datetime import datetime
import threading
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import ipaddress
from scapy.all import sniff, IP, TCP, UDP, Raw

from database import *

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
