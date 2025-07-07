import platform
import socket
import sqlite3
import subprocess

# Cấu hình database
DATABASE = 'firewall_monitor.db'

# Blacklist IP mặc định
DEFAULT_BLACKLIST = [
    '192.168.1.100',  # IP test
]

# Whitelist IP (IP được tin cậy)
WHITELIST = [
    '127.0.0.1',
    '::1',
]


def init_db():
    """Khởi tạo database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            path TEXT,
            method TEXT,
            user_agent TEXT,
            status_code INTEGER,
            is_suspicious BOOLEAN DEFAULT 0,
            threat_level INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            added_date DATETIME DEFAULT (datetime('now', 'localtime')),
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT,
            severity INTEGER DEFAULT 1,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            is_resolved BOOLEAN DEFAULT 0
        )
    ''')
    
    # Thêm blacklist mặc định
    for ip in DEFAULT_BLACKLIST:
        cursor.execute('INSERT OR IGNORE INTO blacklist (ip_address, reason) VALUES (?, ?)', 
                      (ip, 'Default blacklist'))
    
    conn.commit()
    conn.close()

def apply_firewall_rule(remote_ip, action, port=None, protocol='any', domain=None):
    """Chặn hoặc cho phép 1 IP hoặc dải IP với tùy chọn port và protocol"""
    if platform.system() != 'Windows':
        print("Chỉ hỗ trợ Windows")
        return False
    
    try:
        rule_base = remote_ip.replace('.', '_').replace('/', '_').replace('-', '_to_')
        if domain:
            rule_base = domain.replace('.', '_').replace('/', '_').replace('-', '_to_')
        rule_name = f"Rule_{rule_base}_{protocol}_{port or 'any'}"
        
        for rule in ['IN', 'OUT']:
            
            common_args = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}_{rule}',
                f'dir={rule.lower()}',
                f'action={action}',
                f'remoteip={remote_ip}',
                f'protocol={protocol}'
            ]

            if port:
                common_args += [f'localport={port}']

            if action != 'block':
                common_args[3] = 'delete'
                common_args = common_args[:6]  # Giữ lại các tham số cần thiết

            result = subprocess.run(common_args , capture_output=True, text=True)
            
            print(f"{rule}-bound rule: {result.stdout.strip()}")
        
        return result.returncode == 0
    except Exception as e:
        print(f"[Lỗi áp dụng firewall rule]: {e}")
        return False

def block_domain_powershell(domain):
    all_ips = set()
    try:
        ips = set(info[4][0] for info in socket.getaddrinfo(domain, None))
        all_ips.update(ips)
    except Exception as e:
        print(f"Failed to resolve {domain}: {e}")
    try:
        apply_ip_firewall_rule(','.join(all_ips), 'block', domain=domain)
    except Exception as e:
        print(f"Failed to apply firewall rule for {domain}: {e}")
        return False
    return True

def apply_ip_firewall_rule(ip, action):
    return None
    apply_firewall_rule(ip, action, port=None, protocol='any')
    
def add_to_blacklist(ip, reason):
    """Thêm IP vào blacklist"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO blacklist (ip_address, reason) VALUES (?, ?)', (ip, reason))
    conn.commit()
    conn.close()

    # Áp dụng firewall rule để chặn IP
    firewall_success = apply_ip_firewall_rule(ip, 'block')
    
    if firewall_success:
        print(f"Firewall rule đã được áp dụng thành công cho IP {ip}")
    else:
        print(f"Lỗi khi áp dụng firewall rule cho IP {ip}")

def create_alert(ip, alert_type, message, severity=1):
    """Tạo cảnh báo"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Bỏ qua nếu đã có alert tương tự trong 1 phút gần đây
    cursor.execute('''
        SELECT 1 FROM alerts
        WHERE ip_address = ? AND alert_type = ? AND message = ? AND severity = ?
        AND timestamp > datetime('now', '-1 minute')
        LIMIT 1
    ''', (ip, alert_type, message, severity))
    if cursor.fetchone():
        conn.close()
        return

    # Xóa cảnh báo cũ nếu có
    print(f"Removing old alert for IP: {ip}, Type: {alert_type}, Message: {message}, Severity: {severity}")
    cursor.execute('''
        DELETE FROM alerts
        WHERE ip_address = ? AND alert_type = ? AND message = ? AND severity = ?
    ''', (ip, alert_type, message, severity))

    cursor.execute('''
        INSERT INTO alerts (ip_address, alert_type, message, severity)
        VALUES (?, ?, ?, ?)
    ''', (ip, alert_type, message, severity))
    conn.commit()
    conn.close()

def is_blacklisted(ip):
    """Kiểm tra IP có trong blacklist không"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM blacklist WHERE ip_address = ? AND is_active = 1', (ip,))
    result = cursor.fetchone()[0] > 0
    conn.close()
    return result

def log_request_to_db(ip, path, method, user_agent, status_code, is_suspicious, threat_level):
    """Ghi log request vào database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO access_logs (ip_address, path, method, user_agent, status_code, is_suspicious, threat_level)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (ip, path, method, user_agent, status_code, is_suspicious, threat_level))
    conn.commit()
    conn.close()

def get_total_requests_24h():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Thống kê tổng quan
    cursor.execute('SELECT COUNT(*) FROM access_logs WHERE timestamp > datetime("now", "-24 hours")')
    total_requests_24h = cursor.fetchone()[0]

    return total_requests_24h

def get_suspicious_requests_24h():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Thống kê các request đáng ngờ
    cursor.execute('''
        SELECT COUNT(*) FROM access_logs 
        WHERE is_suspicious = 1 AND timestamp > datetime("now", "-24 hours")
    ''')
    suspicious_requests_24h = cursor.fetchone()[0]

    return suspicious_requests_24h

def get_total_blacklisted():
    """Lấy tổng số IP trong blacklist"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM blacklist WHERE is_active = 1')
    total_blacklisted = cursor.fetchone()[0]
    conn.close()
    return total_blacklisted

def get_active_alerts():
    """Lấy danh sách các cảnh báo chưa được giải quyết"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM alerts WHERE is_resolved = 0')
    active_alerts = cursor.fetchone()[0]
    conn.close()
    return active_alerts

# def get_top_suspicious_ips(limit=10):
#     """Lấy danh sách các IP đáng ngờ nhất"""
#     conn = sqlite3.connect(DATABASE)
#     cursor = conn.cursor()
#     cursor.execute('''
#         SELECT ip_address, COUNT(*) as count, AVG(threat_level) as avg_threat
#         FROM access_logs 
#         WHERE timestamp > datetime("now", "-24 hours") AND threat_level > 0
#         GROUP BY ip_address 
#         ORDER BY avg_threat DESC, count DESC 
#         LIMIT ?
#     ''', (limit,))
#     top_suspicious_ips = cursor.fetchall()
#     conn.close()
#     return top_suspicious_ips
def get_top_suspicious_ips(limit=10):
    """Lấy danh sách các IP đáng ngờ nhất, kèm theo trạng thái is_active (có trong blacklist hay không)"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            logs.ip_address, 
            COUNT(*) as count, 
            AVG(logs.threat_level) as avg_threat,
            CASE 
                WHEN bl.is_active = 1 THEN 1
                ELSE 0
            END as is_active
        FROM access_logs logs
        LEFT JOIN blacklist bl ON logs.ip_address = bl.ip_address
        WHERE logs.timestamp > datetime("now", "-24 hours") AND logs.threat_level > 0
        GROUP BY logs.ip_address
        ORDER BY avg_threat DESC, count DESC
        LIMIT ?
    ''', (limit,))
    top_suspicious_ips = cursor.fetchall()
    conn.close()
    return top_suspicious_ips


def get_recent_alerts(limit=10):
    """Lấy danh sách các cảnh báo gần đây nhất"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT ip_address, alert_type, message, severity, timestamp
        FROM alerts 
        WHERE is_resolved = 0
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    recent_alerts = cursor.fetchall()
    conn.close()
    return recent_alerts

def get_log_page(page=1, per_page=50):
    """Lấy trang log"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    offset = (page - 1) * per_page
    cursor.execute('''
        SELECT ip_address, timestamp, path, method, user_agent, status_code, is_suspicious, threat_level
        FROM access_logs 
        ORDER BY timestamp DESC 
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    logs = cursor.fetchall()
    cursor.execute('SELECT COUNT(*) FROM access_logs')
    total_logs = cursor.fetchone()[0]
    conn.close()
    return logs, total_logs

def get_blacklist_entries():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT ip_address, reason, added_date, is_active FROM blacklist ORDER BY added_date DESC')
    blacklist_entries = cursor.fetchall()
    conn.close()
    return blacklist_entries

def update_blacklist(ip, is_active=0):
    """Xóa IP khỏi blacklist"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('UPDATE blacklist SET is_active = ? WHERE ip_address = ?', (is_active, ip,))
    conn.commit()
    conn.close()

    action = 'unblock' if is_active == 0 else 'block'
    apply_ip_firewall_rule(ip, action=action)

def get_alerts(limit=100):
    """Lấy danh sách cảnh báo"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, ip_address, alert_type, message, severity, timestamp, is_resolved
        FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    alerts = cursor.fetchall()
    conn.close()
    return alerts
    
def update_alert_resolved(alert_id):
    """Cập nhật trạng thái cảnh báo là đã giải quyết"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('UPDATE alerts SET is_resolved = 1 WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()