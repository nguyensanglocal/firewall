from flask import Flask, render_template, request, jsonify, redirect, url_for, Blueprint
import json
import threading
import time
import ipaddress
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json

from database import *


main_bp = Blueprint('main', __name__)

@main_bp.route('/')
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

@main_bp.route('/logs')
def view_logs():
    """Xem logs chi tiết"""
    page = request.args.get('page', 1, type=int)
    per_page = 500
    
    logs, total_logs = get_log_page(page, per_page)
    
    return render_template('logs.html', logs=logs, page=page, per_page=per_page, total_logs=total_logs)

@main_bp.route('/suspicious')
def view_suspicious():
    """Xem các IP đáng nghi nhất"""
    top_suspicious_ips = get_top_suspicious_ips(limit=50)

    return render_template('suspicious.html', top_suspicious_ips=top_suspicious_ips)

@main_bp.route('/blacklist')
def manage_blacklist():
    """Quản lý blacklist"""
    blacklist_entries = get_blacklist_entries()
    domain_blacklist_entries = get_domain_blacklist_entries()
    
    return render_template('blacklist.html', blacklist_entries=blacklist_entries, 
                           domain_blacklist_entries=domain_blacklist_entries)

@main_bp.route('/add_blacklist', methods=['POST'])
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
    
    return redirect(url_for('main.manage_blacklist'))

@main_bp.route('/submit_blacklist', methods=['POST'])
def submit_blacklist():
    """Nhận danh sách IP/dải IP từ pending list và thêm vào blacklist"""
    entries_json = request.form.get('entries')
    if not entries_json:
        return redirect(url_for('main.manage_blacklist'))

    try:
        entries = json.loads(entries_json)
    except json.JSONDecodeError:
        return redirect(url_for('main.manage_blacklist'))

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

    return redirect(url_for('main.manage_blacklist'))

@main_bp.route('/submit_domain_blacklist', methods=['POST'])
def submit_domain_blacklist():
    """Nhận danh sách domain từ pending list và thêm vào blacklist"""
    domains_json = request.form.get('domains')
    if not domains_json:
        return redirect(url_for('main.manage_blacklist'))

    try:
        entries = json.loads(domains_json)
    except json.JSONDecodeError:
        return redirect(url_for('main.manage_blacklist'))

    for entry in entries:
        domain = entry.get("domain", "").strip().lower()
        reason = entry.get("reason", "Manual addition")
        if domain:
            # add_to_blacklist(domain, reason, entry_type="domain")
            block_domains(domain=domain)
            create_alert(domain, 'BLACKLISTED', f'Domain {domain} added to blacklist: {reason}', severity=1)

    return redirect(url_for('main.manage_blacklist'))

@main_bp.route('/remove_blacklist/<ip>')
def remove_blacklist_entry(ip):
    """Xóa IP khỏi blacklist"""
    update_blacklist(ip, is_active=0)
    return redirect(url_for('main.manage_blacklist'))

@main_bp.route('/remove_blacklist/<ip>', methods=['POST'])
def remove_blacklist_entry_(ip):
    """Xóa IP khỏi blacklist"""
    try:
        update_blacklist(ip, is_active=0)
        print(f"Removing IP {ip} from blacklist...")
        return jsonify({'success': True, 'ip': ip})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@main_bp.route('/block_blacklist/<ip>')
def block_blacklist_entry(ip):
    """Update IP in blacklist"""
    update_blacklist(ip, is_active=1)
    return redirect(url_for('main.manage_blacklist'))

@main_bp.route('/alerts')
def view_alerts():
    """Xem cảnh báo"""
    alerts = get_alerts(limit=100)
    return render_template('alerts.html', alerts=alerts)

@main_bp.route('/resolve_alert/<int:alert_id>')
def resolve_alert(alert_id):
    """Đánh dấu cảnh báo đã xử lý"""
    update_alert_resolved(alert_id)
    return redirect(url_for('view_alerts'))

@main_bp.route('/api/stats')
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

@main_bp.route('/about')
def home():
    """Trang chủ"""
    return render_template('about.html')


@main_bp.route('/wireshark')
def index():
    """Trang chủ"""
    return render_template('wireshark.html')