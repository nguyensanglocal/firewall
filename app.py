import threading
import time
from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from database import *
from routes.main import main_bp
from routes.PacketAnalyzer import packet_bp
from routes.process_system import process_group
from sockets.events import register_socket_events
from models.PacketAnalyzer import get_packet_analyzer

# from create_templates import create_templates
# create_templates()

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# from models.PacketBasedAnalyzer import PacketBasedAnalyzer
# packet_analyzer = PacketBasedAnalyzer(interface="Wi-Fi", server_port=80)
packet_analyzer = get_packet_analyzer()
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


app.register_blueprint(main_bp)
app.register_blueprint(packet_bp)
app.register_blueprint(process_group)

register_socket_events(socketio)


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