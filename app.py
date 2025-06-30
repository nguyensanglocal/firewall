from modules.FirewallManager import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize firewall manager
firewall = FirewallManager(socketio=socketio, app=app)

if __name__ == '__main__':
    
    print("🛡️ SimpleWall Clone Server Starting...")
    print("📋 Features:")
    print("   • Monitor running processes with network activity")
    print("   • View active network connections")
    print("   • Block/Allow applications")
    print("   • Real-time connection monitoring")
    print("   • Web-based management interface")
    print("\n⚠️  Note: Run as Administrator for full functionality")
    print("🌐 Access the application at: http://localhost:5000")
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)