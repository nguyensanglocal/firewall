from flask_socketio import emit
from models.ProcessManager import get_process_manager
from datetime import datetime

process_manager = get_process_manager()

def register_socket_events(socketio):
    @socketio.on('start_monitoring')
    def handle_start_monitoring():
        process_manager.start_monitoring()
        emit('monitoring_status', {'monitoring': True})

    @socketio.on('stop_monitoring')
    def handle_stop_monitoring():
        process_manager.stop_monitoring()
        emit('monitoring_status', {'monitoring': False})

    @socketio.on('get_connections')
    def handle_get_connections():
        emit('connection_update', {
            'connections': process_manager.get_network_connections(),
            'timestamp': datetime.now().isoformat()
        })

    @socketio.on('get_processes')
    def handle_get_processes():
        emit('processes_update', {
            'processes': process_manager.get_running_processes(),
            'timestamp': datetime.now().isoformat()
        })

    @socketio.on('block_app')
    def handle_block_app(data):
        app_path = data.get('app_path')
        if not app_path:
            emit('error', {'message': 'Missing app_path'})
            return
        process_manager.block_app(app_path)
        emit('app_blocked', {'app_path': app_path})
    @socketio.on('allow_app')
    def handle_allow_app(data):
        app_path = data.get('app_path')
        if not app_path:
            emit('error', {'message': 'Missing app_path'})
            return
        process_manager.allow_app(app_path)
        emit('app_allowed', {'app_path': app_path})

    @socketio.on('get_rules')
    def handle_get_rules():
        emit('rules_update', {
            'blocked_apps': list(process_manager.blocked_apps),
            'allowed_apps': list(process_manager.allowed_apps)
        })
    @socketio.on('connect')
    def handle_connect():
        print("Client connected")
        emit('connected', {'message': 'Connected to FirewallManager'})
    @socketio.on('disconnect')
    def handle_disconnect():
        print("Client disconnected")
        process_manager.stop_monitoring()
        emit('disconnected', {'message': 'Disconnected from FirewallManager'})
