from flask import Blueprint, render_template, jsonify, request
import os
from models.ProcessManager import get_process_manager

process_group = Blueprint('firewall', __name__, url_prefix='/firewall')

process_manager = get_process_manager()

@process_group.route('/')
def index():
    return render_template('manager_process.html')

@process_group.route('/processes')
def list_processes():
    processes = process_manager.get_running_processes()
    if not processes:
        return jsonify({'error': 'No processes with network activity found'}), 404
    print(f"Found {len(processes)} processes with network activity")
    return jsonify(processes)

@process_group.route('/connections')
def list_connections():
    connections = process_manager.get_network_connections()
    return jsonify(connections)

@process_group.route('/block', methods=['POST'])
def block_application():
    data = request.get_json()
    print(f"Received block request: {data}")
    app_path = data.get('app_path')
    if not app_path:
        return jsonify({'error': 'Missing app_path'}), 400
    process_manager.block_app(app_path)
    return jsonify({'success': True, 'message': f'Blocked {os.path.basename(app_path)}'})

@process_group.route('/allow', methods=['POST'])
def allow_application():
    data = request.get_json()
    app_path = data.get('app_path')
    if not app_path:
        return jsonify({'error': 'Missing app_path'}), 400
    process_manager.allow_app(app_path)
    return jsonify({'success': True, 'message': f'Allowed {os.path.basename(app_path)}'})

@process_group.route('/rules')
def get_rules():
    return jsonify({
        'blocked_apps': list(process_manager.blocked_apps),
        'allowed_apps': list(process_manager.allowed_apps)
    })

@process_group.route('/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    process_manager.start_monitoring()
    return jsonify({'success': True, 'message': 'Monitoring started'})

@process_group.route('/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    process_manager.stop_monitoring()
    return jsonify({'success': True, 'message': 'Monitoring stopped'})
