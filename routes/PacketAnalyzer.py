from models.PacketAnalyzer import get_packet_analyzer
from flask import Blueprint, render_template, jsonify

packet_bp = Blueprint('packet_analyzer', __name__, url_prefix='/api')


# Khởi tạo PacketAnalyzer
packet_analyzer = get_packet_analyzer()

@packet_bp.route('/start_capture', methods=['POST'])
def start_capture():
    """API bắt đầu bắt gói tin"""
    if packet_analyzer.start_capture():
        return jsonify({'status': 'success', 'message': 'Bắt đầu bắt gói tin'})
    else:
        return jsonify({'status': 'error', 'message': 'Đã đang bắt gói tin'})

@packet_bp.route('/stop_capture', methods=['POST'])
def stop_capture():
    """API dừng bắt gói tin"""
    packet_analyzer.stop_capture()
    return jsonify({'status': 'success', 'message': 'Đã dừng bắt gói tin'})

@packet_bp.route('/clear_packets', methods=['POST'])
def clear_packets():
    """API xóa gói tin"""
    packet_analyzer.clear_packets()
    return jsonify({'status': 'success', 'message': 'Đã xóa tất cả gói tin'})

@packet_bp.route('/packets')
def get_packets():
    """API lấy danh sách gói tin"""
    # print("Lấy danh sách gói tin: ", packet_analyzer.packets)
    return jsonify(packet_analyzer.packets)

@packet_bp.route('/packet/<int:packet_id>')
def get_packet_detail(packet_id):
    """API lấy chi tiết gói tin"""
    for packet in packet_analyzer.packets:
        if packet['id'] == packet_id:
            return jsonify(packet)
    return jsonify({'error': 'Packet not found'}), 404

@packet_bp.route('/stats_wireshark')
def get_stats():
    """API thống kê"""
    protocol_stats = {}
    for packet in packet_analyzer.packets:
        protocol = packet.get('protocol', 'Unknown')
        protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
    
    return jsonify({
        'total_packets': len(packet_analyzer.packets),
        'protocol_stats': protocol_stats,
        'is_capturing': packet_analyzer.is_capturing
    })
