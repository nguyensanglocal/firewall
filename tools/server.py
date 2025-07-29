import socket

def run_dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))
    print("[*] DNS Server listening on port 53...")
    
    while True:
        data, addr = sock.recvfrom(512)
        print(f"[RECEIVED] from {addr}: {data}")

# Chạy bằng sudo nếu cần quyền
run_dns_server()
