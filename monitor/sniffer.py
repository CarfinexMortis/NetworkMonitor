import scapy.all as scapy
import requests
from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime
from database.db_manager import save_log, is_ip_blacklisted, add_to_blacklist

class NetworkSniffer(QThread):
    new_ip_signal = pyqtSignal(str, str, int, str, str)  
    threat_detected = pyqtSignal(str, str)  
    blacklist_updated = pyqtSignal()  

    def __init__(self, auto_blacklist_threshold=5):
        super().__init__()
        self.running = True
        self.auto_blacklist_threshold = auto_blacklist_threshold
        self.suspicious_ips = {}  

    def run(self):
        """Start the sniffer with error handling"""
        try:
            scapy.sniff(prn=self.process_packet, store=False, stop_filter=self.should_stop)
        except Exception as e:
            print(f"Sniffer error: {e}")
            self.threat_detected.emit("SYSTEM", f"Sniffer error: {e}")

    def should_stop(self, _):
        """Condition to stop sniffing"""
        return not self.running

    def process_packet(self, packet):
        """Process each network packet with enhanced logic"""
        if not self.running:
            return

        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            protocol, port = self.get_protocol_and_port(packet)

            
            if is_ip_blacklisted(ip_src):
                self.handle_blacklisted_ip(ip_src)
                return  
            
            country, provider = self.get_ip_info(ip_src)

            
            save_log(ip_src, protocol, port, country, provider)

            
            self.new_ip_signal.emit(ip_src, protocol, port, country, provider)

            
            self.analyze_for_threats(ip_src, protocol, port)

    def get_protocol_and_port(self, packet):
        """Extract protocol and port from packet"""
        if packet.haslayer(scapy.TCP):
            return "TCP", packet[scapy.TCP].sport
        elif packet.haslayer(scapy.UDP):
            return "UDP", packet[scapy.UDP].sport
        elif packet.haslayer(scapy.ICMP):
            return "ICMP", 0
        else:
            return "Other", 0

    def get_ip_info(self, ip):
        """Get country and provider by IP with improved error handling"""
        try:
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=2,
                headers={'User-Agent': 'NetworkMonitor/1.0'}
            )
            response.raise_for_status()
            data = response.json()
            
           
            provider = data.get("org", "Unknown")
            if isinstance(provider, str) and " " in provider:
                provider = provider.split(" ")[-1]
                
            return data.get("country", "Unknown"), provider
        except requests.exceptions.RequestException:
            return "Unknown", "Unknown"
        except (ValueError, KeyError):
            return "Unknown", "Unknown"

    def analyze_for_threats(self, ip, protocol, port):
        """Analyze packet for potential threats"""
     
        vulnerable_ports = {
            22: "SSH brute force attempt",
            3389: "RDP access attempt",
            445: "SMB exploitation attempt",
            1433: "SQL server access"
        }

        if port in vulnerable_ports:
            reason = vulnerable_ports[port]
            self.handle_suspicious_activity(ip, reason)

       

    def handle_suspicious_activity(self, ip, reason):
        """Handle suspicious IP activity with auto-blacklisting"""
       
        self.suspicious_ips[ip] = self.suspicious_ips.get(ip, 0) + 1

        self.threat_detected.emit(ip, f"{reason} detected")

        
        if self.suspicious_ips[ip] >= self.auto_blacklist_threshold:
            if add_to_blacklist(ip, f"Auto-blocked: {reason} (multiple attempts)"):
                self.threat_detected.emit(ip, f"IP automatically blacklisted due to {reason}")
                self.blacklist_updated.emit()

    def handle_blacklisted_ip(self, ip):
        """Handle traffic from blacklisted IPs"""
        self.threat_detected.emit(ip, "Blacklisted IP detected")
        
    def stop(self):
        """Stop the sniffer safely"""
        self.running = False
        
    def set_blacklist_threshold(self, threshold):
        """Update the auto-blacklisting threshold"""
        self.auto_blacklist_threshold = threshold