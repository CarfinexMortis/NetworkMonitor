import scapy.all as scapy
import requests
import re
import json
from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime
from database.db_manager import save_log, is_ip_blacklisted, add_to_blacklist
from alerts.firewall_manager import WindowsFirewallManager
import logging
import subprocess

class NetworkSniffer(QThread):
    new_ip_signal = pyqtSignal(str, str, int, str, str)  
    threat_detected = pyqtSignal(str, str)  
    blacklist_updated = pyqtSignal()  

    def __init__(self, auto_blacklist_threshold=5):
        super().__init__()
        self.running = True
        self.auto_blacklist_threshold = auto_blacklist_threshold
        self.suspicious_ips = {}  
        self.known_malicious_ips = self.load_malicious_ip_list()
        self.protocol_stats = {}  # Track protocol statistics
        self.port_scan_threshold = 10  # Number of ports to trigger port scan detection

    def load_malicious_ip_list(self):
        """Load known malicious IPs from a file or online source"""
        try:
            # You can replace this with loading from a file or API
            return {
                '185.143.223.62': "Known malicious server",
                '91.219.236.222': "Historical attack source",
                '45.155.205.233': "Recent brute force attacks"
            }
        except Exception as e:
            print(f"Error loading malicious IP list: {e}")
            return {}

    def run(self):
        """Start the sniffer with error handling"""
        try:
            # Use BPF filter to focus on suspicious traffic
            filter = "tcp or udp or icmp"
            scapy.sniff(
                prn=self.process_packet,
                store=False,
                stop_filter=self.should_stop,
                filter=filter
            )
        except Exception as e:
            print(f"Sniffer error: {e}")
            self.threat_detected.emit("SYSTEM", f"Sniffer error: {e}")

    def should_stop(self, _):
        """Condition to stop sniffing"""
        return not self.running

    def process_packet(self, packet):
        """Process each network packet with enhanced threat detection"""
        if not self.running:
            return

        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            protocol, port = self.get_protocol_and_port(packet)

            # Skip local traffic if needed
            if ip_src.startswith(('192.168.', '10.', '172.16.')) and ip_dst.startswith(('192.168.', '10.', '172.16.')):
                return

            # Check if IP is blacklisted
            if is_ip_blacklisted(ip_src):
                self.handle_blacklisted_ip(ip_src)
                return

            # Check against known malicious IPs
            if ip_src in self.known_malicious_ips:
                reason = f"Known malicious IP: {self.known_malicious_ips[ip_src]}"
                self.handle_immediate_threat(ip_src, reason)
                return

            country, provider = self.get_ip_info(ip_src)
            save_log(ip_src, protocol, port, country, provider)
            self.new_ip_signal.emit(ip_src, protocol, port, country, provider)

            # Update protocol statistics for anomaly detection
            self.update_protocol_stats(ip_src, protocol, port)

            # Enhanced threat analysis
            self.analyze_for_threats(ip_src, protocol, port, packet)

    def get_protocol_and_port(self, packet):
        """Extract protocol and port from packet with more detail"""
        if packet.haslayer(scapy.TCP):
            flags = packet[scapy.TCP].flags
            if flags & 0x02:  # SYN flag
                return "TCP-SYN", packet[scapy.TCP].dport
            elif flags & 0x10:  # ACK flag
                return "TCP-ACK", packet[scapy.TCP].dport
            else:
                return "TCP", packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            return "UDP", packet[scapy.UDP].dport
        elif packet.haslayer(scapy.ICMP):
            return "ICMP", 0
        else:
            return "Other", 0

    def update_protocol_stats(self, ip, protocol, port):
        """Track protocol and port usage statistics for anomaly detection"""
        if ip not in self.protocol_stats:
            self.protocol_stats[ip] = {
                'protocols': {},
                'ports': {},
                'total_packets': 0
            }

        self.protocol_stats[ip]['total_packets'] += 1

        # Track protocol usage
        if protocol in self.protocol_stats[ip]['protocols']:
            self.protocol_stats[ip]['protocols'][protocol] += 1
        else:
            self.protocol_stats[ip]['protocols'][protocol] = 1

        # Track port usage (only for TCP/UDP)
        if port > 0:
            if port in self.protocol_stats[ip]['ports']:
                self.protocol_stats[ip]['ports'][port] += 1
            else:
                self.protocol_stats[ip]['ports'][port] = 1

    def analyze_for_threats(self, ip, protocol, port, packet):
        """Enhanced threat detection with multiple analysis methods"""
        # 1. Check for suspicious ports
        self.check_suspicious_ports(ip, port)

        # 2. Detect port scanning behavior
        self.detect_port_scanning(ip)

        # 3. Check for protocol anomalies
        self.check_protocol_anomalies(ip)

        # 4. Detect SYN flood attacks
        if "TCP-SYN" in protocol:
            self.detect_syn_flood(ip)

        # 5. Check for suspicious payloads
        if packet.haslayer(scapy.Raw):
            payload = str(packet[scapy.Raw].load)
            self.check_malicious_payload(ip, payload)

    def check_suspicious_ports(self, ip, port):
        """Check for traffic on known vulnerable ports"""
        vulnerable_ports = {
            22: "SSH brute force attempt",
            23: "Telnet (insecure protocol)",
            3389: "RDP access attempt",
            445: "SMB exploitation attempt",
            1433: "SQL server access",
            3306: "MySQL access",
            5432: "PostgreSQL access",
            5900: "VNC access",
            8080: "Possible web admin interface"
        }

        if port in vulnerable_ports:
            reason = vulnerable_ports[port]
            self.handle_suspicious_activity(ip, reason)

    def detect_port_scanning(self, ip):
        """Detect potential port scanning activity"""
        if ip in self.protocol_stats:
            # If an IP has touched many different ports in a short time
            if len(self.protocol_stats[ip]['ports']) >= self.port_scan_threshold:
                reason = f"Port scanning detected ({len(self.protocol_stats[ip]['ports'])} different ports)"
                self.handle_suspicious_activity(ip, reason)

    def check_protocol_anomalies(self, ip):
        """Check for unusual protocol usage patterns"""
        if ip in self.protocol_stats:
            stats = self.protocol_stats[ip]
            
            # High percentage of ICMP packets could indicate ping flood
            if 'ICMP' in stats['protocols']:
                icmp_ratio = stats['protocols']['ICMP'] / stats['total_packets']
                if icmp_ratio > 0.8:  # 80% ICMP traffic
                    self.handle_suspicious_activity(ip, "ICMP flood detected")

            # Many SYN packets without follow-up could indicate SYN flood
            if 'TCP-SYN' in stats['protocols']:
                syn_ratio = stats['protocols']['TCP-SYN'] / stats['total_packets']
                if syn_ratio > 0.7:  # 70% SYN packets
                    self.handle_suspicious_activity(ip, "SYN flood suspected")

    def detect_syn_flood(self, ip):
        """Specifically detect SYN flood attacks"""
        if ip in self.suspicious_ips:
            self.suspicious_ips[ip]['syn_count'] = self.suspicious_ips[ip].get('syn_count', 0) + 1
            
            if self.suspicious_ips[ip]['syn_count'] > 50:  # Threshold for SYN flood
                reason = "SYN flood attack detected"
                self.handle_immediate_threat(ip, reason)

    def check_malicious_payload(self, ip, payload):
        """Check packet payload for known attack patterns"""
        # SQL injection patterns
        sql_injection_patterns = [
            r'\b(select|union|insert|update|delete|drop|alter|create)\b',
            r'\b(1=1|true)\b',
            r'(\'|\"|--|;)'
        ]
        
        # XSS patterns
        xss_patterns = [
            r'<script>',
            r'javascript:',
            r'onerror=',
            r'onload='
        ]
        
        # Shell command patterns
        shell_patterns = [
            r'\b(rm -rf|wget|curl|nc |netcat|bash |sh |python |perl )\b',
            r'\|\s*sh\b'
        ]
        
        # Combine all patterns
        all_patterns = sql_injection_patterns + xss_patterns + shell_patterns
        
        for pattern in all_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                reason = f"Malicious payload detected: {pattern}"
                self.handle_immediate_threat(ip, reason)
                break

    def handle_suspicious_activity(self, ip, reason):
        """Handle suspicious IP activity with auto-blacklisting"""
        if ip not in self.suspicious_ips:
            self.suspicious_ips[ip] = {'count': 0, 'first_seen': datetime.now()}
        
        self.suspicious_ips[ip]['count'] += 1
        self.suspicious_ips[ip]['last_reason'] = reason
        
        self.threat_detected.emit(ip, f"{reason} (attempt {self.suspicious_ips[ip]['count']})")

        # Auto-blacklist if threshold reached
        if self.suspicious_ips[ip]['count'] >= self.auto_blacklist_threshold:
            full_reason = f"Auto-blocked: {reason} ({self.suspicious_ips[ip]['count']} attempts)"
            if add_to_blacklist(ip, full_reason):
                self.threat_detected.emit(ip, f"IP automatically blacklisted: {full_reason}")
                self.blacklist_updated.emit()

    def handle_immediate_threat(self, ip, reason):
        """Handle immediate threats that should be blocked right away"""
        if not is_ip_blacklisted(ip):
            if add_to_blacklist(ip, f"Immediate threat: {reason}"):
                self.threat_detected.emit(ip, f"Immediate threat blocked: {reason}")
                self.blacklist_updated.emit()

    def handle_blacklisted_ip(self, ip):
        """Handle traffic from blacklisted IPs with actual blocking"""
        # Create descriptive rule name
        rule_name = f"NETMON_BLOCK_{ip}_{datetime.now().strftime('%Y%m%d')}"
        
        # Add to Windows Firewall
        if WindowsFirewallManager.block_ip(ip, rule_name):
            self.threat_detected.emit(ip, f"Blocked in Windows Firewall (Rule: {rule_name})")
            self.log_threat(ip, "FW_BLOCKED", f"Added firewall rule {rule_name}")
        else:
            self.threat_detected.emit(ip, "Failed to block in firewall!")
            self.log_threat(ip, "FW_BLOCK_FAILED", "Firewall rule creation failed")

    def handle_immediate_threat(self, ip, reason):
        """Handle immediate threats with firewall blocking"""
        if not is_ip_blacklisted(ip):
            if add_to_blacklist(ip, f"Immediate threat: {reason}"):
                self.handle_blacklisted_ip(ip)  # This will trigger firewall block
                self.threat_detected.emit(ip, f"Immediate threat blocked: {reason}")
                self.blacklist_updated.emit()

    

    def update_threat_intelligence(self):
        """Fetch updated threat intelligence"""
        try:
            response = requests.get(
                "https://my-threat-api.com/known-malicious-ips",
                timeout=5,
                headers={'User-Agent': 'NetworkMonitor/2.0'}
            )
            response.raise_for_status()
            
            # Format: {"ips": {"1.2.3.4": "MALWARE", "5.6.7.8": "APT"}}
            new_threats = response.json().get('ips', {})
            
            # Merge with existing knowledge
            self.known_malicious_ips.update(new_threats)
            
            # Save local cache
            with open("threat_cache.json", "w") as f:
                json.dump(self.known_malicious_ips, f)
                
            self.log_threat("SYSTEM", "THREAT_UPDATE", 
                          f"Updated {len(new_threats)} threat indicators")
            
        except Exception as e:
            print(f"Threat intel update failed: {e}")
            # Fallback to cached data
            try:
                with open("threat_cache.json", "r") as f:
                    self.known_malicious_ips = json.load(f)
            except:
                pass  # Use whatever we have in memory

    def initialize_protection(self):
        """Initialize all security components"""
        # Load threat intelligence
        self.update_threat_intelligence()
        
        # Ensure firewall is configured
        self.configure_firewall()
        
        # Setup logging
        logging.basicConfig(
            filename='network_monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def configure_firewall(self):
        """Ensure Windows Firewall is properly configured"""
        try:
            # Enable firewall if disabled
            subprocess.run(
                'netsh advfirewall set allprofiles state on',
                check=True, shell=True
            )
            logging.info("Windows Firewall verified and enabled")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to configure firewall: {e}")
            self.threat_detected.emit(
                "SYSTEM", 
                "CRITICAL: Failed to configure Windows Firewall!"
            )

    def run(self):
        """Main sniffer loop with enhanced protection"""
        self.initialize_protection()
        
        try:
            scapy.sniff(
                prn=self.process_packet,
                store=False,
                stop_filter=self.should_stop,
                filter="tcp or udp or icmp"
            )
        except Exception as e:
            logging.error(f"Sniffer error: {e}")
            self.threat_detected.emit("SYSTEM", f"Sniffer crashed: {e}")

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

    def stop(self):
        """Stop the sniffer safely"""
        self.running = False
        
    def set_blacklist_threshold(self, threshold):
        """Update the auto-blacklisting threshold"""
        self.auto_blacklist_threshold = threshold