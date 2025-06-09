import scapy.all as scapy
import requests
import re
import json
import subprocess
import logging
from datetime import datetime
from PyQt5.QtCore import QThread, pyqtSignal
from database.db_manager import save_log, is_ip_blacklisted, add_to_blacklist
from alerts.firewall_manager import WindowsFirewallManager

WHITELIST = {"8.8.8.8", "1.1.1.1", "8.8.4.4"}  

class NetworkSniffer(QThread):
    new_ip_signal = pyqtSignal(str, str, int, str, str)
    threat_detected = pyqtSignal(str, str)
    blacklist_updated = pyqtSignal()

    def __init__(self, auto_blacklist_threshold=10):
        super().__init__()
        self.running = True
        self.auto_blacklist_threshold = auto_blacklist_threshold
        self.suspicious_ips = {}
        self.known_malicious_ips = {}
        self.protocol_stats = {}
        self.blocked_ips = set()
        self.ip_info_cache = {}
        self.port_scan_threshold = 10
        self.initialize_protection()

    def initialize_protection(self):
        logging.basicConfig(
            filename='network_monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.update_threat_intelligence()
        self.configure_firewall()

    def configure_firewall(self):
        try:
            subprocess.run(
                'netsh advfirewall set allprofiles state on',
                shell=True, check=True
            )
            logging.info("Windows Firewall verified and enabled")
        except subprocess.CalledProcessError as e:
            logging.error(f"Firewall configuration failed: {str(e)}")
            self.threat_detected.emit("SYSTEM", "CRITICAL: Failed to configure Windows Firewall")

    def update_threat_intelligence(self):
        threat_sources = [
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "https://reputation.alienvault.com/reputation.data"
        ]
        for source in threat_sources:
            try:
                response = requests.get(source, timeout=10)
                response.raise_for_status()
                if "github" in source:
                    self.known_malicious_ips.update({
                        parts[0]: f"Threat level {parts[1]}"
                        for line in response.text.split('\n') if '\t' in line and (parts := line.split('\t'))
                    })
                elif "alienvault" in source:
                    self.known_malicious_ips.update({
                        line.split('#')[0].strip(): line.split('#')[1].strip()
                        for line in response.text.split('\n') if '#' in line
                    })
                else:
                    self.known_malicious_ips.update({
                        ip.strip(): "Known threat"
                        for ip in response.text.split('\n') if ip.strip() and not ip.startswith('#')
                    })
                with open("threat_cache.json", "w") as f:
                    json.dump(self.known_malicious_ips, f)
                logging.info(f"Threat intelligence updated from {source}")
                return
            except Exception as e:
                logging.warning(f"Failed to update from {source}: {str(e)}")

        try:
            with open("threat_cache.json", "r") as f:
                self.known_malicious_ips = json.load(f)
        except:
            self.known_malicious_ips = {
                '185.143.223.62': "Example threat 1",
                '91.219.236.222': "Example threat 2"
            }

    def run(self):
        try:
            while self.running:
                try:
                    scapy.sniff(
                        prn=self.process_packet,
                        store=False,
                        stop_filter=lambda _: not self.running,
                        filter="(tcp or udp or icmp) and not src net 192.168.0.0/16",
                        timeout=1
                    )
                except Exception as e:
                    logging.error(f"Sniffing error: {str(e)}")
        except Exception as e:
            logging.error(f"Sniffer crashed: {str(e)}")
            self.threat_detected.emit("SYSTEM", f"Sniffer crashed: {str(e)}")

    def process_packet(self, packet):
        if not self.running or not packet or not packet.haslayer(scapy.IP):
            return
        try:
            ip_src = packet[scapy.IP].src
            if ip_src in WHITELIST or is_ip_blacklisted(ip_src):
                return
            self.handle_packet(ip_src, packet)
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def handle_packet(self, ip_src, packet):
        protocol, port = self.get_protocol_and_port(packet)
        country, provider = self.get_ip_info(ip_src)
        save_log(ip_src, protocol, port, country, provider)
        self.new_ip_signal.emit(ip_src, protocol, port, country, provider)
        self.update_protocol_stats(ip_src, protocol, port)
        self.analyze_for_threats(ip_src, protocol, port, packet)

    def get_protocol_and_port(self, packet):
        protocol = "Other"
        port = 0
        try:
            if packet.haslayer(scapy.TCP):
                protocol = "TCP"
                flags = packet[scapy.TCP].flags
                if flags & 0x02:
                    protocol = "TCP-SYN"
                elif flags & 0x10:
                    protocol = "TCP-ACK"
                port = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                protocol = "UDP"
                port = packet[scapy.UDP].dport
            elif packet.haslayer(scapy.ICMP):
                protocol = "ICMP"
        except Exception as e:
            logging.error(f"Error extracting protocol/port: {str(e)}")
        return protocol, port

    def update_protocol_stats(self, ip, protocol, port):
        if ip not in self.protocol_stats:
            self.protocol_stats[ip] = {
                'protocols': {}, 'ports': {}, 'first_seen': datetime.now(), 'total_packets': 0
            }
        stats = self.protocol_stats[ip]
        stats['total_packets'] += 1
        stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1
        if port > 0:
            stats['ports'][port] = stats['ports'].get(port, 0) + 1

    def analyze_for_threats(self, ip, protocol, port, packet):
        self.check_suspicious_ports(ip, port)
        self.detect_port_scanning(ip)
        self.check_protocol_anomalies(ip)
        if "TCP-SYN" in protocol:
            self.detect_syn_flood(ip)
        if packet.haslayer(scapy.Raw):
            self.check_malicious_payload(ip, str(packet[scapy.Raw].load))
        if ip in self.known_malicious_ips:
            self.handle_immediate_threat(ip, f"Known malicious IP: {self.known_malicious_ips[ip]}")

    def check_suspicious_ports(self, ip, port):
        vulnerable_ports = {
            22: "SSH brute force", 23: "Telnet", 3389: "RDP", 445: "SMB",
            1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL",
            5900: "VNC", 8080: "Web admin"
        }
        if port in vulnerable_ports:
            self.handle_suspicious_activity(ip, f"{vulnerable_ports[port]} attempt")

    def detect_port_scanning(self, ip):
        stats = self.protocol_stats.get(ip)
        if not stats: return
        elapsed = (datetime.now() - stats['first_seen']).seconds
        if elapsed > 0 and len(stats['ports']) / elapsed > 5:
            self.handle_immediate_threat(ip, "Fast port scan detected")
        elif len(stats['ports']) >= self.port_scan_threshold:
            self.handle_immediate_threat(ip, "Port scan detected")

    def check_protocol_anomalies(self, ip):
        stats = self.protocol_stats.get(ip)
        if not stats: return
        if 'ICMP' in stats['protocols'] and stats['protocols']['ICMP'] / stats['total_packets'] > 0.8:
            self.handle_suspicious_activity(ip, "ICMP flood")
        if 'TCP-SYN' in stats['protocols'] and stats['protocols']['TCP-SYN'] / stats['total_packets'] > 0.7:
            self.handle_suspicious_activity(ip, "SYN flood")

    def detect_syn_flood(self, ip):
        if ip not in self.suspicious_ips:
            self.suspicious_ips[ip] = {'syn_count': 0, 'first_syn': datetime.now()}
        self.suspicious_ips[ip]['syn_count'] += 1
        elapsed = (datetime.now() - self.suspicious_ips[ip]['first_syn']).seconds
        if elapsed > 5:
            self.suspicious_ips[ip] = {'syn_count': 1, 'first_syn': datetime.now()}
        elif self.suspicious_ips[ip]['syn_count'] > 50:
            self.handle_immediate_threat(ip, "SYN flood attack")

    def check_malicious_payload(self, ip, payload):
        patterns = {
            'SQL Injection': [r'\b(union\s+select|select\s+\*|insert\s+into|drop\s+table)',
                              r'(\'|\"|--|;|\/\*)\s*', r'\b(1=1|true|waitfor\s+delay)\b'],
            'XSS': [r'<script>|javascript:|onerror=|onload=', r'document\.|window\.|alert\('],
            'RCE': [r'\b(rm\s+-rf|wget\s+|curl\s+|bash\s+|sh\+|cmd\.exe)', r'\|\s*(sh|bash)$']
        }
        for threat_type, regex_list in patterns.items():
            for pattern in regex_list:
                if re.search(pattern, payload, re.IGNORECASE):
                    # ƒополнительна€ проверка через внешние сервисы
                    if self.is_ip_really_malicious(ip):
                        self.handle_immediate_threat(ip, f"{threat_type} attempt")
                    else:
                        self.handle_suspicious_activity(ip, f"Suspicious {threat_type} payload")
                    return

    def is_ip_really_malicious(self, ip):
        abuse_score = 0
        try:
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                headers={"Key": "e86e84afcfe924fd8f368f5f9ffc859eecc9db3d0e19942505c447709f0eaf1d00f68abcc1357b0d", "Accept": "application/json"},
                timeout=3
            )
            data = response.json()
            abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
        except Exception as e:
            logging.warning(f"AbuseIPDB check failed for {ip}: {str(e)}")

        vt_malicious = self.is_ip_malicious_virustotal(ip)

        if abuse_score > 70 or vt_malicious:
            return True
        return False

    def is_ip_malicious_virustotal(self, ip):
        try:
            headers = {
                "x-apikey": "1e38f6f4b20132aad9ff01e1e47e8af8849a44bd2d2f23aff7dcd382d0ac6689",  
                "Accept": "application/json"
            }
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers, timeout=5
            )
            if response.status_code != 200:
                logging.warning(f"VirusTotal query failed for {ip}: HTTP {response.status_code}")
                return False

            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            return (malicious + suspicious) >= 2  
        except Exception as e:
            logging.warning(f"VirusTotal check failed for {ip}: {str(e)}")
            return False

    def handle_suspicious_activity(self, ip, reason):
        if ip not in self.suspicious_ips:
            self.suspicious_ips[ip] = {'count': 0, 'first_seen': datetime.now(), 'last_reason': reason}
        self.suspicious_ips[ip]['count'] += 1
        self.suspicious_ips[ip]['last_reason'] = reason
        self.threat_detected.emit(ip, f"{reason} (attempt {self.suspicious_ips[ip]['count']})")
        if self.suspicious_ips[ip]['count'] >= self.auto_blacklist_threshold:
            if self.is_ip_really_malicious(ip) and add_to_blacklist(ip, reason):
                self.handle_blacklisted_ip(ip)
                self.blacklist_updated.emit()

    def handle_immediate_threat(self, ip, reason):
        if ip in self.blocked_ips or is_ip_blacklisted(ip) or ip in WHITELIST:
            return
        if self.is_ip_really_malicious(ip) and add_to_blacklist(ip, reason):
            self.blocked_ips.add(ip)
            self.handle_blacklisted_ip(ip)
            self.threat_detected.emit(ip, f"Immediate block: {reason}")
            self.blacklist_updated.emit()

    def handle_blacklisted_ip(self, ip):
        rule_name = f"NETMON_BLOCK_{ip}_{datetime.now().strftime('%Y%m%d')}"
        try:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}', 'dir=in', 'action=block',
                f'remoteip={ip}', 'protocol=any', 'enable=yes'
            ], check=True, shell=True)
            logging.info(f"Blocked {ip} via firewall")
        except subprocess.CalledProcessError as e:
            logging.error(f"Firewall block failed: {e}")
            self.threat_detected.emit(ip, "Firewall block failed!")

    def get_ip_info(self, ip):
        if ip in self.ip_info_cache:
            return self.ip_info_cache[ip]
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,as", timeout=3)
            data = response.json()
            if data["status"] != "success":
                raise Exception("Failed to fetch IP info")
            country = data.get("country", "Unknown")
            region = data.get("regionName", "")
            city = data.get("city", "")
            isp = data.get("isp", "Unknown")
            asn = data.get("as", "Unknown")
            provider_info = f"{isp} ({asn})"
            location_info = f"{country}, {region}, {city}".strip(', ')
            result = (location_info, provider_info)
            self.ip_info_cache[ip] = result
            return result
        except Exception as e:
            logging.warning(f"IP info lookup failed for {ip}: {str(e)}")
            return "Unknown", "Unknown"

    def stop(self):
        self.running = False
        self.suspicious_ips.clear()
        self.protocol_stats.clear()
        self.blocked_ips.clear()

    def set_blacklist_threshold(self, threshold):
        self.auto_blacklist_threshold = threshold