import os
import subprocess
from datetime import datetime

class WindowsFirewallManager:
    @staticmethod
    def block_ip(ip_address, rule_name=None):
        """Block an IP address in Windows Firewall"""
        if not rule_name:
            rule_name = f"Blocked_{ip_address}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Create inbound block rule
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}"',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}',
                'enable=yes'
            ], check=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip_address}: {e}")
            return False

    @staticmethod
    def unblock_ip(rule_name):
        """Remove a firewall rule by name"""
        try:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name="{rule_name}"'
            ], check=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to remove rule {rule_name}: {e}")
            return False

    @staticmethod
    def list_blocked_ips():
        """List all active block rules"""
        try:
            result = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
            ], capture_output=True, text=True, shell=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Failed to list rules: {e}")
            return ""