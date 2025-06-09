import os
import subprocess
from datetime import datetime

class WindowsFirewallManager:
    @staticmethod
    def _generate_rule_name(ip_address):
        """Generate consistent rule name for an IP"""
        return f"NETMON_BLOCK_{ip_address}"

    @staticmethod
    def block_ip(ip_address):
        """
        Block an IP address in Windows Firewall.
        Ensures only one rule exists per IP.
        Returns True if successful, False otherwise.
        """
        rule_name = WindowsFirewallManager._generate_rule_name(ip_address)
        
        # First check if rule already exists
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'],
                capture_output=True,
                text=True,
                shell=True
            )
            
            # If rule exists (return code 0), delete it first to refresh
            if result.returncode == 0:
                WindowsFirewallManager.unblock_ip(ip_address)
        except subprocess.CalledProcessError:
            pass  # Rule doesn't exist yet
        
        try:
            # Create new inbound block rule
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}',
                'protocol=any',
                'enable=yes'
            ], check=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip_address}: {e}")
            return False

    @staticmethod
    def unblock_ip(ip_address):
        """
        Remove firewall rule for specific IP.
        Returns True if successful or rule didn't exist, False otherwise.
        """
        rule_name = WindowsFirewallManager._generate_rule_name(ip_address)
        
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                capture_output=True,
                text=True,
                shell=True
            )
            return True
        except subprocess.CalledProcessError as e:
            if "The specified rule does not exist" in str(e.stderr):
                return True  # Rule didn't exist, which is fine
            print(f"Failed to remove rule for IP {ip_address}: {e}")
            return False

    @staticmethod
    def is_ip_blocked(ip_address):
        """Check if an IP is currently blocked"""
        rule_name = WindowsFirewallManager._generate_rule_name(ip_address)
        
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'],
                capture_output=True,
                text=True,
                shell=True
            )
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def list_blocked_ips():
        """List all IPs currently blocked by our rules"""
        blocked_ips = []
        
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
                capture_output=True,
                text=True,
                shell=True
            )
            
            # Parse output to find our rules
            for line in result.stdout.split('\n'):
                if 'NETMON_BLOCK_' in line:
                    parts = line.split()
                    if len(parts) > 1:
                        rule_name = parts[1].strip()
                        ip = rule_name.replace('NETMON_BLOCK_', '')
                        blocked_ips.append(ip)
            
            return blocked_ips
        except subprocess.CalledProcessError as e:
            print(f"Failed to list blocked IPs: {e}")
            return []