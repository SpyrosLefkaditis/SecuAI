"""
SecuAI Firewall Management Module
Integrates with iptables for IP blocking and whitelisting
"""

import subprocess
import logging
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class FirewallManager:
    """
    Manages firewall rules using iptables with safety features
    """
    
    def __init__(self, simulate_mode: bool = True):
        """
        Initialize firewall manager
        
        Args:
            simulate_mode: If True, only simulate changes without applying them
        """
        self.simulate_mode = simulate_mode
        self.chain_name = "SECUAI_BLOCK"
        self.whitelist_chain = "SECUAI_WHITELIST"
        
        # Initialize chains if not in simulation mode
        if not self.simulate_mode:
            self._ensure_chains_exist()
    
    def _ensure_chains_exist(self) -> bool:
        """
        Ensure SecuAI iptables chains exist
        
        Returns:
            bool: True if chains exist or were created successfully
        """
        try:
            # Check if chains exist
            result = subprocess.run(['iptables', '-L', self.chain_name], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                # Create block chain
                subprocess.run(['iptables', '-N', self.chain_name], check=True)
                # Insert reference to our chain in INPUT
                subprocess.run(['iptables', '-I', 'INPUT', '-j', self.chain_name], check=True)
                logger.info(f"Created iptables chain: {self.chain_name}")
            
            # Check whitelist chain
            result = subprocess.run(['iptables', '-L', self.whitelist_chain], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                # Create whitelist chain
                subprocess.run(['iptables', '-N', self.whitelist_chain], check=True)
                # Insert reference before block chain
                subprocess.run(['iptables', '-I', 'INPUT', '1', '-j', self.whitelist_chain], check=True)
                logger.info(f"Created iptables chain: {self.whitelist_chain}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create iptables chains: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error creating chains: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str = "SecuAI Block") -> Dict[str, any]:
        """
        Block an IP address using iptables
        
        Args:
            ip: IP address or CIDR to block
            reason: Reason for blocking
            
        Returns:
            Dict with status and message
        """
        try:
            # Validate IP address
            if not self._is_valid_ip(ip):
                return {
                    'status': 'error',
                    'message': f'Invalid IP address format: {ip}'
                }
            
            # Safety check - don't block local networks
            if self._is_local_ip(ip):
                return {
                    'status': 'error',
                    'message': f'Cannot block local network IP: {ip}'
                }
            
            if self.simulate_mode:
                logger.info(f"[SIMULATION] Would block IP {ip} - {reason}")
                return {
                    'status': 'success',
                    'message': f'Simulated blocking of {ip}',
                    'simulated': True
                }
            
            # Add iptables rule
            cmd = ['iptables', '-A', self.chain_name, '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            logger.info(f"Blocked IP {ip} via iptables - {reason}")
            
            return {
                'status': 'success',
                'message': f'Successfully blocked {ip}',
                'rule_applied': True
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to block IP {ip}: {e.stderr}"
            logger.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg
            }
        except Exception as e:
            error_msg = f"Unexpected error blocking IP {ip}: {str(e)}"
            logger.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg
            }
    
    def unblock_ip(self, ip: str) -> Dict[str, any]:
        """
        Unblock an IP address by removing iptables rule
        
        Args:
            ip: IP address or CIDR to unblock
            
        Returns:
            Dict with status and message
        """
        try:
            if not self._is_valid_ip(ip):
                return {
                    'status': 'error',
                    'message': f'Invalid IP address format: {ip}'
                }
            
            if self.simulate_mode:
                logger.info(f"[SIMULATION] Would unblock IP {ip}")
                return {
                    'status': 'success',
                    'message': f'Simulated unblocking of {ip}',
                    'simulated': True
                }
            
            # Remove iptables rule
            cmd = ['iptables', '-D', self.chain_name, '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Unblocked IP {ip} via iptables")
                return {
                    'status': 'success',
                    'message': f'Successfully unblocked {ip}',
                    'rule_removed': True
                }
            else:
                return {
                    'status': 'warning',
                    'message': f'No active block rule found for {ip}'
                }
                
        except Exception as e:
            error_msg = f"Error unblocking IP {ip}: {str(e)}"
            logger.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg
            }
    
    def whitelist_ip(self, ip: str, description: str = "SecuAI Whitelist") -> Dict[str, any]:
        """
        Whitelist an IP address using iptables
        
        Args:
            ip: IP address or CIDR to whitelist
            description: Description for whitelist entry
            
        Returns:
            Dict with status and message
        """
        try:
            if not self._is_valid_ip(ip):
                return {
                    'status': 'error',
                    'message': f'Invalid IP address format: {ip}'
                }
            
            if self.simulate_mode:
                logger.info(f"[SIMULATION] Would whitelist IP {ip} - {description}")
                return {
                    'status': 'success',
                    'message': f'Simulated whitelisting of {ip}',
                    'simulated': True
                }
            
            # Add whitelist rule (ACCEPT before any blocking rules)
            cmd = ['iptables', '-A', self.whitelist_chain, '-s', ip, '-j', 'ACCEPT']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            logger.info(f"Whitelisted IP {ip} via iptables - {description}")
            
            return {
                'status': 'success',
                'message': f'Successfully whitelisted {ip}',
                'rule_applied': True
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to whitelist IP {ip}: {e.stderr}"
            logger.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg
            }
        except Exception as e:
            error_msg = f"Unexpected error whitelisting IP {ip}: {str(e)}"
            logger.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg
            }
    
    def remove_whitelist(self, ip: str) -> Dict[str, any]:
        """
        Remove IP from whitelist
        
        Args:
            ip: IP address to remove from whitelist
            
        Returns:
            Dict with status and message
        """
        try:
            if not self._is_valid_ip(ip):
                return {
                    'status': 'error',
                    'message': f'Invalid IP address format: {ip}'
                }
            
            if self.simulate_mode:
                logger.info(f"[SIMULATION] Would remove {ip} from whitelist")
                return {
                    'status': 'success',
                    'message': f'Simulated removal of {ip} from whitelist',
                    'simulated': True
                }
            
            # Remove whitelist rule
            cmd = ['iptables', '-D', self.whitelist_chain, '-s', ip, '-j', 'ACCEPT']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Removed IP {ip} from whitelist")
                return {
                    'status': 'success',
                    'message': f'Successfully removed {ip} from whitelist',
                    'rule_removed': True
                }
            else:
                return {
                    'status': 'warning',
                    'message': f'No whitelist rule found for {ip}'
                }
                
        except Exception as e:
            error_msg = f"Error removing {ip} from whitelist: {str(e)}"
            logger.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg
            }
    
    def get_blocked_ips(self) -> List[Dict[str, any]]:
        """
        Get list of currently blocked IPs from iptables
        
        Returns:
            List of blocked IP dictionaries
        """
        try:
            if self.simulate_mode:
                # Return simulated data
                return [
                    {
                        'ip': '192.168.100.100',
                        'target': 'DROP',
                        'packets': 15,
                        'bytes': 1200,
                        'simulated': True
                    },
                    {
                        'ip': '10.0.0.50',
                        'target': 'DROP',
                        'packets': 8,
                        'bytes': 640,
                        'simulated': True
                    }
                ]
            
            # Get rules from our chain
            cmd = ['iptables', '-L', self.chain_name, '-n', '-v', '--line-numbers']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return []
            
            blocked_ips = []
            lines = result.stdout.split('\n')[2:]  # Skip header lines
            
            for line in lines:
                if line.strip() and 'DROP' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        blocked_ips.append({
                            'line_number': parts[0],
                            'packets': parts[1],
                            'bytes': parts[2],
                            'target': parts[3],
                            'ip': parts[8] if parts[8] != '0.0.0.0/0' else 'Any',
                        })
            
            return blocked_ips
            
        except Exception as e:
            logger.error(f"Error getting blocked IPs: {e}")
            return []
    
    def get_whitelisted_ips(self) -> List[Dict[str, any]]:
        """
        Get list of currently whitelisted IPs from iptables
        
        Returns:
            List of whitelisted IP dictionaries
        """
        try:
            if self.simulate_mode:
                # Return simulated data
                return [
                    {
                        'ip': '192.168.1.0/24',
                        'target': 'ACCEPT',
                        'packets': 1250,
                        'bytes': 125000,
                        'simulated': True
                    },
                    {
                        'ip': '10.0.0.1',
                        'target': 'ACCEPT',
                        'packets': 50,
                        'bytes': 4000,
                        'simulated': True
                    }
                ]
            
            # Get rules from whitelist chain
            cmd = ['iptables', '-L', self.whitelist_chain, '-n', '-v', '--line-numbers']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return []
            
            whitelisted_ips = []
            lines = result.stdout.split('\n')[2:]  # Skip header lines
            
            for line in lines:
                if line.strip() and 'ACCEPT' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        whitelisted_ips.append({
                            'line_number': parts[0],
                            'packets': parts[1],
                            'bytes': parts[2],
                            'target': parts[3],
                            'ip': parts[8] if parts[8] != '0.0.0.0/0' else 'Any',
                        })
            
            return whitelisted_ips
            
        except Exception as e:
            logger.error(f"Error getting whitelisted IPs: {e}")
            return []
    
    def backup_rules(self) -> Optional[str]:
        """
        Create backup of current iptables rules
        
        Returns:
            Backup content as string or None if failed
        """
        try:
            if self.simulate_mode:
                return "# Simulated iptables backup\n# SecuAI firewall rules"
            
            result = subprocess.run(['iptables-save'], capture_output=True, text=True, check=True)
            return result.stdout
            
        except Exception as e:
            logger.error(f"Error creating iptables backup: {e}")
            return None
    
    def restore_rules(self, backup_content: str) -> bool:
        """
        Restore iptables rules from backup
        
        Args:
            backup_content: Previously saved iptables rules
            
        Returns:
            bool: True if restore successful
        """
        try:
            if self.simulate_mode:
                logger.info("[SIMULATION] Would restore iptables rules")
                return True
            
            process = subprocess.Popen(['iptables-restore'], 
                                     stdin=subprocess.PIPE, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, 
                                     text=True)
            stdout, stderr = process.communicate(input=backup_content)
            
            if process.returncode == 0:
                logger.info("Successfully restored iptables rules")
                return True
            else:
                logger.error(f"Failed to restore iptables rules: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error restoring iptables rules: {e}")
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate IP address format
        
        Args:
            ip: IP address to validate
            
        Returns:
            bool: True if valid IP or CIDR
        """
        # IPv4 address pattern
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$'
        
        # IPv6 pattern (basic)
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        
        return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))
    
    def _is_local_ip(self, ip: str) -> bool:
        """
        Check if IP is in local/private ranges that shouldn't be blocked
        
        Args:
            ip: IP address to check
            
        Returns:
            bool: True if IP is in local ranges
        """
        # Remove CIDR notation for checking
        ip_addr = ip.split('/')[0]
        
        # Local ranges that should never be blocked
        local_ranges = [
            '127.',      # Loopback
            '10.',       # Private Class A
            '172.16.',   # Private Class B start
            '172.17.',   # Private Class B
            '172.18.',   # Private Class B
            '172.19.',   # Private Class B
            '172.20.',   # Private Class B
            '172.21.',   # Private Class B
            '172.22.',   # Private Class B
            '172.23.',   # Private Class B
            '172.24.',   # Private Class B
            '172.25.',   # Private Class B
            '172.26.',   # Private Class B
            '172.27.',   # Private Class B
            '172.28.',   # Private Class B
            '172.29.',   # Private Class B
            '172.30.',   # Private Class B
            '172.31.',   # Private Class B end
            '192.168.',  # Private Class C
            '169.254.',  # Link-local
        ]
        
        return any(ip_addr.startswith(range_start) for range_start in local_ranges)
    
    def get_firewall_status(self) -> Dict[str, any]:
        """
        Get overall firewall status
        
        Returns:
            Dict with firewall status information
        """
        try:
            if self.simulate_mode:
                return {
                    'active': True,
                    'simulation_mode': True,
                    'chains_exist': True,
                    'blocked_count': 2,
                    'whitelisted_count': 2
                }
            
            # Check if iptables is running and our chains exist
            block_result = subprocess.run(['iptables', '-L', self.chain_name], 
                                        capture_output=True, text=True)
            whitelist_result = subprocess.run(['iptables', '-L', self.whitelist_chain], 
                                            capture_output=True, text=True)
            
            blocked_ips = self.get_blocked_ips()
            whitelisted_ips = self.get_whitelisted_ips()
            
            return {
                'active': block_result.returncode == 0 and whitelist_result.returncode == 0,
                'simulation_mode': False,
                'chains_exist': block_result.returncode == 0 and whitelist_result.returncode == 0,
                'blocked_count': len(blocked_ips),
                'whitelisted_count': len(whitelisted_ips)
            }
            
        except Exception as e:
            logger.error(f"Error getting firewall status: {e}")
            return {
                'active': False,
                'simulation_mode': self.simulate_mode,
                'chains_exist': False,
                'blocked_count': 0,
                'whitelisted_count': 0,
                'error': str(e)
            }


# Global firewall manager instance
firewall_manager = FirewallManager(simulate_mode=True)  # Safe default