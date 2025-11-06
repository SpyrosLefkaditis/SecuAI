"""
SecuAI Host Blocker Agent
Handles IP blocking operations with safety controls

⚠️  SECURITY WARNING ⚠️
Real blocking functionality is DISABLED by default for safety.
Enable only in controlled environments with proper network isolation.
"""

import os
import subprocess
import logging
from datetime import datetime
from typing import Dict, Any, Tuple
from decouple import config

logger = logging.getLogger(__name__)

# Configuration
SIMULATE_BLOCKS = config('SIMULATE_BLOCKS', default=True, cast=bool)
BLOCK_LOG_FILE = config('BLOCK_LOG_FILE', default='blocked_ips.txt')
REAL_BLOCKING_ENABLED = config('REAL_BLOCKING_ENABLED', default=False, cast=bool)

# Safety checks
ALLOWED_PRIVATE_RANGES = [
    '10.0.0.0/8',
    '172.16.0.0/12', 
    '192.168.0.0/16',
    '127.0.0.0/8'
]

PROTECTED_IPS = [
    '127.0.0.1',
    '::1',
    '0.0.0.0'
]


def simulate_block(ip: str) -> Dict[str, Any]:
    """
    Simulate blocking an IP address (safe mode)
    
    Args:
        ip (str): IP address to simulate blocking
        
    Returns:
        Dict: Result of the simulated block operation
    """
    try:
        timestamp = datetime.utcnow().isoformat()
        
        # Log to file
        log_entry = f"{timestamp} - SIMULATED BLOCK: {ip}\n"
        
        try:
            with open(BLOCK_LOG_FILE, 'a') as f:
                f.write(log_entry)
        except IOError as e:
            logger.warning(f"Could not write to block log file: {e}")
        
        logger.info(f"Simulated block for IP: {ip}")
        
        return {
            'success': True,
            'action': 'simulate',
            'ip': ip,
            'message': f'Simulated blocking of {ip} (logged to {BLOCK_LOG_FILE})',
            'timestamp': timestamp,
            'real_block_applied': False
        }
        
    except Exception as e:
        logger.error(f"Simulation error for {ip}: {e}")
        return {
            'success': False,
            'action': 'simulate',
            'ip': ip,
            'message': f'Simulation failed: {str(e)}',
            'timestamp': datetime.utcnow().isoformat(),
            'real_block_applied': False
        }


def can_apply_real_block() -> bool:
    """
    Check if real blocking is allowed and safe to perform
    
    Returns:
        bool: True if real blocking is allowed
    """
    if not REAL_BLOCKING_ENABLED:
        logger.info("Real blocking is disabled by configuration")
        return False
    
    if SIMULATE_BLOCKS:
        logger.info("Currently in simulation mode")
        return False
    
    # Check if running with appropriate privileges
    if os.geteuid() != 0:
        logger.warning("Real blocking requires root privileges")
        return False
    
    # Check if required tools are available
    required_tools = ['iptables', 'ufw']
    available_tools = []
    
    for tool in required_tools:
        if check_command_available(tool):
            available_tools.append(tool)
    
    if not available_tools:
        logger.error("No blocking tools (iptables/ufw) available")
        return False
    
    logger.info(f"Real blocking available with tools: {available_tools}")
    return True


def check_command_available(command: str) -> bool:
    """Check if a command is available in the system"""
    try:
        subprocess.run(['which', command], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def is_safe_to_block(ip: str) -> Tuple[bool, str]:
    """
    Perform safety checks before blocking an IP
    
    Args:
        ip (str): IP address to check
        
    Returns:
        Tuple[bool, str]: (is_safe, reason)
    """
    # Check for protected IPs
    if ip in PROTECTED_IPS:
        return False, f"IP {ip} is in protected list"
    
    # Check for localhost variants
    if ip.startswith('127.') or ip == '::1':
        return False, f"Cannot block localhost IP {ip}"
    
    # Check for private network ranges (configurable)
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Allow blocking private IPs only in test environments
        if ip_obj.is_private and not config('ALLOW_PRIVATE_BLOCKING', default=False, cast=bool):
            return False, f"Private IP {ip} blocking disabled for safety"
            
        # Block multicast and reserved ranges
        if ip_obj.is_multicast or ip_obj.is_reserved:
            return False, f"Cannot block multicast/reserved IP {ip}"
            
    except ValueError:
        return False, f"Invalid IP address format: {ip}"
    
    return True, "Safe to block"


def apply_iptables_block(ip: str) -> Dict[str, Any]:
    """
    Apply blocking using iptables
    
    ⚠️  WARNING: This function can block network access!
    Only use in controlled environments.
    """
    try:
        # Safety check
        is_safe, reason = is_safe_to_block(ip)
        if not is_safe:
            return {
                'success': False,
                'message': f"Blocking rejected: {reason}",
                'tool': 'iptables'
            }
        
        # Build iptables command
        cmd = [
            'iptables',
            '-I', 'INPUT',
            '-s', ip,
            '-j', 'DROP'
        ]
        
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            logger.info(f"Successfully blocked {ip} with iptables")
            return {
                'success': True,
                'message': f'Successfully blocked {ip} using iptables',
                'tool': 'iptables',
                'command': ' '.join(cmd)
            }
        else:
            logger.error(f"iptables command failed: {result.stderr}")
            return {
                'success': False,
                'message': f'iptables failed: {result.stderr}',
                'tool': 'iptables'
            }
            
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'message': 'iptables command timed out',
            'tool': 'iptables'
        }
    except Exception as e:
        logger.error(f"iptables blocking error: {e}")
        return {
            'success': False,
            'message': f'iptables error: {str(e)}',
            'tool': 'iptables'
        }


def apply_ufw_block(ip: str) -> Dict[str, Any]:
    """
    Apply blocking using UFW (Uncomplicated Firewall)
    
    ⚠️  WARNING: This function can block network access!
    Only use in controlled environments.
    """
    try:
        # Safety check
        is_safe, reason = is_safe_to_block(ip)
        if not is_safe:
            return {
                'success': False,
                'message': f"Blocking rejected: {reason}",
                'tool': 'ufw'
            }
        
        # Build UFW command
        cmd = ['ufw', 'insert', '1', 'deny', 'from', ip]
        
        # Execute command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            logger.info(f"Successfully blocked {ip} with UFW")
            return {
                'success': True,
                'message': f'Successfully blocked {ip} using UFW',
                'tool': 'ufw',
                'command': ' '.join(cmd)
            }
        else:
            logger.error(f"UFW command failed: {result.stderr}")
            return {
                'success': False,
                'message': f'UFW failed: {result.stderr}',
                'tool': 'ufw'
            }
            
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'message': 'UFW command timed out',
            'tool': 'ufw'
        }
    except Exception as e:
        logger.error(f"UFW blocking error: {e}")
        return {
            'success': False,
            'message': f'UFW error: {str(e)}',
            'tool': 'ufw'
        }


def apply_real_block(ip: str) -> Dict[str, Any]:
    """
    Apply real blocking to an IP address
    
    ⚠️  DANGER: This function can permanently block network access!
    ⚠️  Only use in isolated test environments!
    
    Args:
        ip (str): IP address to block
        
    Returns:
        Dict: Result of the block operation
    """
    if not can_apply_real_block():
        return {
            'success': False,
            'message': 'Real blocking is not available or disabled',
            'ip': ip
        }
    
    logger.warning(f"APPLYING REAL BLOCK TO {ip} - THIS IS NOT A SIMULATION!")
    
    # Try UFW first (more user-friendly), then iptables
    if check_command_available('ufw'):
        result = apply_ufw_block(ip)
        if result['success']:
            return result
    
    if check_command_available('iptables'):
        result = apply_iptables_block(ip)
        if result['success']:
            return result
    
    return {
        'success': False,
        'message': 'No suitable blocking tool available',
        'ip': ip
    }


def unblock_ip(ip: str) -> Dict[str, Any]:
    """
    Remove blocking for an IP address
    
    Args:
        ip (str): IP address to unblock
        
    Returns:
        Dict: Result of the unblock operation
    """
    if not can_apply_real_block():
        return {
            'success': False,
            'message': 'Real unblocking is not available (simulation mode)',
            'ip': ip
        }
    
    results = []
    
    # Try to remove from UFW
    if check_command_available('ufw'):
        try:
            cmd = ['ufw', 'delete', 'deny', 'from', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            results.append(f"UFW: {result.returncode == 0}")
        except Exception as e:
            results.append(f"UFW error: {e}")
    
    # Try to remove from iptables
    if check_command_available('iptables'):
        try:
            cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            results.append(f"iptables: {result.returncode == 0}")
        except Exception as e:
            results.append(f"iptables error: {e}")
    
    return {
        'success': True,
        'message': f'Unblock attempted for {ip}',
        'results': results,
        'ip': ip
    }


def get_blocked_ips() -> Dict[str, Any]:
    """
    Get list of currently blocked IPs from the system
    
    Returns:
        Dict: Information about blocked IPs
    """
    blocked_ips = {
        'simulated': [],
        'real': [],
        'tools_available': []
    }
    
    # Read simulated blocks from log file
    try:
        if os.path.exists(BLOCK_LOG_FILE):
            with open(BLOCK_LOG_FILE, 'r') as f:
                for line in f:
                    if 'SIMULATED BLOCK:' in line:
                        # Extract IP from log line
                        parts = line.split('SIMULATED BLOCK: ')
                        if len(parts) > 1:
                            ip = parts[1].strip()
                            blocked_ips['simulated'].append(ip)
    except Exception as e:
        logger.error(f"Error reading block log: {e}")
    
    # Check real blocks if available
    if can_apply_real_block():
        # Check iptables
        if check_command_available('iptables'):
            blocked_ips['tools_available'].append('iptables')
            try:
                result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    # Parse iptables output for blocked IPs
                    for line in result.stdout.split('\n'):
                        if 'DROP' in line and 'tcp' in line:
                            # Basic parsing - could be enhanced
                            parts = line.split()
                            if len(parts) > 3:
                                blocked_ips['real'].append(parts[3])
            except Exception as e:
                logger.error(f"Error checking iptables: {e}")
        
        # Check UFW
        if check_command_available('ufw'):
            blocked_ips['tools_available'].append('ufw')
            try:
                result = subprocess.run(['ufw', 'status', 'numbered'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    # Parse UFW output for blocked IPs
                    for line in result.stdout.split('\n'):
                        if 'DENY IN' in line:
                            # Basic parsing - could be enhanced
                            # UFW output format varies, this is a simple example
                            pass
            except Exception as e:
                logger.error(f"Error checking UFW: {e}")
    
    return blocked_ips


def test_blocking_system():
    """
    Test the blocking system with safe operations
    
    Returns:
        Dict: Test results
    """
    test_results = {
        'simulation_test': False,
        'safety_checks': False,
        'tools_available': [],
        'can_real_block': False,
        'errors': []
    }
    
    try:
        # Test simulation
        test_ip = '203.0.113.1'  # RFC 5737 test IP
        sim_result = simulate_block(test_ip)
        test_results['simulation_test'] = sim_result['success']
        
        # Test safety checks
        safe, reason = is_safe_to_block('127.0.0.1')
        test_results['safety_checks'] = not safe  # Should be False (not safe)
        
        # Check available tools
        for tool in ['iptables', 'ufw']:
            if check_command_available(tool):
                test_results['tools_available'].append(tool)
        
        # Check if real blocking is possible
        test_results['can_real_block'] = can_apply_real_block()
        
    except Exception as e:
        test_results['errors'].append(str(e))
    
    return test_results


if __name__ == '__main__':
    """
    Test script for the blocking system
    """
    print("🧪 SecuAI Host Blocker Test")
    print("=" * 40)
    
    # Run tests
    results = test_blocking_system()
    
    print(f"✅ Simulation test: {'PASS' if results['simulation_test'] else 'FAIL'}")
    print(f"✅ Safety checks: {'PASS' if results['safety_checks'] else 'FAIL'}")
    print(f"🔧 Available tools: {', '.join(results['tools_available']) if results['tools_available'] else 'None'}")
    print(f"⚠️  Real blocking possible: {'YES' if results['can_real_block'] else 'NO'}")
    
    if results['errors']:
        print(f"❌ Errors: {', '.join(results['errors'])}")
    
    # Test simulation
    print("\n🔄 Testing simulation...")
    test_result = simulate_block('203.0.113.99')
    print(f"Result: {test_result['message']}")
    
    print(f"\n📋 Current configuration:")
    print(f"   SIMULATE_BLOCKS: {SIMULATE_BLOCKS}")  
    print(f"   REAL_BLOCKING_ENABLED: {REAL_BLOCKING_ENABLED}")
    print(f"   BLOCK_LOG_FILE: {BLOCK_LOG_FILE}")
    
    print(f"\n🚨 SECURITY REMINDER:")
    print(f"   Real blocking is {'ENABLED' if REAL_BLOCKING_ENABLED else 'DISABLED'}")
    print(f"   Always test in isolated environments first!")