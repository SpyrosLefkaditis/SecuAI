"""
SecuAI Host Blocker Tests
Test suite for blocking functionality and safety measures
"""

import pytest
import tempfile
import os
from unittest.mock import patch, MagicMock

# Import blocker components
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.host_blocker import (
    simulate_block,
    can_apply_real_block,
    is_safe_to_block,
    check_command_available,
    test_blocking_system,
    get_blocked_ips
)


class TestSimulateBlock:
    """Test simulation blocking functionality"""
    
    def test_simulate_block_success(self):
        """Test successful IP block simulation"""
        result = simulate_block('203.0.113.1')
        
        assert result['success'] is True
        assert result['action'] == 'simulate'
        assert result['ip'] == '203.0.113.1'
        assert 'simulated blocking' in result['message'].lower()
        assert result['real_block_applied'] is False
    
    def test_simulate_block_creates_log(self):
        """Test that simulation creates log entry"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            log_file = f.name
        
        try:
            with patch('agents.host_blocker.BLOCK_LOG_FILE', log_file):
                result = simulate_block('198.51.100.1')
                assert result['success'] is True
                
                # Check log file was created and contains entry
                with open(log_file, 'r') as f:
                    content = f.read()
                    assert '198.51.100.1' in content
                    assert 'SIMULATED BLOCK' in content
        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)
    
    def test_simulate_block_invalid_ip(self):
        """Test simulation with invalid IP"""
        # Should still work for simulation (real validation happens in is_safe_to_block)
        result = simulate_block('invalid-ip')
        assert result['success'] is True  # Simulation doesn't validate IP format


class TestSafetyChecks:
    """Test safety validation functions"""
    
    def test_is_safe_to_block_localhost(self):
        """Test blocking localhost is rejected"""
        safe, reason = is_safe_to_block('127.0.0.1')
        assert safe is False
        assert 'localhost' in reason.lower()
        
        safe, reason = is_safe_to_block('::1')
        assert safe is False
        assert 'localhost' in reason.lower()
    
    def test_is_safe_to_block_protected_ips(self):
        """Test blocking protected IPs is rejected"""
        safe, reason = is_safe_to_block('0.0.0.0')
        assert safe is False
        assert 'protected' in reason.lower()
    
    def test_is_safe_to_block_private_networks(self):
        """Test blocking private networks (default: disabled)"""
        private_ips = ['10.0.0.1', '172.16.0.1', '192.168.1.1']
        
        for ip in private_ips:
            safe, reason = is_safe_to_block(ip)
            # By default, private IP blocking should be disabled for safety
            assert safe is False or 'private' in reason.lower()
    
    def test_is_safe_to_block_valid_public_ip(self):
        """Test blocking valid public IP is allowed"""
        safe, reason = is_safe_to_block('203.0.113.1')  # RFC 5737 test IP
        assert safe is True
        assert reason == "Safe to block"
    
    def test_is_safe_to_block_invalid_format(self):
        """Test invalid IP format is rejected"""
        invalid_ips = ['not-an-ip', '999.999.999.999', 'example.com']
        
        for ip in invalid_ips:
            safe, reason = is_safe_to_block(ip)
            assert safe is False
            assert 'invalid' in reason.lower()
    
    def test_is_safe_to_block_multicast_reserved(self):
        """Test multicast and reserved IPs are rejected"""
        # Test multicast IP
        safe, reason = is_safe_to_block('224.0.0.1')
        assert safe is False
        assert 'multicast' in reason.lower() or 'reserved' in reason.lower()


class TestRealBlockingCapabilities:
    """Test real blocking capability checks"""
    
    def test_can_apply_real_block_disabled_by_config(self):
        """Test real blocking disabled by configuration"""
        with patch('agents.host_blocker.REAL_BLOCKING_ENABLED', False):
            result = can_apply_real_block()
            assert result is False
    
    def test_can_apply_real_block_simulation_mode(self):
        """Test real blocking disabled in simulation mode"""
        with patch('agents.host_blocker.SIMULATE_BLOCKS', True):
            result = can_apply_real_block()
            assert result is False
    
    @patch('os.geteuid')
    def test_can_apply_real_block_no_root(self, mock_geteuid):
        """Test real blocking requires root privileges"""
        mock_geteuid.return_value = 1000  # Non-root user
        
        with patch('agents.host_blocker.REAL_BLOCKING_ENABLED', True), \
             patch('agents.host_blocker.SIMULATE_BLOCKS', False):
            result = can_apply_real_block()
            assert result is False
    
    def test_check_command_available(self):
        """Test command availability checking"""
        # Test with a command that should exist
        assert check_command_available('echo') is True
        
        # Test with a command that shouldn't exist
        assert check_command_available('this-command-does-not-exist-12345') is False


class TestBlockingSystem:
    """Test the overall blocking system"""
    
    def test_test_blocking_system(self):
        """Test the system test function"""
        results = test_blocking_system()
        
        assert 'simulation_test' in results
        assert 'safety_checks' in results
        assert 'tools_available' in results
        assert 'can_real_block' in results
        
        # Simulation should always work
        assert results['simulation_test'] is True
        
        # Safety checks should work (blocking localhost should be rejected)
        assert results['safety_checks'] is True
        
        # Tools available should be a list
        assert isinstance(results['tools_available'], list)
    
    def test_get_blocked_ips_empty(self):
        """Test getting blocked IPs when none exist"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            log_file = f.name
        
        try:
            with patch('agents.host_blocker.BLOCK_LOG_FILE', log_file):
                result = get_blocked_ips()
                
                assert 'simulated' in result
                assert 'real' in result
                assert 'tools_available' in result
                assert isinstance(result['simulated'], list)
                assert isinstance(result['real'], list)
        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)
    
    def test_get_blocked_ips_with_simulated(self):
        """Test getting blocked IPs with simulated entries"""
        log_content = """2023-10-15T10:30:00.000000 - SIMULATED BLOCK: 203.0.113.1
2023-10-15T10:31:00.000000 - SIMULATED BLOCK: 198.51.100.1
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(log_content)
            log_file = f.name
        
        try:
            with patch('agents.host_blocker.BLOCK_LOG_FILE', log_file):
                result = get_blocked_ips()
                
                assert len(result['simulated']) == 2
                assert '203.0.113.1' in result['simulated']
                assert '198.51.100.1' in result['simulated']
        finally:
            if os.path.exists(log_file):
                os.unlink(log_file)


class TestIPValidation:
    """Test IP address validation and parsing"""
    
    def test_ipv4_validation(self):
        """Test IPv4 address validation"""
        valid_ipv4 = ['192.168.1.1', '10.0.0.1', '203.0.113.1', '8.8.8.8']
        
        for ip in valid_ipv4:
            safe, reason = is_safe_to_block(ip)
            # Should not fail due to format (may fail for other reasons like being private)
            assert 'invalid' not in reason.lower()
    
    def test_ipv6_validation(self):
        """Test IPv6 address validation"""
        # Basic IPv6 validation test
        safe, reason = is_safe_to_block('2001:db8::1')
        # Should handle IPv6 format (implementation may vary)
        assert isinstance(safe, bool)
    
    def test_cidr_notation(self):
        """Test CIDR notation handling"""
        # This would test if CIDR ranges are handled properly
        # Implementation depends on requirements
        pass


class TestErrorHandling:
    """Test error handling in blocking system"""
    
    def test_simulate_block_file_permission_error(self):
        """Test simulation when log file can't be written"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            # Should still succeed but log the error
            result = simulate_block('203.0.113.1')
            assert result['success'] is True  # Should handle gracefully
    
    def test_blocking_with_network_errors(self):
        """Test blocking with network/system errors"""
        # This would test how the system handles network or system command failures
        pass


class TestConfigurationOptions:
    """Test different configuration scenarios"""
    
    def test_different_block_log_locations(self):
        """Test with different block log file locations"""
        custom_log = '/tmp/custom_blocks.log'
        
        with patch('agents.host_blocker.BLOCK_LOG_FILE', custom_log):
            result = simulate_block('203.0.113.1')
            assert result['success'] is True
            
            # Clean up
            if os.path.exists(custom_log):
                os.unlink(custom_log)
    
    def test_private_ip_blocking_enabled(self):
        """Test when private IP blocking is explicitly enabled"""
        with patch('agents.host_blocker.config') as mock_config:
            mock_config.return_value = True  # ALLOW_PRIVATE_BLOCKING=True
            
            safe, reason = is_safe_to_block('192.168.1.100')
            # When private blocking is enabled, should be safe (unless other restrictions)
            # Implementation may vary based on exact logic


if __name__ == '__main__':
    pytest.main([__file__, '-v'])