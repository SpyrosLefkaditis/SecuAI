"""
Test suite for SecuAI log analyzer
Tests rule-based detection and ML enrichment functionality
"""

import pytest
import json
from analyzer import (
    analyze_logs,
    detect_failed_logins,
    detect_port_scans,
    detect_web_probing,
    detect_suricata_alerts,
    ml_enrich,
    generate_mock_ml_enrichment,
    parse_honeypot_feed
)


class TestLogAnalyzer:
    """Test cases for log analysis functionality"""
    
    def test_failed_login_detection(self):
        """Test SSH failed login detection"""
        sample_logs = [
            "Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2",
            "Oct 15 10:30:20 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2",
            "Oct 15 10:30:25 server sshd[12347]: Failed password for user from 192.168.1.100 port 22 ssh2",
            "Oct 15 10:30:30 server sshd[12348]: Failed password for test from 192.168.1.100 port 22 ssh2"
        ]
        
        findings = detect_failed_logins(sample_logs)
        
        assert len(findings) == 1
        assert findings[0]['ip'] == '192.168.1.100'
        assert 'failed login' in findings[0]['reason'].lower()
        assert findings[0]['confidence'] >= 0.5
        assert findings[0]['details']['attempt_count'] == 4
    
    def test_port_scan_detection(self):
        """Test port scanning detection"""
        sample_logs = [
            "Oct 15 10:31:01 server kernel: [12345.678901] SYN flood detected from 10.0.0.50",
            "Oct 15 10:31:02 server kernel: [12346.789012] Possible port scan from 10.0.0.50",
            "Oct 15 10:31:03 server kernel: [12347.890123] Multiple SYN packets from 10.0.0.50 to various ports"
        ]
        
        findings = detect_port_scans(sample_logs)
        
        assert len(findings) >= 1
        port_scan_finding = next((f for f in findings if f['ip'] == '10.0.0.50' and 'scan' in f['reason'].lower()), None)
        assert port_scan_finding is not None
        assert port_scan_finding['confidence'] >= 0.7
    
    def test_web_probing_detection(self):
        """Test web application probing detection"""
        sample_logs = [
            '203.0.113.45 - - [15/Oct/2023:10:32:15 +0000] "GET /admin HTTP/1.1" 404 162',
            '203.0.113.45 - - [15/Oct/2023:10:32:16 +0000] "GET /wp-admin HTTP/1.1" 404 162',
            '203.0.113.45 - - [15/Oct/2023:10:32:17 +0000] "GET /phpmyadmin HTTP/1.1" 404 162',
            '203.0.113.45 - - [15/Oct/2023:10:32:18 +0000] "GET /.env HTTP/1.1" 404 162'
        ]
        
        findings = detect_web_probing(sample_logs)
        
        assert len(findings) == 1
        assert findings[0]['ip'] == '203.0.113.45'
        assert 'probing' in findings[0]['reason'].lower()
        assert findings[0]['confidence'] >= 0.6
        assert findings[0]['details']['request_count'] >= 3
    
    def test_suricata_alerts_detection(self):
        """Test Suricata EVE JSON parsing"""
        suricata_alert = {
            "timestamp": "2023-10-15T10:33:45.123456+0000",
            "event_type": "alert",
            "src_ip": "198.51.100.10",
            "dest_ip": "192.168.1.10",
            "alert": {
                "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                "severity": 2
            }
        }
        
        sample_logs = [json.dumps(suricata_alert)]
        findings = detect_suricata_alerts(sample_logs)
        
        assert len(findings) == 1
        assert findings[0]['ip'] == '198.51.100.10'
        assert 'Suricata Alert' in findings[0]['reason']
        assert findings[0]['confidence'] >= 0.8
        assert findings[0]['details']['signature'] == "ET SCAN Nmap Scripting Engine User-Agent Detected"
    
    def test_comprehensive_log_analysis(self):
        """Test complete log analysis with multiple threat types"""
        comprehensive_logs = """
        Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
        Oct 15 10:30:20 server sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2
        Oct 15 10:30:25 server sshd[12347]: Failed password for user from 192.168.1.100 port 22 ssh2
        Oct 15 10:31:01 server kernel: [12345.678] SYN flood detected from 10.0.0.50
        Oct 15 10:32:15 server apache2: 203.0.113.45 - - [15/Oct/2023:10:32:15 +0000] "GET /admin HTTP/1.1" 404 162
        Oct 15 10:32:16 server apache2: 203.0.113.45 - - [15/Oct/2023:10:32:16 +0000] "GET /wp-admin HTTP/1.1" 404 162
        Oct 15 10:32:17 server apache2: 203.0.113.45 - - [15/Oct/2023:10:32:17 +0000] "GET /phpmyadmin HTTP/1.1" 404 162
        {"timestamp":"2023-10-15T10:33:45.123456+0000","event_type":"alert","src_ip":"198.51.100.10","alert":{"signature":"ET SCAN Nmap","severity":2}}
        """
        
        findings = analyze_logs(comprehensive_logs)
        
        # Should detect multiple types of threats
        assert len(findings) >= 3
        
        # Check for different IP addresses (multiple threats)
        ips_found = {finding['ip'] for finding in findings}
        assert len(ips_found) >= 3
        
        # Check for different attack types
        attack_types = {finding['details'].get('attack_type', 'unknown') for finding in findings}
        assert len(attack_types) >= 3
    
    def test_ml_enrichment(self):
        """Test ML enrichment functionality"""
        sample_finding = {
            'ip': '192.168.1.100',
            'reason': 'Multiple failed login attempts',
            'confidence': 0.7,
            'details': {'attack_type': 'brute_force_login'}
        }
        
        enriched = ml_enrich(sample_finding)
        
        # Should contain original data
        assert enriched['ip'] == sample_finding['ip']
        assert enriched['reason'] == sample_finding['reason']
        
        # Should have ML insights
        assert 'ml_insights' in enriched
        assert 'explanation' in enriched['ml_insights']
        assert 'threat_level' in enriched['ml_insights']
        assert 'geolocation' in enriched['ml_insights']
        
        # Confidence should be adjusted
        assert enriched['confidence'] >= sample_finding['confidence']
    
    def test_mock_ml_enrichment(self):
        """Test mock ML enrichment generation"""
        sample_finding = {
            'ip': '203.0.113.1',
            'reason': 'Port scanning activity detected',
            'confidence': 0.8
        }
        
        mock_result = generate_mock_ml_enrichment(sample_finding)
        
        assert 'confidence' in mock_result
        assert 'ml_insights' in mock_result
        assert mock_result['confidence'] >= sample_finding['confidence']
        assert mock_result['ml_insights']['geolocation']['country'] is not None
    
    def test_honeypot_feed_parsing(self):
        """Test honeypot feed data parsing"""
        feed_data = {
            'ips': [
                {
                    'ip': '172.16.0.100',
                    'attacks': ['ssh_bruteforce', 'command_execution'],
                    'severity': 'high',
                    'confidence': 0.95
                },
                {
                    'ip': '203.0.113.200',
                    'attacks': ['web_scanning'],
                    'severity': 'medium',
                    'confidence': 0.85
                }
            ]
        }
        
        alerts = parse_honeypot_feed(feed_data)
        
        assert len(alerts) == 2
        assert alerts[0]['ip'] == '172.16.0.100'
        assert alerts[0]['confidence'] == 0.9  # High confidence for honeypot hits
        assert alerts[0]['details']['attack_type'] == 'honeypot_interaction'
    
    def test_empty_logs(self):
        """Test handling of empty log data"""
        empty_findings = analyze_logs("")
        assert len(empty_findings) == 0
        
        none_findings = analyze_logs(None)
        assert len(none_findings) == 0
        
        whitespace_findings = analyze_logs("   \n  \t  ")
        assert len(whitespace_findings) == 0
    
    def test_malformed_logs(self):
        """Test handling of malformed log data"""
        malformed_logs = """
        This is not a proper log format
        Neither is this line
        Oct 15 10:30:15 server sshd[12345]: Failed password for root from INVALID_IP port 22 ssh2
        {"invalid_json": unclosed string
        """
        
        # Should not crash and should handle gracefully
        findings = analyze_logs(malformed_logs)
        
        # May or may not find anything, but should not raise exceptions
        assert isinstance(findings, list)
    
    def test_high_volume_logs(self):
        """Test performance with high volume of log entries"""
        # Generate a large number of log entries
        large_log_set = []
        for i in range(1000):
            large_log_set.append(
                f"Oct 15 10:30:{i%60:02d} server sshd[{12345+i}]: Failed password for root from 192.168.1.{i%255} port 22 ssh2"
            )
        
        large_logs = "\n".join(large_log_set)
        
        # Should complete in reasonable time
        import time
        start_time = time.time()
        findings = analyze_logs(large_logs)
        elapsed_time = time.time() - start_time
        
        # Should complete within 10 seconds for 1000 entries
        assert elapsed_time < 10.0
        
        # Should find multiple unique IPs
        unique_ips = {finding['ip'] for finding in findings}
        assert len(unique_ips) > 10


class TestSecurityValidation:
    """Test security-related validation and edge cases"""
    
    def test_ip_validation_in_findings(self):
        """Test that all findings contain valid IP addresses"""
        sample_logs = """
        Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
        Oct 15 10:30:16 server sshd[12346]: Failed password for root from 10.0.0.1 port 22 ssh2
        Oct 15 10:30:17 server sshd[12347]: Failed password for root from 172.16.0.1 port 22 ssh2
        """
        
        findings = analyze_logs(sample_logs)
        
        for finding in findings:
            ip = finding['ip']
            # Basic IP format validation
            parts = ip.split('.')
            assert len(parts) == 4
            for part in parts:
                assert 0 <= int(part) <= 255
    
    def test_confidence_score_validation(self):
        """Test that confidence scores are within valid range"""
        sample_logs = """
        Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
        Oct 15 10:31:01 server kernel: [12345.678] SYN flood detected from 10.0.0.50
        """
        
        findings = analyze_logs(sample_logs)
        
        for finding in findings:
            confidence = finding['confidence']
            assert 0.0 <= confidence <= 1.0
    
    def test_sql_injection_patterns(self):
        """Test detection of SQL injection attempts in web logs"""
        sql_injection_logs = [
            '198.51.100.77 - - [15/Oct/2023:10:37:00 +0000] "GET /?id=1\' UNION SELECT null,username,password FROM users-- HTTP/1.1" 400 226',
            '198.51.100.77 - - [15/Oct/2023:10:37:01 +0000] "GET /?id=1\' AND 1=1-- HTTP/1.1" 400 226',
            '198.51.100.77 - - [15/Oct/2023:10:37:02 +0000] "GET /?id=1\' OR 1=1-- HTTP/1.1" 400 226'
        ]
        
        findings = detect_web_probing(sql_injection_logs)
        
        # Should detect SQL injection patterns
        assert len(findings) >= 1
        sql_finding = findings[0]
        assert sql_finding['ip'] == '198.51.100.77'
        assert sql_finding['confidence'] >= 0.6


if __name__ == '__main__':
    pytest.main([__file__, '-v'])