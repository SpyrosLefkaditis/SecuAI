#!/usr/bin/env python3
"""
Test script to generate sample security alerts for AI analysis testing
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, Alert
from datetime import datetime
import json

def create_test_alerts():
    """Create sample security alerts for testing AI analysis"""
    
    test_alerts = [
        {
            'ip': '192.168.1.100',
            'reason': 'SQL Injection from 192.168.1.100 targeting /admin/login.php',
            'confidence': 0.9,
            'source': 'nginx_access',
            'details': json.dumps({
                'raw_log': '192.168.1.100 - - [09/Nov/2025:15:30:00 +0000] "GET /admin/login.php?id=1\' OR 1=1-- HTTP/1.1" 200 1234 "-" "sqlmap/1.6"',
                'attack_summary': {
                    'ip': '192.168.1.100',
                    'attack_type': 'SQL Injection',
                    'target_url': '/admin/login.php',
                    'method': 'GET',
                    'status_code': '200',
                    'user_agent': 'sqlmap/1.6',
                    'total_attempts': 3
                }
            })
        },
        {
            'ip': '10.0.0.50',
            'reason': 'Admin Panel Probing from 10.0.0.50 targeting /wp-admin/',
            'confidence': 0.75,
            'source': 'nginx_access',
            'details': json.dumps({
                'raw_log': '10.0.0.50 - - [09/Nov/2025:15:25:00 +0000] "GET /wp-admin/ HTTP/1.1" 404 162 "-" "Nikto/2.1.6"',
                'attack_summary': {
                    'ip': '10.0.0.50',
                    'attack_type': 'Admin Panel Probing',
                    'target_url': '/wp-admin/',
                    'method': 'GET',
                    'status_code': '404',
                    'user_agent': 'Nikto/2.1.6',
                    'total_attempts': 5
                }
            })
        },
        {
            'ip': '172.16.0.25',
            'reason': 'SSH Brute Force from 172.16.0.25',
            'confidence': 0.85,
            'source': 'auth',
            'details': json.dumps({
                'raw_log': 'Nov  9 15:20:00 server sshd[12345]: Failed password for root from 172.16.0.25 port 22 ssh2',
                'attack_summary': {
                    'ip': '172.16.0.25',
                    'attack_type': 'SSH Brute Force',
                    'target_url': None,
                    'method': 'SSH',
                    'status_code': None,
                    'user_agent': None,
                    'total_attempts': 8
                }
            })
        },
        {
            'ip': '203.0.113.15',
            'reason': 'Directory Traversal from 203.0.113.15 targeting /../etc/passwd',
            'confidence': 0.95,
            'source': 'nginx_access',
            'details': json.dumps({
                'raw_log': '203.0.113.15 - - [09/Nov/2025:15:15:00 +0000] "GET /../etc/passwd HTTP/1.1" 404 162 "-" "curl/7.68.0"',
                'attack_summary': {
                    'ip': '203.0.113.15',
                    'attack_type': 'Directory Traversal',
                    'target_url': '/../etc/passwd',
                    'method': 'GET',
                    'status_code': '404',
                    'user_agent': 'curl/7.68.0',
                    'total_attempts': 2
                }
            })
        },
        {
            'ip': '198.51.100.30',
            'reason': 'XSS Attempt from 198.51.100.30 targeting /search',
            'confidence': 0.70,
            'source': 'nginx_access',
            'details': json.dumps({
                'raw_log': '198.51.100.30 - - [09/Nov/2025:15:10:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 500 "-" "Mozilla/5.0"',
                'attack_summary': {
                    'ip': '198.51.100.30',
                    'attack_type': 'XSS Attempt',
                    'target_url': '/search',
                    'method': 'GET',
                    'status_code': '200',
                    'user_agent': 'Mozilla/5.0',
                    'total_attempts': 1
                }
            })
        }
    ]
    
    with app.app_context():
        print("🧪 Creating test security alerts...")
        
        for alert_data in test_alerts:
            alert = Alert(
                ip=alert_data['ip'],
                reason=alert_data['reason'],
                confidence=alert_data['confidence'],
                source=alert_data['source'],
                details=alert_data['details'],
                created_at=datetime.utcnow()
            )
            
            db.session.add(alert)
            print(f"✅ Created alert: {alert_data['reason'][:50]}...")
        
        db.session.commit()
        print(f"🎯 Successfully created {len(test_alerts)} test alerts!")
        
        # Show current alert count
        total_alerts = Alert.query.count()
        print(f"📊 Total alerts in database: {total_alerts}")

if __name__ == '__main__':
    create_test_alerts()