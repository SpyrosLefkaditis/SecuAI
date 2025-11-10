#!/usr/bin/env python3
"""
Generate fresh security alerts for demo
"""

import os
import sys
import random
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, Alert

# Sample attack scenarios
attack_scenarios = [
    {
        'ip': '192.168.1.100',
        'reason': 'SQL Injection from 192.168.1.100 targeting /admin/login.php',
        'confidence': 0.92,
        'source': 'nginx_access',
        'details': str({
            'raw_log': '192.168.1.100 - - [10/Nov/2025:12:00:00 +0200] "POST /admin/login.php HTTP/1.1" 200',
            'attack_summary': {
                'ip': '192.168.1.100',
                'attack_type': 'SQL Injection',
                'target_url': '/admin/login.php',
                'method': 'POST',
                'status_code': '200',
                'user_agent': 'sqlmap/1.6.0',
                'total_attempts': 8
            }
        })
    },
    {
        'ip': '10.0.0.50',
        'reason': 'Brute Force from 10.0.0.50 targeting SSH service',
        'confidence': 0.88,
        'source': 'auth',
        'details': str({
            'raw_log': 'Failed password for admin from 10.0.0.50 port 22 ssh2',
            'attack_summary': {
                'ip': '10.0.0.50',
                'attack_type': 'SSH Brute Force',
                'target_url': None,
                'method': 'SSH',
                'status_code': None,
                'user_agent': None,
                'total_attempts': 15
            }
        })
    },
    {
        'ip': '172.16.0.25',
        'reason': 'Directory Traversal from 172.16.0.25 targeting /../../etc/passwd',
        'confidence': 0.95,
        'source': 'nginx_access',
        'details': str({
            'raw_log': '172.16.0.25 - - [10/Nov/2025:12:05:00 +0200] "GET /../../etc/passwd HTTP/1.1" 404',
            'attack_summary': {
                'ip': '172.16.0.25',
                'attack_type': 'Directory Traversal',
                'target_url': '/../../etc/passwd',
                'method': 'GET',
                'status_code': '404',
                'user_agent': 'curl/7.68.0',
                'total_attempts': 3
            }
        })
    },
    {
        'ip': '192.168.2.75',
        'reason': 'XSS Attempt from 192.168.2.75 targeting /search',
        'confidence': 0.78,
        'source': 'nginx_access',
        'details': str({
            'raw_log': '192.168.2.75 - - [10/Nov/2025:12:10:00 +0200] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200',
            'attack_summary': {
                'ip': '192.168.2.75',
                'attack_type': 'XSS Attempt',
                'target_url': '/search?q=<script>alert(1)</script>',
                'method': 'GET',
                'status_code': '200',
                'user_agent': 'Mozilla/5.0',
                'total_attempts': 2
            }
        })
    },
    {
        'ip': '10.10.10.100',
        'reason': 'Admin Panel Probing from 10.10.10.100 targeting /wp-admin',
        'confidence': 0.85,
        'source': 'nginx_access',
        'details': str({
            'raw_log': '10.10.10.100 - - [10/Nov/2025:12:15:00 +0200] "GET /wp-admin/ HTTP/1.1" 404',
            'attack_summary': {
                'ip': '10.10.10.100',
                'attack_type': 'Admin Panel Probing',
                'target_url': '/wp-admin/',
                'method': 'GET',
                'status_code': '404',
                'user_agent': 'WPScan',
                'total_attempts': 5
            }
        })
    },
    {
        'ip': '192.168.5.200',
        'reason': 'Automated Scanning from 192.168.5.200 targeting multiple endpoints',
        'confidence': 0.90,
        'source': 'nginx_access',
        'details': str({
            'raw_log': '192.168.5.200 - - [10/Nov/2025:12:20:00 +0200] "GET /.env HTTP/1.1" 404',
            'attack_summary': {
                'ip': '192.168.5.200',
                'attack_type': 'Automated Scanning',
                'target_url': '/.env',
                'method': 'GET',
                'status_code': '404',
                'user_agent': 'Nikto/2.1.6',
                'total_attempts': 12
            }
        })
    },
    {
        'ip': '172.30.1.50',
        'reason': 'File Discovery from 172.30.1.50 targeting backup files',
        'confidence': 0.82,
        'source': 'nginx_access',
        'details': str({
            'raw_log': '172.30.1.50 - - [10/Nov/2025:12:25:00 +0200] "GET /backup.sql HTTP/1.1" 404',
            'attack_summary': {
                'ip': '172.30.1.50',
                'attack_type': 'File Discovery',
                'target_url': '/backup.sql',
                'method': 'GET',
                'status_code': '404',
                'user_agent': 'DirBuster',
                'total_attempts': 7
            }
        })
    },
    {
        'ip': '10.20.30.40',
        'reason': 'Command Injection from 10.20.30.40 targeting API endpoint',
        'confidence': 0.94,
        'source': 'nginx_access',
        'details': str({
            'raw_log': '10.20.30.40 - - [10/Nov/2025:12:30:00 +0200] "POST /api/exec HTTP/1.1" 500',
            'attack_summary': {
                'ip': '10.20.30.40',
                'attack_type': 'Command Injection',
                'target_url': '/api/exec',
                'method': 'POST',
                'status_code': '500',
                'user_agent': 'python-requests/2.28.0',
                'total_attempts': 4
            }
        })
    }
]

def generate_alerts(count=8):
    """Generate fresh security alerts"""
    print(f"🔥 Generating {count} fresh security alerts...")
    
    with app.app_context():
        created_count = 0
        
        # Select random scenarios
        scenarios = random.sample(attack_scenarios, min(count, len(attack_scenarios)))
        
        for scenario in scenarios:
            # Create alert with current timestamp
            alert = Alert(
                ip=scenario['ip'],
                reason=scenario['reason'],
                confidence=scenario['confidence'],
                source=scenario['source'],
                details=scenario['details'],
                created_at=datetime.utcnow() - timedelta(minutes=random.randint(0, 30))
            )
            
            db.session.add(alert)
            created_count += 1
            print(f"✅ Created alert: {scenario['reason'][:60]}...")
        
        db.session.commit()
        print(f"\n🎉 Successfully created {created_count} fresh alerts!")
        print(f"💡 These alerts are from the last 30 minutes and will show up in your dashboard.")

if __name__ == '__main__':
    generate_alerts(8)
