#!/usr/bin/env python3
"""
Add sample data to SecuAI database for testing
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, Alert, Block, Whitelist
from datetime import datetime, timedelta
import random

def add_sample_data():
    """Add sample alerts, blocks, and whitelist entries"""
    
    with app.app_context():
        print("Adding sample data to SecuAI database...")
        
        # Sample IPs for testing
        suspicious_ips = [
            '203.0.113.10',
            '198.51.100.25', 
            '192.0.2.100',
            '104.244.42.129',
            '185.220.101.50'
        ]
        
        trusted_ips = [
            '192.168.1.0/24',
            '10.0.0.1',
            '172.16.1.10'
        ]
        
        # Add sample alerts
        print("Creating sample security alerts...")
        for i, ip in enumerate(suspicious_ips):
            confidence = random.uniform(0.6, 0.95)
            reasons = [
                'SSH brute force attack detected',
                'Multiple failed login attempts',
                'Suspicious port scanning activity',
                'Malware communication detected',
                'DDoS attack pattern identified'
            ]
            
            alert = Alert(
                ip=ip,
                reason=random.choice(reasons),
                confidence=confidence,
                source='auth.log',
                created_at=datetime.utcnow() - timedelta(hours=random.randint(1, 24))
            )
            db.session.add(alert)
        
        # Add some blocked IPs
        print("Creating sample IP blocks...")
        for i, ip in enumerate(suspicious_ips[:3]):  # Block first 3 IPs
            block = Block(
                ip=ip,
                reason=f'Blocked due to suspicious activity - Alert #{i+1}',
                is_active=True,
                applied=False,  # Simulation mode
                created_at=datetime.utcnow() - timedelta(hours=random.randint(1, 12))
            )
            db.session.add(block)
        
        # Add whitelist entries  
        print("Creating sample whitelist entries...")
        descriptions = [
            'Office network range',
            'Main server',
            'Admin workstation'
        ]
        
        for ip, desc in zip(trusted_ips, descriptions):
            whitelist = Whitelist(
                ip=ip,
                description=desc,
                is_active=True,
                created_at=datetime.utcnow() - timedelta(days=random.randint(1, 30))
            )
            db.session.add(whitelist)
        
        # Commit all changes
        db.session.commit()
        
        print(f"✅ Added {len(suspicious_ips)} sample alerts")
        print(f"✅ Added 3 sample IP blocks")  
        print(f"✅ Added {len(trusted_ips)} sample whitelist entries")
        print("\nSample data added successfully!")

if __name__ == '__main__':
    add_sample_data()