#!/usr/bin/env python3
"""
SecuAI Database Initialization Script
Creates tables and seeds initial data including admin user
"""

import os
import json
from datetime import datetime
from app import app
from models import db, User, Alert, Whitelist, AuditLog
from analyzer import analyze_logs
from decouple import config

# Default admin credentials - CHANGE THESE IMMEDIATELY IN PRODUCTION!
DEFAULT_ADMIN_EMAIL = config('ADMIN_EMAIL', default='admin@secai.local')
DEFAULT_ADMIN_PASSWORD = config('ADMIN_PASSWORD', default='ChangeMe123!')

def init_database():
    """Initialize database with tables and seed data"""
    print("🔧 Initializing SecuAI database...")
    
    with app.app_context():
        try:
            # Drop all tables if they exist (for fresh start)
            print("📋 Dropping existing tables...")
            db.drop_all()
            
            # Create all tables
            print("📋 Creating database tables...")
            db.create_all()
            
            # Seed admin user
            print("👤 Creating admin user...")
            create_admin_user()
            
            # Seed sample data
            print("📊 Seeding sample data...")
            seed_sample_data()
            
            # Seed whitelist entries
            print("🔐 Creating whitelist entries...")
            seed_whitelist()
            
            print("✅ Database initialization complete!")
            print(f"🚨 SECURITY WARNING: Default admin credentials are:")
            print(f"   Email: {DEFAULT_ADMIN_EMAIL}")
            print(f"   Password: {DEFAULT_ADMIN_PASSWORD}")
            print(f"🚨 CHANGE THESE CREDENTIALS IMMEDIATELY!")
            
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            raise


def create_admin_user():
    """Create default admin user"""
    try:
        # Check if admin user already exists
        existing_admin = User.query.filter_by(email=DEFAULT_ADMIN_EMAIL).first()
        if existing_admin:
            print(f"⚠️  Admin user {DEFAULT_ADMIN_EMAIL} already exists, skipping...")
            return
        
        # Create new admin user
        admin_user = User(
            email=DEFAULT_ADMIN_EMAIL,
            is_admin=True,
            is_active=True
        )
        admin_user.set_password(DEFAULT_ADMIN_PASSWORD)
        
        db.session.add(admin_user)
        db.session.commit()
        
        # Log admin creation
        audit_log = AuditLog(
            action='admin_user_created',
            details=f'Initial admin user created: {DEFAULT_ADMIN_EMAIL}',
            user_id=admin_user.id
        )
        db.session.add(audit_log)
        db.session.commit()
        
        print(f"✅ Admin user created: {DEFAULT_ADMIN_EMAIL}")
        
    except Exception as e:
        print(f"❌ Failed to create admin user: {e}")
        db.session.rollback()
        raise


def seed_sample_data():
    """Seed database with sample alerts from log analysis"""
    try:
        # Load sample log file if it exists
        sample_log_path = 'sample_auth.log'
        if os.path.exists(sample_log_path):
            print(f"📄 Analyzing sample log file: {sample_log_path}")
            
            with open(sample_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample_logs = f.read()
            
            # Analyze sample logs
            findings = analyze_logs(sample_logs)
            
            # Create alerts from findings
            for finding in findings:
                alert = Alert(
                    ip=finding['ip'],
                    reason=finding['reason'],
                    confidence=finding.get('confidence', 0.5),
                    details=json.dumps(finding.get('details', {})),
                    source='sample_data'
                )
                db.session.add(alert)
            
            print(f"✅ Created {len(findings)} sample alerts from log analysis")
            
        else:
            print("⚠️  No sample log file found, creating mock alerts...")
            create_mock_alerts()
        
        db.session.commit()
        
    except Exception as e:
        print(f"❌ Failed to seed sample data: {e}")
        db.session.rollback()
        raise


def create_mock_alerts():
    """Create mock security alerts for demonstration"""
    mock_alerts = [
        {
            'ip': '192.168.1.100',
            'reason': 'Multiple failed login attempts (5 attempts)',
            'confidence': 0.8,
            'details': {
                'attack_type': 'brute_force_login',
                'attempt_count': 5,
                'detection_rule': 'failed_login_detection'
            }
        },
        {
            'ip': '10.0.0.50',
            'reason': 'Port scanning activity detected (3 indicators)',
            'confidence': 0.9,
            'details': {
                'attack_type': 'port_scan',
                'indicator_count': 3,
                'detection_rule': 'port_scan_detection'
            }
        },
        {
            'ip': '203.0.113.45',
            'reason': 'Web application probing (7 suspicious requests)',
            'confidence': 0.75,
            'details': {
                'attack_type': 'web_probing',
                'request_count': 7,
                'suspicious_patterns': ['/admin', '/wp-admin', '/.env'],
                'detection_rule': 'web_probing_detection'
            }
        },
        {
            'ip': '198.51.100.10',
            'reason': 'Suricata Alert: ET SCAN Nmap Scripting Engine',
            'confidence': 0.95,
            'details': {
                'attack_type': 'ids_alert',
                'signature': 'ET SCAN Nmap Scripting Engine',
                'severity': 2,
                'detection_rule': 'suricata_eve_parsing'
            }
        },
        {
            'ip': '172.16.0.100',
            'reason': 'Honeypot interaction detected',
            'confidence': 0.9,
            'details': {
                'attack_type': 'honeypot_interaction',
                'honeypot_data': {'port': 22, 'service': 'ssh'},
                'detection_rule': 'honeypot_feed'
            }
        }
    ]
    
    for mock_alert in mock_alerts:
        alert = Alert(
            ip=mock_alert['ip'],
            reason=mock_alert['reason'],
            confidence=mock_alert['confidence'],
            details=json.dumps(mock_alert['details']),
            source='mock_data'
        )
        db.session.add(alert)
    
    print(f"✅ Created {len(mock_alerts)} mock alerts")


def seed_whitelist():
    """Create initial whitelist entries for safe IPs"""
    whitelist_entries = [
        {
            'ip': '127.0.0.0/8',
            'description': 'Localhost loopback addresses'
        },
        {
            'ip': '10.0.0.1',
            'description': 'Internal network gateway'
        },
        {
            'ip': '192.168.1.1',
            'description': 'Local router/gateway'
        },
        {
            'ip': '::1',
            'description': 'IPv6 localhost'
        }
    ]
    
    admin_user = User.query.filter_by(email=DEFAULT_ADMIN_EMAIL).first()
    
    for entry in whitelist_entries:
        whitelist_item = Whitelist(
            ip=entry['ip'],
            description=entry['description'],
            is_active=True,
            created_by=admin_user.id if admin_user else None
        )
        db.session.add(whitelist_item)
    
    db.session.commit()
    print(f"✅ Created {len(whitelist_entries)} whitelist entries")


def create_sample_log_file():
    """Create a sample auth.log file for testing"""
    sample_log_content = """Oct 15 10:30:15 server1 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Oct 15 10:30:20 server1 sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2
Oct 15 10:30:25 server1 sshd[12347]: Failed password for user from 192.168.1.100 port 22 ssh2
Oct 15 10:30:30 server1 sshd[12348]: Failed password for test from 192.168.1.100 port 22 ssh2
Oct 15 10:30:35 server1 sshd[12349]: Failed password for guest from 192.168.1.100 port 22 ssh2
Oct 15 10:31:01 server1 kernel: [12345.678] SYN flood detected from 10.0.0.50
Oct 15 10:31:02 server1 kernel: [12346.789] Port scan detected from 10.0.0.50
Oct 15 10:31:03 server1 kernel: [12347.890] Multiple SYN packets from 10.0.0.50
Oct 15 10:32:15 server1 apache2: 203.0.113.45 - - [15/Oct/2023:10:32:15 +0000] "GET /admin HTTP/1.1" 404 162
Oct 15 10:32:16 server1 apache2: 203.0.113.45 - - [15/Oct/2023:10:32:16 +0000] "GET /wp-admin HTTP/1.1" 404 162
Oct 15 10:32:17 server1 apache2: 203.0.113.45 - - [15/Oct/2023:10:32:17 +0000] "GET /administrator HTTP/1.1" 404 162
Oct 15 10:32:18 server1 apache2: 203.0.113.45 - - [15/Oct/2023:10:32:18 +0000] "GET /phpmyadmin HTTP/1.1" 404 162
Oct 15 10:32:19 server1 apache2: 203.0.113.45 - - [15/Oct/2023:10:32:19 +0000] "GET /.env HTTP/1.1" 404 162
Oct 15 10:32:20 server1 apache2: 203.0.113.45 - - [15/Oct/2023:10:32:20 +0000] "GET /config.php HTTP/1.1" 404 162
Oct 15 10:32:21 server1 apache2: 203.0.113.45 - - [15/Oct/2023:10:32:21 +0000] "GET /backup HTTP/1.1" 404 162
Oct 15 10:33:45 server1 suricata: {"timestamp":"2023-10-15T10:33:45.123456+0000","flow_id":123456789,"event_type":"alert","src_ip":"198.51.100.10","src_port":54321,"dest_ip":"192.168.1.10","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":20,"signature":"ET SCAN Nmap Scripting Engine User-Agent Detected","category":"Attempted Information Leak","severity":2}}
Oct 15 10:34:00 server1 honeypot: Connection from 172.16.0.100 to SSH honeypot on port 2222
Oct 15 10:34:01 server1 honeypot: Login attempt: root/password from 172.16.0.100
Oct 15 10:34:02 server1 honeypot: Command executed by 172.16.0.100: whoami
Oct 15 10:35:15 server1 sshd[12350]: Invalid user hacker from 198.51.100.20 port 22 ssh2
Oct 15 10:35:20 server1 sshd[12351]: Failed password for invalid user hacker from 198.51.100.20 port 22 ssh2
Oct 15 10:35:25 server1 sshd[12352]: Connection closed by 198.51.100.20 port 22 [preauth]
Oct 15 10:36:10 server1 kernel: [12400.123] Possible SYN flooding on port 80. Sending cookies.
Oct 15 10:36:11 server1 kernel: [12401.234] TCP: drop open request from 203.0.113.99/1234
Oct 15 10:36:12 server1 kernel: [12402.345] TCP: drop open request from 203.0.113.99/1235
Oct 15 10:36:13 server1 kernel: [12403.456] TCP: drop open request from 203.0.113.99/1236
"""
    
    try:
        with open('sample_auth.log', 'w') as f:
            f.write(sample_log_content)
        print("✅ Created sample_auth.log file")
    except Exception as e:
        print(f"⚠️  Could not create sample log file: {e}")


def create_honeypot_feed():
    """Create a sample honeypot feed JSON file"""
    honeypot_data = {
        "feed_name": "SecuAI Demo Honeypot",
        "last_updated": datetime.utcnow().isoformat(),
        "ips": [
            {
                "ip": "172.16.0.100",
                "first_seen": "2023-10-15T10:34:00Z",
                "last_seen": "2023-10-15T10:34:30Z",
                "attacks": ["ssh_bruteforce", "command_execution"],
                "severity": "high",
                "country": "Unknown",
                "asn": "AS12345"
            },
            {
                "ip": "203.0.113.200",
                "first_seen": "2023-10-15T09:15:00Z",
                "last_seen": "2023-10-15T09:45:00Z",
                "attacks": ["web_scanning", "sql_injection_attempt"],
                "severity": "medium",
                "country": "RU",
                "asn": "AS54321"
            },
            {
                "ip": "198.51.100.150",
                "first_seen": "2023-10-15T08:30:00Z",
                "last_seen": "2023-10-15T11:00:00Z",
                "attacks": ["port_scan", "service_enumeration"],
                "severity": "high",
                "country": "CN",
                "asn": "AS9999"
            }
        ]
    }
    
    try:
        with open('honeypot_feed.json', 'w') as f:
            json.dump(honeypot_data, f, indent=2)
        print("✅ Created honeypot_feed.json file")
    except Exception as e:
        print(f"⚠️  Could not create honeypot feed file: {e}")


if __name__ == '__main__':
    print("🚀 SecuAI Database Initialization")
    print("=" * 50)
    
    # Create sample files first
    create_sample_log_file()
    create_honeypot_feed()
    
    # Initialize database
    init_database()
    
    print("\n🎉 Setup complete! You can now start the SecuAI application.")
    print("\n🔧 Next steps:")
    print("1. Start the application: python app.py")
    print("2. Open http://localhost:5000 in your browser")
    print("3. Login with admin credentials to access admin panel")
    print("4. Upload log files or use the API to analyze security data")
    print(f"\n🚨 Remember to change the admin password from '{DEFAULT_ADMIN_PASSWORD}'!")