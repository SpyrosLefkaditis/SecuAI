#!/usr/bin/env python3
"""
SecuAI Real-time Log Monitor
Continuously monitors Linux system logs for security threats
"""

import os
import sys
import time
import re
import logging
from datetime import datetime
from pathlib import Path
import threading
from typing import Dict, List, Optional

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, Alert, Block, AuditLog
from analyzer import analyze_logs
from ai_analyzer import ai_analyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('log_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class LogMonitor:
    """Real-time log monitoring for security threats"""
    
    def __init__(self):
        self.monitoring = False
        self.log_files = {
            'auth': '/var/log/auth.log',
            'syslog': '/var/log/syslog',
            'kern': '/var/log/kern.log',
            'nginx_access': '/var/log/nginx/access.log',
            'nginx_error': '/var/log/nginx/error.log',
            'apache_access': '/var/log/apache2/access.log',
            'apache_error': '/var/log/apache2/error.log',
            'test_auth': '/tmp/test_auth.log'  # Test log for simulation
        }
        
        # Threat detection patterns
        self.threat_patterns = {
            'ssh_brute_force': [
                r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
                r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)',
                r'Connection closed by (\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]'
            ],
            'sudo_failures': [
                r'sudo: pam_unix\(sudo:auth\): authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)',
                r'sudo: .* : command not allowed ; TTY=.* ; PWD=.* ; USER=root ; COMMAND=.*'
            ],
            'suspicious_logins': [
                r'Accepted publickey for .* from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2',
                r'Accepted password for .* from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2'
            ],
            'web_attacks': [
                r'(\d+\.\d+\.\d+\.\d+) .* "(?:GET|POST) .*/(?:admin|wp-admin|phpmyadmin|\.\./).*" [4-5]\d\d',
                r'(\d+\.\d+\.\d+\.\d+) .* "(?:GET|POST) .*(?:union|select|script|alert|passwd|config|backup).*" \d+',
                r'(\d+\.\d+\.\d+\.\d+) .* "(?:GET|POST) .*[<>"\'].*" \d+',
                r'(\d+\.\d+\.\d+\.\d+) .* "(?:GET|POST) .*(?:sqlmap|nikto|\.env|shell\.php).*" \d+',
                r'(\d+\.\d+\.\d+\.\d+) .* "(?:GET|POST) .*[\'"--].*" \d+'
            ],
            'port_scans': [
                r'kernel:.*TCP.*from (\d+\.\d+\.\d+\.\d+):\d+ to .*WINDOW:\d+ RES:0x00 SYN URGP:0',
                r'kernel:.*UDP.*from (\d+\.\d+\.\d+\.\d+):\d+ to'
            ],
            'ddos_patterns': [
                r'kernel:.*SYN flood on port \d+\. Sending cookies\.',
                r'(\d+\.\d+\.\d+\.\d+) .* ".*" [45]\d\d .* "-" ".*bot.*"'
            ]
        }
        
        # IP tracking for pattern analysis
        self.ip_activity = {}
        self.activity_threshold = 2  # Suspicious after 2 events from same IP (more sensitive)
        self.time_window = 300  # 5 minutes
    
    def check_file_readable(self, filepath: str) -> bool:
        """Check if log file exists and is readable"""
        try:
            if os.path.exists(filepath) and os.access(filepath, os.R_OK):
                return True
            return False
        except Exception as e:
            logger.warning(f"Cannot access {filepath}: {e}")
            return False
    
    def tail_file(self, filepath: str) -> Optional[str]:
        """Generator that yields new lines from a file (like tail -f)"""
        try:
            with open(filepath, 'r') as file:
                # Go to the end of the file
                file.seek(0, 2)
                
                while self.monitoring:
                    line = file.readline()
                    if line:
                        yield line.strip()
                    else:
                        time.sleep(0.5)  # Lightweight delay when no new lines
        except Exception as e:
            logger.error(f"Error tailing {filepath}: {e}")
            return None
    
    def extract_ip(self, line: str, pattern: str) -> Optional[str]:
        """Extract IP address from log line using regex pattern"""
        try:
            # Escape regex pattern to avoid warnings
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
            return None
        except Exception as e:
            logger.debug(f"Pattern matching error: {e}")
            return None
    
    def extract_log_details(self, line: str, log_type: str) -> dict:
        """Extract detailed information from log line"""
        details = {
            'timestamp': None,
            'method': None,
            'url': None,
            'status_code': None,
            'user_agent': None,
            'attack_type': None
        }
        
        try:
            if log_type == 'nginx_access':
                # Parse nginx access log format
                # 127.0.0.1 - - [08/Nov/2025:01:34:00 +0200] "GET /admin HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
                
                # Extract timestamp
                timestamp_match = re.search(r'\[([^\]]+)\]', line)
                if timestamp_match:
                    details['timestamp'] = timestamp_match.group(1)
                
                # Extract method and URL
                request_match = re.search(r'"(GET|POST|PUT|DELETE) ([^"]*) HTTP/[^"]*"', line)
                if request_match:
                    details['method'] = request_match.group(1)
                    details['url'] = request_match.group(2)
                
                # Extract status code
                status_match = re.search(r'" (\d{3}) \d+', line)
                if status_match:
                    details['status_code'] = status_match.group(1)
                
                # Extract user agent
                ua_match = re.search(r'"([^"]*)"$', line)
                if ua_match:
                    details['user_agent'] = ua_match.group(1)
                
                # Identify attack type based on URL and user agent
                url = details['url'] or ''
                ua = details['user_agent'] or ''
                
                if any(x in url.lower() for x in ['admin', 'wp-admin', 'phpmyadmin']):
                    details['attack_type'] = 'Admin Panel Probing'
                elif any(x in url.lower() for x in ['../', 'etc/passwd', 'config']):
                    details['attack_type'] = 'Directory Traversal'
                elif any(x in url.lower() for x in ['union', 'select', 'or 1=1']):
                    details['attack_type'] = 'SQL Injection'
                elif any(x in url.lower() for x in ['script', 'alert', 'xss']):
                    details['attack_type'] = 'XSS Attempt'
                elif any(x in ua.lower() for x in ['sqlmap', 'nikto', 'nmap']):
                    details['attack_type'] = 'Automated Scanning'
                elif '.env' in url or 'backup' in url or '.sql' in url:
                    details['attack_type'] = 'File Discovery'
                else:
                    details['attack_type'] = 'Suspicious Request'
            
            elif log_type == 'auth':
                # Parse auth.log format for SSH attempts
                if 'Failed password' in line:
                    details['attack_type'] = 'SSH Brute Force'
                elif 'Invalid user' in line:
                    details['attack_type'] = 'SSH User Enumeration'
                
                # Extract timestamp from syslog format
                timestamp_match = re.search(r'^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})', line)
                if timestamp_match:
                    details['timestamp'] = timestamp_match.group(1)
        
        except Exception as e:
            logger.debug(f"Error extracting log details: {e}")
        
        return details

    def analyze_log_line(self, line: str, log_type: str):
        """Analyze a single log line for threats"""
        try:
            current_time = datetime.utcnow()
            
            for threat_type, patterns in self.threat_patterns.items():
                for pattern in patterns:
                    ip = self.extract_ip(line, pattern)
                    if ip:
                        # Extract detailed information from the log line
                        log_details = self.extract_log_details(line, log_type)
                        
                        # Track IP activity with detailed info
                        if ip not in self.ip_activity:
                            self.ip_activity[ip] = []
                        
                        activity_entry = {
                            'timestamp': current_time,
                            'threat_type': threat_type,
                            'log_type': log_type,
                            'raw_line': line,
                            'details': log_details
                        }
                        
                        self.ip_activity[ip].append(activity_entry)
                        
                        # Clean old activity data
                        self.ip_activity[ip] = [
                            activity for activity in self.ip_activity[ip]
                            if (current_time - activity['timestamp']).seconds < self.time_window
                        ]
                        
                        # Check if IP has suspicious activity
                        if len(self.ip_activity[ip]) >= self.activity_threshold:
                            self.create_alert(ip, threat_type, log_type, line, log_details)
                        
                        # Enhanced logging with details
                        attack_info = log_details.get('attack_type', threat_type)
                        target = log_details.get('url', 'unknown target')
                        logger.info(f"🔍 Detected {attack_info} from {ip} → {target} ({log_type})")
                        break
        except Exception as e:
            logger.error(f"Error analyzing log line: {e}")
    
    def create_alert(self, ip: str, threat_type: str, log_type: str, raw_line: str, log_details: dict = None):
        """Create security alert in database with detailed information"""
        try:
            with app.app_context():
                # Check if we already have a recent alert for this IP and threat
                existing_alert = Alert.query.filter(
                    Alert.ip == ip,
                    Alert.reason.contains(threat_type),
                    Alert.created_at >= datetime.utcnow().replace(hour=datetime.utcnow().hour - 1)
                ).first()
                
                if existing_alert:
                    logger.debug(f"Recent alert already exists for {ip} - {threat_type}")
                    return
                
                # Calculate confidence based on activity frequency and attack type
                activity_count = len(self.ip_activity.get(ip, []))
                base_confidence = 0.5 + (activity_count * 0.08)
                
                # Boost confidence for dangerous attacks
                if log_details and log_details.get('attack_type'):
                    attack_type = log_details['attack_type']
                    if 'SQL Injection' in attack_type or 'Directory Traversal' in attack_type:
                        base_confidence += 0.2
                    elif 'Automated Scanning' in attack_type:
                        base_confidence += 0.15
                
                confidence = min(0.95, base_confidence)
                
                # Create detailed reason
                if log_details and log_details.get('attack_type'):
                    reason = f"{log_details['attack_type']} from {ip}"
                    if log_details.get('url'):
                        reason += f" targeting {log_details['url']}"
                else:
                    reason = f"{threat_type.replace('_', ' ').title()} detected from {ip}"
                
                # Create comprehensive details JSON
                alert_details = {
                    'raw_log': raw_line[:500],
                    'attack_summary': {
                        'ip': ip,
                        'attack_type': log_details.get('attack_type', threat_type) if log_details else threat_type,
                        'target_url': log_details.get('url') if log_details else None,
                        'method': log_details.get('method') if log_details else None,
                        'status_code': log_details.get('status_code') if log_details else None,
                        'user_agent': log_details.get('user_agent') if log_details else None,
                        'log_timestamp': log_details.get('timestamp') if log_details else None,
                        'total_attempts': activity_count
                    }
                }
                
                # Create alert data for AI analysis
                alert_data = {
                    'ip': ip,
                    'reason': reason,
                    'confidence': confidence,
                    'source': log_type,
                    'details': alert_details
                }
                
                # Get AI analysis for this threat
                try:
                    ai_analysis = ai_analyzer.analyze_threat(alert_data)
                    alert_details['ai_analysis'] = ai_analysis
                    
                    # Update confidence based on AI assessment
                    if ai_analysis.get('risk_score'):
                        ai_confidence = ai_analysis['risk_score'] / 100.0
                        # Blend original confidence with AI assessment
                        confidence = (confidence + ai_confidence) / 2.0
                        confidence = min(0.98, confidence)  # Cap at 98%
                    
                    logger.info(f"🤖 AI Analysis: {ai_analysis.get('severity_level', 'Unknown')} threat - {ai_analysis.get('explanation', 'No details')[:100]}...")
                    
                except Exception as e:
                    logger.warning(f"AI analysis failed for {ip}: {e}")
                    alert_details['ai_analysis'] = {'error': str(e), 'fallback': True}
                
                # Create new alert with AI enhancement
                alert = Alert(
                    ip=ip,
                    reason=reason,
                    confidence=confidence,
                    source=log_type,
                    details=str(alert_details),  # Store as JSON string with AI analysis
                    created_at=datetime.utcnow()
                )
                
                db.session.add(alert)
                db.session.commit()
                
                # Enhanced alert logging
                attack_summary = f"{log_details.get('attack_type', threat_type)} from {ip}"
                if log_details and log_details.get('url'):
                    attack_summary += f" → {log_details['url']}"
                
                logger.warning(f"🚨 ALERT CREATED: {attack_summary} (confidence: {confidence:.1%}, attempts: {activity_count})")
                
                # Auto-block high confidence threats
                if confidence >= 0.8:
                    block_reason = f"Auto-blocked: {log_details.get('attack_type', threat_type)} (confidence: {confidence:.1%})"
                    self.auto_block_ip(ip, block_reason)
                
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
    
    def auto_block_ip(self, ip: str, reason: str):
        """Automatically block high-threat IPs"""
        try:
            with app.app_context():
                existing_block = Block.query.filter_by(ip=ip, is_active=True).first()
                if existing_block:
                    logger.debug(f"IP {ip} already blocked")
                    return
                
                # Get recent activity for this IP for block details
                recent_activity = self.ip_activity.get(ip, [])
                attack_types = list(set([activity['details'].get('attack_type', 'Unknown') 
                                       for activity in recent_activity 
                                       if activity.get('details')]))
                
                block_details = {
                    'auto_blocked': True,
                    'block_reason': reason,
                    'attack_types': attack_types,
                    'total_attempts': len(recent_activity),
                    'blocked_at': datetime.utcnow().isoformat()
                }
                
                block = Block(
                    ip=ip,
                    reason=reason,
                    details=str(block_details),
                    is_active=True,
                    applied=False,  # Simulation mode
                    created_at=datetime.utcnow()
                )
                
                db.session.add(block)
                db.session.commit()
                
                logger.critical(f"🔒 AUTO-BLOCKED: {ip} - {reason} (attack types: {', '.join(attack_types)})")
                
        except Exception as e:
            logger.error(f"Error auto-blocking IP {ip}: {e}")
    
    def monitor_log_file(self, log_type: str, filepath: str):
        """Monitor a specific log file"""
        logger.info(f"Starting monitor for {log_type}: {filepath}")
        
        if not self.check_file_readable(filepath):
            logger.warning(f"Cannot read {filepath}, skipping {log_type} monitoring")
            return
        
        try:
            for line in self.tail_file(filepath):
                if not self.monitoring:
                    break
                self.analyze_log_line(line, log_type)
        except Exception as e:
            logger.error(f"Error monitoring {log_type}: {e}")
    
    def start_monitoring(self):
        """Start monitoring all available log files"""
        logger.info("🚀 Starting SecuAI Log Monitor...")
        self.monitoring = True
        
        # Create database tables if they don't exist
        with app.app_context():
            db.create_all()
        
        threads = []
        
        # Start monitoring threads for each log file
        for log_type, filepath in self.log_files.items():
            if self.check_file_readable(filepath):
                thread = threading.Thread(
                    target=self.monitor_log_file,
                    args=(log_type, filepath),
                    daemon=True
                )
                thread.start()
                threads.append(thread)
                logger.info(f"✅ Started monitoring {log_type}")
            else:
                logger.warning(f"❌ Cannot monitor {log_type} - file not accessible")
        
        if not threads:
            logger.error("❌ No log files available for monitoring!")
            return
        
        logger.info(f"🔍 Monitoring {len(threads)} log files for security threats...")
        
        try:
            # Keep main thread alive with lightweight monitoring
            while self.monitoring:
                time.sleep(2)  # Reduced frequency for lower CPU usage
        except KeyboardInterrupt:
            logger.info("🛑 Received interrupt signal, stopping monitor...")
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop log monitoring"""
        logger.info("⏹️ Stopping log monitor...")
        self.monitoring = False
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        return {
            'monitoring_active': self.monitoring,
            'tracked_ips': len(self.ip_activity),
            'log_files_monitored': len([f for f in self.log_files.values() if self.check_file_readable(f)])
        }

def main():
    """Main function to run the log monitor"""
    monitor = LogMonitor()
    
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down log monitor...")
        monitor.stop_monitoring()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()