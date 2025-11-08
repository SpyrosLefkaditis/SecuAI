#!/usr/bin/env python3
"""
SecuAI Threat Simulation Script
Generates realistic security events for testing log monitoring
"""

import subprocess
import time
import random
import threading
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatSimulator:
    """Simulate various security threats for testing"""
    
    def __init__(self):
        self.running = False
        self.target_host = "127.0.0.1"  # Target localhost for safety
        
    def simulate_failed_ssh_attempts(self):
        """Simulate SSH brute force attempts"""
        logger.info("🔥 Starting SSH brute force simulation...")
        
        # Simulate failed SSH attempts in auth.log
        fake_ips = [
            "203.0.113.10", "198.51.100.25", "192.0.2.100",
            "104.244.42.129", "185.220.101.50"
        ]
        
        users = ["root", "admin", "user", "test", "guest", "ubuntu"]
        
        for i in range(10):
            if not self.running:
                break
                
            ip = random.choice(fake_ips)
            user = random.choice(users)
            timestamp = datetime.now().strftime("%b %d %H:%M:%S")
            
            # Create fake auth.log entry
            log_entry = f"{timestamp} pop-os sshd[{random.randint(10000, 99999)}]: Failed password for {user} from {ip} port 22 ssh2"
            
            # Write to a test log file that we can monitor
            with open('/tmp/test_auth.log', 'a') as f:
                f.write(log_entry + '\n')
            
            logger.info(f"Simulated failed SSH from {ip} for user {user}")
            time.sleep(random.uniform(1, 3))
    
    def simulate_web_attacks(self):
        """Simulate web attacks against nginx"""
        logger.info("🌐 Starting web attack simulation...")
        
        attack_urls = [
            "/admin",
            "/wp-admin/admin.php", 
            "/phpmyadmin/index.php",
            "/../../etc/passwd",
            "/index.php?id=1' OR '1'='1",
            "/search?q=<script>alert('xss')</script>",
            "/login.php?user=admin'--",
            "/backup.zip",
            "/.env",
            "/config.php",
            "/xmlrpc.php",
            "/wp-config.php",
            "/database.sql",
            "/shell.php",
            "/admin/login.php"
        ]
        
        user_agents = [
            "sqlmap/1.0",
            "Nikto/2.1.6", 
            "Mozilla/5.0 (compatible; Baiduspider/2.0)",
            "python-requests/2.25.1",
            "<script>alert('xss')</script>",
            "()$; union select 1,2,3--",
            "../../../../../../../../../../etc/passwd"
        ]
        
        # Generate attacks from different source IPs
        source_ips = ["203.0.113.10", "198.51.100.25", "192.0.2.100"]
        
        for i in range(20):  # More attacks
            if not self.running:
                break
                
            url = random.choice(attack_urls)
            user_agent = random.choice(user_agents)
            source_ip = random.choice(source_ips)
            
            try:
                # Make actual HTTP requests to generate real nginx logs
                cmd = [
                    'curl', '-s', '-A', user_agent,
                    f'http://localhost:80{url}',  # Explicitly specify port 80
                    '--connect-timeout', '3',
                    '--max-time', '5'
                ]
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                
                logger.info(f"Simulated web attack: {url} with UA: {user_agent[:30]}...")
                
                # Also try with different HTTP methods
                if i % 3 == 0:
                    cmd_post = [
                        'curl', '-s', '-X', 'POST', '-A', user_agent,
                        f'http://localhost:80{url}',
                        '-d', 'user=admin&pass=admin123',
                        '--connect-timeout', '3'
                    ]
                    subprocess.run(cmd_post, capture_output=True, timeout=5)
                    logger.info(f"Simulated POST attack: {url}")
                
                time.sleep(random.uniform(0.2, 1.5))
                
            except Exception as e:
                logger.debug(f"Web attack simulation error: {e}")
    
    def simulate_port_scan(self):
        """Simulate port scanning activity"""
        logger.info("🔍 Starting port scan simulation...")
        
        target_ports = [22, 80, 443, 3306, 5432, 21, 23, 25, 53, 110]
        
        for port in random.sample(target_ports, 5):
            if not self.running:
                break
                
            try:
                # Use nmap for port scanning
                cmd = ['nmap', '-p', str(port), '--max-retries', '1', '--host-timeout', '2s', self.target_host]
                subprocess.run(cmd, capture_output=True, timeout=10)
                
                logger.info(f"Simulated port scan on port {port}")
                time.sleep(random.uniform(0.2, 1))
                
            except Exception as e:
                logger.debug(f"Port scan simulation error: {e}")
    
    def simulate_sudo_abuse(self):
        """Simulate suspicious sudo attempts"""
        logger.info("🔐 Starting sudo abuse simulation...")
        
        for i in range(5):
            if not self.running:
                break
                
            timestamp = datetime.now().strftime("%b %d %H:%M:%S")
            fake_ip = f"192.168.1.{random.randint(100, 200)}"
            
            # Create fake sudo failure log entry
            log_entry = f"{timestamp} pop-os sudo: pam_unix(sudo:auth): authentication failure; logname=attacker uid=1001 euid=0 tty=/dev/pts/1 ruser=attacker rhost={fake_ip} user=root"
            
            with open('/tmp/test_auth.log', 'a') as f:
                f.write(log_entry + '\n')
            
            logger.info(f"Simulated sudo abuse from {fake_ip}")
            time.sleep(random.uniform(2, 4))
    
    def simulate_ddos_attempt(self):
        """Simulate DDoS-like traffic"""
        logger.info("💥 Starting DDoS simulation...")
        
        for i in range(20):
            if not self.running:
                break
                
            try:
                # Generate rapid requests
                subprocess.run(['curl', '-s', 'http://localhost/', '--connect-timeout', '1'], 
                             capture_output=True, timeout=2)
                time.sleep(0.1)  # Rapid fire
                
            except Exception as e:
                logger.debug(f"DDoS simulation error: {e}")
    
    def run_simulation(self, duration_minutes=5):
        """Run all threat simulations for specified duration"""
        logger.info(f"🚀 Starting {duration_minutes}-minute threat simulation...")
        self.running = True
        
        # Initialize test log file
        with open('/tmp/test_auth.log', 'w') as f:
            f.write("# SecuAI Test Authentication Log\n")
        
        # Start simulation threads
        threads = [
            threading.Thread(target=self.simulate_failed_ssh_attempts, daemon=True),
            threading.Thread(target=self.simulate_web_attacks, daemon=True),
            threading.Thread(target=self.simulate_port_scan, daemon=True),
            threading.Thread(target=self.simulate_sudo_abuse, daemon=True),
            threading.Thread(target=self.simulate_ddos_attempt, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
            time.sleep(2)  # Stagger start times
        
        # Run for specified duration
        try:
            time.sleep(duration_minutes * 60)
        except KeyboardInterrupt:
            logger.info("🛑 Simulation interrupted by user")
        
        self.running = False
        logger.info("✅ Threat simulation completed")
        
        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=5)

def main():
    """Main function"""
    simulator = ThreatSimulator()
    
    print("🔥 SecuAI Threat Simulator")
    print("This will generate realistic security events for testing")
    print("Press Ctrl+C to stop early\n")
    
    duration = input("Enter simulation duration in minutes (default: 2): ").strip()
    if not duration:
        duration = 2
    else:
        try:
            duration = int(duration)
        except ValueError:
            duration = 2
    
    simulator.run_simulation(duration)

if __name__ == '__main__':
    main()