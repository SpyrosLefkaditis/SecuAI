"""
SecuAI Log Analyzer
Rule-based detection engine with ML enrichment capabilities
"""

import re
import json
import logging
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Any
import requests
from decouple import config

logger = logging.getLogger(__name__)

# Configuration
ML_ENABLED = config('ML_ENABLED', default=False, cast=bool)
ML_ENDPOINT = config('ML_ENDPOINT', default='')
CONFIDENCE_THRESHOLD = config('CONFIDENCE_THRESHOLD', default=0.7, cast=float)


def analyze_logs(log_text: str) -> List[Dict[str, Any]]:
    """
    Main log analysis function with rule-based detection
    
    Args:
        log_text (str): Raw log text to analyze
        
    Returns:
        List[Dict]: List of findings with IP, reason, confidence, and details
    """
    findings = []
    
    if not log_text or not log_text.strip():
        return findings
    
    try:
        # Split into lines for analysis
        lines = log_text.strip().split('\n')
        
        # Run different detection rules
        findings.extend(detect_failed_logins(lines))
        findings.extend(detect_port_scans(lines))
        findings.extend(detect_web_probing(lines))
        findings.extend(detect_suricata_alerts(lines))
        findings.extend(detect_suspicious_commands(lines))
        findings.extend(detect_brute_force_patterns(lines))
        
        # Deduplicate and sort by confidence
        findings = deduplicate_findings(findings)
        findings.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        logger.info(f"Analysis complete: {len(findings)} findings detected from {len(lines)} log lines")
        
    except Exception as e:
        logger.error(f"Log analysis error: {e}")
        # Return partial results if available
        
    return findings


def detect_failed_logins(lines: List[str]) -> List[Dict[str, Any]]:
    """Detect repeated failed login attempts"""
    findings = []
    failed_attempts = defaultdict(int)
    
    # Patterns for different log formats
    patterns = [
        r'Failed password for .+ from (\d+\.\d+\.\d+\.\d+)',
        r'authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)',
        r'Invalid user .+ from (\d+\.\d+\.\d+\.\d+)',
        r'Connection closed by (\d+\.\d+\.\d+\.\d+) .* \[preauth\]',
        r'Did not receive identification string from (\d+\.\d+\.\d+\.\d+)'
    ]
    
    for line in lines:
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
    
    # Flag IPs with multiple failed attempts
    for ip, count in failed_attempts.items():
        if count >= 3:  # Threshold for suspicious activity
            confidence = min(0.9, 0.5 + (count - 3) * 0.1)  # Increase confidence with more attempts
            findings.append({
                'ip': ip,
                'reason': f'Multiple failed login attempts ({count} attempts)',
                'confidence': confidence,
                'details': {
                    'attack_type': 'brute_force_login',
                    'attempt_count': count,
                    'detection_rule': 'failed_login_detection'
                }
            })
    
    return findings


def detect_port_scans(lines: List[str]) -> List[Dict[str, Any]]:
    """Detect port scanning activity"""
    findings = []
    scan_indicators = defaultdict(int)
    
    # Patterns for port scan detection
    patterns = [
        r'.*(?:port scan|nmap|masscan).*from.*?(\d+\.\d+\.\d+\.\d+)',
        r'.*SYN.*(\d+\.\d+\.\d+\.\d+).*multiple ports',
        r'.*Connection attempt.*(\d+\.\d+\.\d+\.\d+).*refused',
        r'.*TCP.*(\d+\.\d+\.\d+\.\d+).*\[SYN\].*multiple'
    ]
    
    # Count SYN packets per IP
    syn_counts = defaultdict(int)
    
    for line in lines:
        # Direct scan detection
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                ip = match.group(1)
                scan_indicators[ip] += 1
        
        # Count SYN packets
        syn_match = re.search(r'(\d+\.\d+\.\d+\.\d+).*SYN', line, re.IGNORECASE)
        if syn_match:
            ip = syn_match.group(1)
            syn_counts[ip] += 1
    
    # Flag direct scan indicators
    for ip, count in scan_indicators.items():
        confidence = min(0.95, 0.7 + count * 0.1)
        findings.append({
            'ip': ip,
            'reason': f'Port scanning activity detected ({count} indicators)',
            'confidence': confidence,
            'details': {
                'attack_type': 'port_scan',
                'indicator_count': count,
                'detection_rule': 'port_scan_detection'
            }
        })
    
    # Flag excessive SYN packets
    for ip, count in syn_counts.items():
        if count >= 10:  # Threshold for suspicious SYN activity
            confidence = min(0.8, 0.5 + (count - 10) * 0.02)
            findings.append({
                'ip': ip,
                'reason': f'Excessive SYN packets ({count} packets)',
                'confidence': confidence,
                'details': {
                    'attack_type': 'potential_syn_scan',
                    'syn_count': count,
                    'detection_rule': 'syn_flood_detection'
                }
            })
    
    return findings


def detect_web_probing(lines: List[str]) -> List[Dict[str, Any]]:
    """Detect web application probing and scanning"""
    findings = []
    probing_attempts = defaultdict(int)
    suspicious_uris = defaultdict(set)
    
    # Suspicious URI patterns
    suspicious_patterns = [
        r'/admin', r'/wp-admin', r'/administrator', r'/login',
        r'/phpmyadmin', r'/mysql', r'/database',
        r'\.php\?', r'\.asp\?', r'\.jsp\?',
        r'/etc/passwd', r'/etc/shadow',
        r'SELECT.*FROM', r'UNION.*SELECT',
        r'<script>', r'javascript:', r'eval\(',
        r'/\.env', r'/config\.', r'/backup'
    ]
    
    for line in lines:
        # Extract IP and URI from web logs
        web_match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?"[A-Z]+\s+([^\s]+)', line)
        if web_match:
            ip, uri = web_match.groups()
            
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, uri, re.IGNORECASE):
                    probing_attempts[ip] += 1
                    suspicious_uris[ip].add(pattern)
                    break
    
    # Flag IPs with multiple probing attempts
    for ip, count in probing_attempts.items():
        if count >= 3:
            confidence = min(0.85, 0.6 + count * 0.05)
            findings.append({
                'ip': ip,
                'reason': f'Web application probing ({count} suspicious requests)',
                'confidence': confidence,
                'details': {
                    'attack_type': 'web_probing',
                    'request_count': count,
                    'suspicious_patterns': list(suspicious_uris[ip]),
                    'detection_rule': 'web_probing_detection'
                }
            })
    
    return findings


def detect_suricata_alerts(lines: List[str]) -> List[Dict[str, Any]]:
    """Parse Suricata EVE JSON alerts"""
    findings = []
    
    for line in lines:
        try:
            # Try to parse as JSON (Suricata EVE format)
            if line.strip().startswith('{'):
                event = json.loads(line.strip())
                
                if event.get('event_type') == 'alert':
                    alert = event.get('alert', {})
                    src_ip = event.get('src_ip')
                    dest_ip = event.get('dest_ip')
                    signature = alert.get('signature', '')
                    severity = alert.get('severity', 3)
                    
                    # Determine which IP to flag (prefer external/source IP)
                    target_ip = src_ip if src_ip else dest_ip
                    
                    if target_ip and signature:
                        # Calculate confidence based on signature and severity
                        confidence = 0.5
                        if 'ET SCAN' in signature or 'NMAP' in signature:
                            confidence = 0.8
                        elif 'SQL' in signature and 'injection' in signature.lower():
                            confidence = 0.9
                        elif severity <= 2:  # High severity
                            confidence = 0.85
                        elif severity == 3:  # Medium severity
                            confidence = 0.7
                        
                        findings.append({
                            'ip': target_ip,
                            'reason': f'Suricata Alert: {signature}',
                            'confidence': confidence,
                            'details': {
                                'attack_type': 'ids_alert',
                                'signature': signature,
                                'severity': severity,
                                'dest_ip': dest_ip,
                                'detection_rule': 'suricata_eve_parsing'
                            }
                        })
                        
        except json.JSONDecodeError:
            continue
        except Exception as e:
            logger.debug(f"Suricata parsing error: {e}")
            continue
    
    return findings


def detect_suspicious_commands(lines: List[str]) -> List[Dict[str, Any]]:
    """Detect suspicious command execution in logs"""
    findings = []
    command_attempts = defaultdict(int)
    
    # Suspicious command patterns
    suspicious_commands = [
        r'nc\s+-[lv]',  # netcat listeners
        r'wget\s+http',  # downloading files
        r'curl\s+.*\|\s*bash',  # curl pipe to bash
        r'/bin/sh\s+-c',  # shell command execution
        r'python.*-c.*import',  # python one-liners
        r'powershell.*-enc',  # encoded powershell
        r'base64\s+-d',  # base64 decoding
        r'chmod\s+\+x',  # making files executable
        r'rm\s+-rf\s+/',  # dangerous rm commands
        r'dd\s+if=.*of='  # disk operations
    ]
    
    for line in lines:
        # Extract IP from command logs
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip = ip_match.group(1)
            
            # Check for suspicious commands
            for pattern in suspicious_commands:
                if re.search(pattern, line, re.IGNORECASE):
                    command_attempts[ip] += 1
                    break
    
    # Flag IPs with suspicious command execution
    for ip, count in command_attempts.items():
        confidence = min(0.9, 0.7 + count * 0.1)
        findings.append({
            'ip': ip,
            'reason': f'Suspicious command execution ({count} commands)',
            'confidence': confidence,
            'details': {
                'attack_type': 'command_execution',
                'command_count': count,
                'detection_rule': 'suspicious_commands'
            }
        })
    
    return findings


def detect_brute_force_patterns(lines: List[str]) -> List[Dict[str, Any]]:
    """Detect various brute force patterns"""
    findings = []
    connection_counts = defaultdict(int)
    time_windows = defaultdict(list)
    
    for line in lines:
        # Extract timestamp and IP
        timestamp_match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        
        if timestamp_match and ip_match:
            timestamp_str = timestamp_match.group(1)
            ip = ip_match.group(1)
            
            # Count connections per IP
            connection_counts[ip] += 1
            
            # Track connection timing (simplified)
            time_windows[ip].append(timestamp_str)
    
    # Flag IPs with excessive connections
    for ip, count in connection_counts.items():
        if count >= 20:  # High connection threshold
            confidence = min(0.8, 0.5 + (count - 20) * 0.01)
            findings.append({
                'ip': ip,
                'reason': f'High connection volume ({count} connections)',
                'confidence': confidence,
                'details': {
                    'attack_type': 'high_volume_connections',
                    'connection_count': count,
                    'detection_rule': 'connection_volume_analysis'
                }
            })
    
    return findings


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings and merge similar ones"""
    deduplicated = {}
    
    for finding in findings:
        key = f"{finding['ip']}:{finding['reason']}"
        
        if key in deduplicated:
            # Merge findings: keep higher confidence and combine details
            existing = deduplicated[key]
            if finding['confidence'] > existing['confidence']:
                existing['confidence'] = finding['confidence']
            
            # Merge details if both have them
            if 'details' in existing and 'details' in finding:
                existing_details = existing.get('details', {})
                new_details = finding.get('details', {})
                existing_details.update(new_details)
        else:
            deduplicated[key] = finding
    
    return list(deduplicated.values())


def ml_enrich(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich finding with ML analysis (stub implementation)
    
    Args:
        finding (Dict): Original finding from rule-based detection
        
    Returns:
        Dict: Enriched finding with ML insights
    """
    enriched = finding.copy()
    
    try:
        if ML_ENABLED and ML_ENDPOINT:
            # Call external ML service
            response = requests.post(
                ML_ENDPOINT,
                json={
                    'ip': finding['ip'],
                    'reason': finding['reason'],
                    'details': finding.get('details', {})
                },
                timeout=5
            )
            
            if response.status_code == 200:
                ml_result = response.json()
                enriched.update(ml_result)
            else:
                logger.warning(f"ML service returned {response.status_code}")
                
        else:
            # Mock ML enrichment for hackathon demo
            mock_ml_result = generate_mock_ml_enrichment(finding)
            enriched.update(mock_ml_result)
            
    except requests.RequestException as e:
        logger.warning(f"ML enrichment failed: {e}")
        # Fall back to mock enrichment
        mock_ml_result = generate_mock_ml_enrichment(finding)
        enriched.update(mock_ml_result)
    
    except Exception as e:
        logger.error(f"ML enrichment error: {e}")
    
    return enriched


def generate_mock_ml_enrichment(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate mock ML enrichment for demonstration
    This simulates what a real ML service might return
    """
    ip = finding['ip']
    reason = finding['reason']
    original_confidence = finding.get('confidence', 0.5)
    
    # Mock confidence adjustment based on "ML analysis"
    confidence_boost = 0.0
    ml_explanation = "Standard rule-based detection"
    threat_level = "medium"
    
    # Simulate ML insights based on patterns
    if 'brute force' in reason.lower() or 'failed login' in reason.lower():
        confidence_boost = 0.1
        ml_explanation = "Pattern consistent with automated attack tools"
        threat_level = "high"
        
    elif 'port scan' in reason.lower():
        confidence_boost = 0.15
        ml_explanation = "Reconnaissance behavior detected, likely automated scanner"
        threat_level = "high"
        
    elif 'web probing' in reason.lower():
        confidence_boost = 0.05
        ml_explanation = "Web application vulnerability scanning detected"
        threat_level = "medium"
        
    elif 'suricata' in reason.lower():
        confidence_boost = 0.2
        ml_explanation = "Network intrusion detection system alert - verified threat"
        threat_level = "critical"
    
    # Simulate geolocation data (mock)
    mock_geo = {
        'country': 'Unknown',
        'region': 'Unknown',
        'is_tor': False,
        'is_vpn': False,
        'is_hosting': False
    }
    
    # Simple heuristic for demo
    if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
        mock_geo['country'] = 'Local Network'
    else:
        # Mock some interesting countries for demo
        countries = ['Russia', 'China', 'North Korea', 'Iran', 'Unknown', 'Germany', 'USA']
        mock_geo['country'] = countries[hash(ip) % len(countries)]
        
        if mock_geo['country'] in ['Russia', 'China', 'North Korea', 'Iran']:
            confidence_boost += 0.05
            threat_level = "high"
    
    # Calculate final confidence
    final_confidence = min(0.99, original_confidence + confidence_boost)
    
    return {
        'confidence': final_confidence,
        'ml_insights': {
            'explanation': ml_explanation,
            'threat_level': threat_level,
            'confidence_adjustment': confidence_boost,
            'geolocation': mock_geo,
            'ml_model_version': 'mock-v1.0',
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
    }


def parse_honeypot_feed(feed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse honeypot feed data and convert to alert format
    
    Args:
        feed_data (Dict): Raw honeypot feed data
        
    Returns:
        List[Dict]: List of alerts from honeypot data
    """
    alerts = []
    
    try:
        if 'ips' in feed_data:
            for ip_entry in feed_data['ips']:
                if isinstance(ip_entry, dict) and 'ip' in ip_entry:
                    alert = {
                        'ip': ip_entry['ip'],
                        'reason': 'Honeypot interaction detected',
                        'confidence': 0.9,  # High confidence for honeypot hits
                        'details': {
                            'attack_type': 'honeypot_interaction',
                            'honeypot_data': ip_entry,
                            'detection_rule': 'honeypot_feed'
                        }
                    }
                    alerts.append(alert)
                    
    except Exception as e:
        logger.error(f"Honeypot feed parsing error: {e}")
    
    return alerts