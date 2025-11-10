#!/usr/bin/env python3
"""
SecuAI AI-Powered Threat Analysis
Uses Google Gemini AI to provide intelligent security analysis
"""

import os
import json
import logging
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import google.generativeai as genai
from functools import wraps
from decouple import config

# Configure logging
logger = logging.getLogger(__name__)

class RateLimiter:
    """Simple rate limiter for API calls"""
    def __init__(self, max_calls=10, time_window=60):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []
    
    def can_make_call(self):
        now = datetime.utcnow()
        # Remove old calls outside the time window
        self.calls = [call_time for call_time in self.calls 
                     if (now - call_time).seconds < self.time_window]
        
        return len(self.calls) < self.max_calls
    
    def record_call(self):
        self.calls.append(datetime.utcnow())
    
    def wait_time(self):
        if not self.calls:
            return 0
        oldest_call = min(self.calls)
        time_passed = (datetime.utcnow() - oldest_call).seconds
        return max(0, self.time_window - time_passed)

class AISecurityAnalyzer:
    """AI-powered security threat analysis using Google Gemini"""
    
    def __init__(self, api_key: str = None):
        """Initialize the AI analyzer with Gemini API key"""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY', 'AIzaSyDTO00DyoJgtgsMfwQhwfAGZ-Rmy-HOS4Y')
        
        # Rate limiter: 10 calls per minute for free tier
        self.rate_limiter = RateLimiter(max_calls=8, time_window=60)
        
        # Cache for recent analyses to avoid duplicate API calls
        self.analysis_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        if not self.api_key:
            logger.error("No Gemini API key provided")
            self.model = None
            return
            
        try:
            genai.configure(api_key=self.api_key)
            # Try different model names in order of preference (using latest available models)
            model_names = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-pro-latest', 'gemini-flash-latest']
            
            self.model = None
            for model_name in model_names:
                try:
                    self.model = genai.GenerativeModel(model_name)
                    # Test the model with a simple request
                    test_response = self.model.generate_content("Hello")
                    logger.info(f"🤖 AI Security Analyzer initialized successfully with model: {model_name}")
                    break
                except Exception as model_error:
                    logger.warning(f"Failed to initialize model {model_name}: {model_error}")
                    continue
            
            if not self.model:
                raise Exception("No working Gemini model found")
                
        except Exception as e:
            logger.error(f"Failed to initialize AI analyzer: {e}")
            self.model = None
    
    def analyze_threat(self, alert_data: dict) -> dict:
        """
        Analyze security threat using AI and provide intelligent assessment
        
        Args:
            alert_data: Dictionary containing alert information
            
        Returns:
            Dictionary with AI analysis results
        """
        if not self.model:
            return self._fallback_analysis(alert_data)
        
        # Create cache key for this alert
        cache_key = f"{alert_data.get('ip', 'unknown')}_{alert_data.get('reason', 'unknown')}"[:50]
        
        # Check cache first
        cached_result = self._get_cached_analysis(cache_key)
        if cached_result:
            logger.info(f"🔄 Using cached AI analysis for {alert_data.get('ip', 'unknown')}")
            return cached_result
        
        # Check rate limit
        if not self.rate_limiter.can_make_call():
            wait_time = self.rate_limiter.wait_time()
            logger.warning(f"⏱️ Rate limit reached. Using fallback analysis. Wait time: {wait_time}s")
            return self._fallback_analysis(alert_data, rate_limited=True)
        
        try:
            # Extract key information from alert
            ip = alert_data.get('ip', 'Unknown')
            reason = alert_data.get('reason', 'Unknown threat')
            confidence = alert_data.get('confidence', 0.0)
            source = alert_data.get('source', 'Unknown')
            details = alert_data.get('details', '{}')
            
            # Parse details if it's a string
            if isinstance(details, str):
                try:
                    details = eval(details) if details.startswith('{') else {}
                except:
                    details = {}
            
            attack_summary = details.get('attack_summary', {})
            
            # Create comprehensive prompt for AI analysis
            prompt = self._create_analysis_prompt(ip, reason, confidence, source, attack_summary)
            
            # Record the API call
            self.rate_limiter.record_call()
            
            # Generate AI response with retry logic
            max_retries = 3
            retry_delay = 2  # seconds
            
            for attempt in range(max_retries):
                try:
                    response = self.model.generate_content(prompt)
                    ai_response = response.text
                    break
                except Exception as retry_error:
                    error_str = str(retry_error).lower()
                    
                    if 'quota' in error_str or 'rate limit' in error_str:
                        logger.warning(f"⚠️ Rate limit hit on attempt {attempt + 1}: {retry_error}")
                        if attempt < max_retries - 1:
                            wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
                            logger.info(f"⏳ Waiting {wait_time}s before retry...")
                            time.sleep(wait_time)
                            continue
                        else:
                            logger.error("🚫 Rate limit exceeded, using fallback analysis")
                            return self._fallback_analysis(alert_data, rate_limited=True)
                    else:
                        logger.warning(f"AI generation attempt {attempt + 1} failed: {retry_error}")
                        if attempt == max_retries - 1:
                            raise retry_error
                        time.sleep(retry_delay)
                        continue
            
            # Parse AI response and structure the analysis
            analysis = self._parse_ai_response(ai_response, alert_data)
            
            # Cache the successful analysis
            self._cache_analysis(cache_key, analysis)
            
            logger.info(f"🧠 AI analysis completed for {ip} - Severity: {analysis.get('severity_level', 'Unknown')}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed for {ip}: {e}")
            return self._fallback_analysis(alert_data)
    
    def _create_analysis_prompt(self, ip: str, reason: str, confidence: float, source: str, attack_summary: dict) -> str:
        """Create a comprehensive prompt for AI threat analysis"""
        
        attack_type = attack_summary.get('attack_type', 'Unknown')
        target_url = attack_summary.get('target_url', 'N/A')
        user_agent = attack_summary.get('user_agent', 'N/A')
        total_attempts = attack_summary.get('total_attempts', 0)
        method = attack_summary.get('method', 'N/A')
        status_code = attack_summary.get('status_code', 'N/A')
        
        prompt = f"""
You are SecuAI, an expert cybersecurity analyst. Analyze this security threat and provide a comprehensive assessment.

THREAT DETAILS:
- Source IP: {ip}
- Attack Type: {attack_type}
- Detection Confidence: {confidence:.1%}
- Log Source: {source}
- Target URL: {target_url}
- HTTP Method: {method}
- Status Code: {status_code}
- User Agent: {user_agent}
- Total Attempts: {total_attempts}
- Alert Reason: {reason}

Please provide your analysis in this JSON format:
{{
    "severity_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "threat_category": "specific category like 'Web Application Attack', 'Brute Force', etc.",
    "risk_score": "number from 1-100",
    "explanation": "clear explanation of what this attack is and why it's dangerous",
    "attack_vector": "how the attacker is trying to compromise the system",
    "potential_impact": "what damage this attack could cause if successful",
    "recommended_actions": [
        "immediate action 1",
        "immediate action 2",
        "preventive measure 1"
    ],
    "is_automated": "true/false - whether this appears to be automated scanning",
    "geolocation_risk": "assessment of IP geographic location risk",
    "technical_details": "technical explanation for security professionals"
}}

Focus on providing actionable insights and clear explanations that both technical and non-technical users can understand.
"""
        return prompt
    
    def _parse_ai_response(self, ai_response: str, original_alert: dict) -> dict:
        """Parse AI response and structure the analysis"""
        try:
            # Try to extract JSON from AI response
            if '{' in ai_response and '}' in ai_response:
                json_start = ai_response.find('{')
                json_end = ai_response.rfind('}') + 1
                json_str = ai_response[json_start:json_end]
                
                # Clean up the JSON string
                json_str = json_str.replace('```json', '').replace('```', '')
                
                analysis = json.loads(json_str)
            else:
                # Fallback parsing if no JSON structure
                analysis = self._extract_analysis_from_text(ai_response)
            
            # Add metadata
            analysis['ai_generated'] = True
            analysis['analysis_timestamp'] = datetime.utcnow().isoformat()
            analysis['original_confidence'] = original_alert.get('confidence', 0.0)
            analysis['enhanced_by_ai'] = True
            
            # Ensure required fields exist
            required_fields = {
                'severity_level': 'MEDIUM',
                'threat_category': 'Security Threat',
                'risk_score': 50,
                'explanation': 'AI analysis completed',
                'recommended_actions': ['Monitor IP activity', 'Review security logs']
            }
            
            for field, default in required_fields.items():
                if field not in analysis:
                    analysis[field] = default
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            return self._fallback_analysis(original_alert)
    
    def _extract_analysis_from_text(self, text: str) -> dict:
        """Extract analysis from unstructured AI response text"""
        analysis = {}
        
        # Simple text parsing for key information
        text_lower = text.lower()
        
        # Determine severity
        if any(word in text_lower for word in ['critical', 'severe', 'dangerous', 'high risk']):
            analysis['severity_level'] = 'HIGH'
            analysis['risk_score'] = 80
        elif any(word in text_lower for word in ['medium', 'moderate']):
            analysis['severity_level'] = 'MEDIUM'
            analysis['risk_score'] = 60
        else:
            analysis['severity_level'] = 'LOW'
            analysis['risk_score'] = 40
        
        # Extract explanation (first few sentences)
        sentences = text.split('.')[:3]
        analysis['explanation'] = '. '.join(sentences).strip()
        
        # Basic threat categorization
        if 'sql' in text_lower or 'injection' in text_lower:
            analysis['threat_category'] = 'SQL Injection Attack'
        elif 'brute' in text_lower or 'password' in text_lower:
            analysis['threat_category'] = 'Brute Force Attack'
        elif 'scan' in text_lower or 'probe' in text_lower:
            analysis['threat_category'] = 'Network Scanning'
        else:
            analysis['threat_category'] = 'Security Threat'
        
        return analysis
    
    def _fallback_analysis(self, alert_data: dict, rate_limited: bool = False) -> dict:
        """Provide fallback analysis when AI is unavailable"""
        confidence = alert_data.get('confidence', 0.0)
        reason = alert_data.get('reason', '')
        
        # Rule-based severity assessment
        if confidence >= 0.9:
            severity = 'CRITICAL'
            risk_score = 95
        elif confidence >= 0.8:
            severity = 'HIGH'
            risk_score = 85
        elif confidence >= 0.6:
            severity = 'MEDIUM'
            risk_score = 65
        else:
            severity = 'LOW'
            risk_score = 40
        
        # Basic threat categorization
        reason_lower = reason.lower()
        if 'sql' in reason_lower:
            category = 'SQL Injection Attack'
            explanation = 'Potential SQL injection attempt detected targeting database queries'
        elif 'brute' in reason_lower or 'ssh' in reason_lower:
            category = 'Brute Force Attack'
            explanation = 'Multiple failed authentication attempts suggesting brute force attack'
        elif 'admin' in reason_lower or 'wp-admin' in reason_lower:
            category = 'Admin Panel Attack'
            explanation = 'Unauthorized access attempts to administrative interfaces'
        else:
            category = 'Security Threat'
            explanation = 'Suspicious activity detected requiring investigation'
        
        fallback_reason = "Rate limit reached" if rate_limited else "AI service unavailable"
        
        return {
            'severity_level': severity,
            'threat_category': category,
            'risk_score': risk_score,
            'explanation': f"{explanation} (Analysis: {fallback_reason})",
            'attack_vector': 'Network-based attack attempt',
            'potential_impact': 'Potential system compromise if successful',
            'recommended_actions': [
                'Block source IP immediately',
                'Review security logs for related activity',
                'Monitor for additional attempts'
            ],
            'is_automated': True,
            'ai_generated': False,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'fallback_analysis': True,
            'rate_limited': rate_limited
        }
    
    def bulk_analyze_alerts(self, alerts: List[dict], max_analyses: int = 5) -> dict:
        """
        Analyze multiple alerts and provide summary insights
        
        Args:
            alerts: List of alert dictionaries
            max_analyses: Maximum number of individual analyses to perform (reduced for rate limiting)
            
        Returns:
            Dictionary with bulk analysis results
        """
        if not alerts:
            return {'summary': 'No alerts to analyze'}
        
        try:
            # Reduce max analyses to respect rate limits
            effective_max = min(max_analyses, 5)  # Limit to 5 for rate limiting
            
            # Analyze top priority alerts individually
            individual_analyses = []
            rate_limited_count = 0
            
            for i, alert in enumerate(alerts[:effective_max]):
                if not self.rate_limiter.can_make_call():
                    rate_limited_count = effective_max - i
                    logger.warning(f"⚠️ Rate limit reached during bulk analysis. Skipping {rate_limited_count} analyses")
                    break
                
                analysis = self.analyze_threat(alert)
                individual_analyses.append({
                    'alert_id': alert.get('id'),
                    'ip': alert.get('ip'),
                    'analysis': analysis
                })
                
                # Small delay between API calls to avoid hitting rate limits
                time.sleep(0.5)
            
            # Create summary analysis
            summary = self._create_bulk_summary(alerts, individual_analyses)
            
            return {
                'individual_analyses': individual_analyses,
                'summary': summary,
                'total_alerts': len(alerts),
                'analyzed_count': len(individual_analyses),
                'rate_limited_count': rate_limited_count,
                'rate_limit_status': {
                    'calls_remaining': max(0, self.rate_limiter.max_calls - len(self.rate_limiter.calls)),
                    'reset_time': self.rate_limiter.wait_time()
                }
            }
            
        except Exception as e:
            logger.error(f"Bulk analysis failed: {e}")
            return {'error': str(e), 'summary': 'Analysis failed'}
    
    def _create_bulk_summary(self, all_alerts: List[dict], analyses: List[dict]) -> dict:
        """Create summary analysis of multiple threats"""
        try:
            # Extract trends and patterns
            severities = [a['analysis'].get('severity_level', 'UNKNOWN') for a in analyses]
            threat_categories = [a['analysis'].get('threat_category', 'Unknown') for a in analyses]
            ips = list(set([alert.get('ip') for alert in all_alerts]))
            
            # Count severity levels
            severity_counts = {
                'CRITICAL': severities.count('CRITICAL'),
                'HIGH': severities.count('HIGH'),
                'MEDIUM': severities.count('MEDIUM'),
                'LOW': severities.count('LOW')
            }
            
            # Most common threat types
            threat_type_counts = {}
            for category in threat_categories:
                threat_type_counts[category] = threat_type_counts.get(category, 0) + 1
            
            most_common_threat = max(threat_type_counts.items(), key=lambda x: x[1])[0] if threat_type_counts else 'Unknown'
            
            return {
                'total_unique_ips': len(ips),
                'severity_breakdown': severity_counts,
                'most_common_threat': most_common_threat,
                'threat_diversity': len(set(threat_categories)),
                'high_priority_count': severity_counts['CRITICAL'] + severity_counts['HIGH'],
                'recommendation': self._get_bulk_recommendation(severity_counts, most_common_threat)
            }
            
        except Exception as e:
            logger.error(f"Failed to create bulk summary: {e}")
            return {'error': 'Summary generation failed'}
    
    def _get_bulk_recommendation(self, severity_counts: dict, most_common_threat: str) -> str:
        """Generate bulk recommendation based on threat analysis"""
        high_priority = severity_counts['CRITICAL'] + severity_counts['HIGH']
        
        if high_priority >= 5:
            return f"🚨 URGENT: Multiple high-severity {most_common_threat.lower()} detected. Immediate incident response required."
        elif high_priority >= 2:
            return f"⚠️ WARNING: Several {most_common_threat.lower()} incidents require attention. Escalate to security team."
        else:
            return f"ℹ️ INFO: Routine security monitoring detected {most_common_threat.lower()}. Continue monitoring."
    
    def list_available_models(self) -> list:
        """List available Gemini models for debugging"""
        try:
            genai.configure(api_key=self.api_key)
            models = genai.list_models()
            available_models = []
            for model in models:
                if 'generateContent' in model.supported_generation_methods:
                    available_models.append(model.name)
            logger.info(f"Available Gemini models: {available_models}")
            return available_models
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return []
    
    def _get_cached_analysis(self, cache_key: str) -> Optional[dict]:
        """Get cached analysis if still valid"""
        if cache_key in self.analysis_cache:
            cached_data = self.analysis_cache[cache_key]
            if datetime.utcnow() - cached_data['timestamp'] < timedelta(seconds=self.cache_ttl):
                return cached_data['analysis']
            else:
                # Remove expired cache
                del self.analysis_cache[cache_key]
        return None
    
    def _cache_analysis(self, cache_key: str, analysis: dict):
        """Cache analysis result"""
        self.analysis_cache[cache_key] = {
            'analysis': analysis,
            'timestamp': datetime.utcnow()
        }
        
        # Clean old cache entries (keep last 50)
        if len(self.analysis_cache) > 50:
            oldest_key = min(self.analysis_cache.keys(), 
                           key=lambda k: self.analysis_cache[k]['timestamp'])
            del self.analysis_cache[oldest_key]

    def get_threat_intelligence(self, ip: str) -> dict:
        """Get AI-powered threat intelligence for an IP address"""
        if not self.model:
            return {'error': 'AI service unavailable'}
        
        try:
            prompt = f"""
Provide threat intelligence analysis for IP address: {ip}

Please analyze this IP and provide intelligence in JSON format:
{{
    "reputation_score": "1-100 risk score",
    "likely_origin": "probable geographic region or hosting provider",
    "threat_indicators": ["list of concerning patterns or behaviors"],
    "recommendation": "specific action recommendation",
    "confidence": "assessment confidence level"
}}

Focus on actionable intelligence for security teams.
"""
            
            response = self.model.generate_content(prompt)
            
            # Parse response similar to threat analysis
            analysis = self._parse_ai_response(response.text, {'ip': ip})
            
            return analysis
            
        except Exception as e:
            logger.error(f"Threat intelligence failed for {ip}: {e}")
            return {'error': str(e)}

# Global instance
ai_analyzer = AISecurityAnalyzer()