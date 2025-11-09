#!/usr/bin/env python3
"""
SecuAI AI-Powered Threat Analysis
Uses Google Gemini AI to provide intelligent security analysis
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import google.generativeai as genai
from decouple import config

# Configure logging
logger = logging.getLogger(__name__)

class AISecurityAnalyzer:
    """AI-powered security threat analysis using Google Gemini"""
    
    def __init__(self, api_key: str = None):
        """Initialize the AI analyzer with Gemini API key"""
        self.api_key = api_key or config('GEMINI_API_KEY', default=None)
        
        if not self.api_key:
            logger.warning("🚫 GEMINI_API_KEY not found in environment variables. AI analysis will be unavailable.")
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
            
            # Generate AI response with retry logic
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    response = self.model.generate_content(prompt)
                    ai_response = response.text
                    break
                except Exception as retry_error:
                    logger.warning(f"AI generation attempt {attempt + 1} failed: {retry_error}")
                    if attempt == max_retries - 1:
                        raise retry_error
                    continue
            
            # Parse AI response and structure the analysis
            analysis = self._parse_ai_response(ai_response, alert_data)
            
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
    
    def _fallback_analysis(self, alert_data: dict) -> dict:
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
        
        return {
            'severity_level': severity,
            'threat_category': category,
            'risk_score': risk_score,
            'explanation': explanation,
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
            'fallback_analysis': True
        }
    
    def bulk_analyze_alerts(self, alerts: List[dict], max_analyses: int = 10) -> dict:
        """
        Analyze multiple alerts and provide summary insights
        
        Args:
            alerts: List of alert dictionaries
            max_analyses: Maximum number of individual analyses to perform
            
        Returns:
            Dictionary with bulk analysis results
        """
        if not alerts:
            return {'summary': 'No alerts to analyze'}
        
        try:
            # Analyze top priority alerts individually
            individual_analyses = []
            for alert in alerts[:max_analyses]:
                analysis = self.analyze_threat(alert)
                individual_analyses.append({
                    'alert_id': alert.get('id'),
                    'ip': alert.get('ip'),
                    'analysis': analysis
                })
            
            # Create summary analysis
            summary = self._create_bulk_summary(alerts, individual_analyses)
            
            return {
                'individual_analyses': individual_analyses,
                'summary': summary,
                'total_alerts': len(alerts),
                'analyzed_count': len(individual_analyses)
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