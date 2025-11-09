#!/usr/bin/env python3
"""
Test script to debug Gemini AI integration
"""

import os
import sys
import logging
from datetime import datetime

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ai_analyzer import ai_analyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_ai_analyzer():
    """Test the AI analyzer functionality"""
    print("🧪 Testing AI Analyzer...")
    
    # Test 1: List available models
    print("\n1. Checking available models:")
    models = ai_analyzer.list_available_models()
    if models:
        print(f"✅ Found {len(models)} available models:")
        for model in models:
            print(f"   - {model}")
    else:
        print("❌ No models found or API error")
    
    # Test 2: Test threat analysis
    print("\n2. Testing threat analysis:")
    test_alert = {
        'ip': '192.168.1.100',
        'reason': 'SQL Injection from 192.168.1.100 targeting /admin/login.php',
        'confidence': 0.85,
        'source': 'nginx_access',
        'details': {
            'attack_summary': {
                'ip': '192.168.1.100',
                'attack_type': 'SQL Injection',
                'target_url': '/admin/login.php',
                'method': 'POST',
                'status_code': '200',
                'user_agent': 'sqlmap/1.6.0',
                'total_attempts': 5
            }
        }
    }
    
    try:
        analysis = ai_analyzer.analyze_threat(test_alert)
        print("✅ AI analysis successful:")
        print(f"   Severity: {analysis.get('severity_level', 'Unknown')}")
        print(f"   Risk Score: {analysis.get('risk_score', 'Unknown')}")
        print(f"   Category: {analysis.get('threat_category', 'Unknown')}")
        print(f"   Explanation: {analysis.get('explanation', 'No explanation')[:100]}...")
        print(f"   AI Generated: {analysis.get('ai_generated', False)}")
        
        if analysis.get('recommended_actions'):
            print("   Recommendations:")
            for action in analysis['recommended_actions'][:3]:
                print(f"   - {action}")
    
    except Exception as e:
        print(f"❌ AI analysis failed: {e}")
    
    # Test 3: Test threat intelligence
    print("\n3. Testing threat intelligence:")
    try:
        intel = ai_analyzer.get_threat_intelligence('192.168.1.100')
        if 'error' not in intel:
            print("✅ Threat intelligence successful")
            print(f"   Intelligence data keys: {list(intel.keys())}")
        else:
            print(f"❌ Threat intelligence failed: {intel['error']}")
    except Exception as e:
        print(f"❌ Threat intelligence error: {e}")
    
    print("\n🎯 AI Analyzer test completed!")

if __name__ == '__main__':
    test_ai_analyzer()