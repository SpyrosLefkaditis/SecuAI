#!/usr/bin/env python3
"""
Test runner script for SecuAI
Runs all tests and provides summary
"""

import pytest
import sys
import os

def main():
    """Run all SecuAI tests"""
    print("🧪 Running SecuAI Test Suite")
    print("=" * 50)
    
    # Add project root to Python path
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)
    
    # Test configuration
    test_args = [
        'tests/',           # Test directory
        '-v',               # Verbose output
        '--tb=short',       # Short traceback format
        '--color=yes',      # Colored output
        '--durations=10',   # Show 10 slowest tests
    ]
    
    # Add coverage if available
    try:
        import coverage
        test_args.extend([
            '--cov=.',
            '--cov-report=term-missing',
            '--cov-report=html:coverage_html'
        ])
        print("📊 Coverage reporting enabled")
    except ImportError:
        print("ℹ️  Coverage reporting not available (install pytest-cov)")
    
    print("\n🚀 Starting tests...")
    
    # Run tests
    exit_code = pytest.main(test_args)
    
    print("\n" + "=" * 50)
    if exit_code == 0:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")
        print("📋 Check the output above for details")
    
    print("\n📁 Test artifacts:")
    if os.path.exists('coverage_html'):
        print("   📊 Coverage report: coverage_html/index.html")
    
    return exit_code

if __name__ == '__main__':
    sys.exit(main())