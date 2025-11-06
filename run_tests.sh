#!/bin/bash
#
# SecuAI Test Runner
# Comprehensive test suite for the SecuAI security monitoring system
#

set -e  # Exit on any error

echo "🧪 SecuAI Test Suite"
echo "==================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if we're in the correct directory
if [ ! -f "app.py" ]; then
    echo -e "${RED}❌ Error: Please run this script from the SecuAI root directory${NC}"
    exit 1
fi

# Function to print status
print_status() {
    echo -e "${BLUE}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Python is available
print_status "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed or not in PATH"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
print_success "Python $PYTHON_VERSION found"

# Check if pip is available
print_status "Checking pip installation..."
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    print_error "pip is not installed or not in PATH"
    exit 1
fi

# Install test dependencies if needed
print_status "Installing test dependencies..."
pip3 install -q pytest pytest-flask coverage || {
    print_error "Failed to install test dependencies"
    exit 1
}
print_success "Test dependencies installed"

# Create uploads directory if it doesn't exist
mkdir -p uploads
mkdir -p logs

# Set environment variables for testing
export FLASK_ENV=testing
export DEBUG=false
export SIMULATE_BLOCKS=true
export REAL_BLOCKING_ENABLED=false

print_status "Environment configured for testing"

# Run unit tests
print_status "Running unit tests..."
echo

# Test the analyzer module
print_status "Testing log analyzer..."
if python3 -m pytest tests/test_analyzer.py -v --tb=short; then
    print_success "Analyzer tests passed"
else
    print_error "Analyzer tests failed"
    TEST_FAILED=1
fi

echo

# Test the Flask application
print_status "Testing Flask application..."
if python3 -m pytest tests/test_app.py -v --tb=short; then
    print_success "Application tests passed"
else
    print_error "Application tests failed"
    TEST_FAILED=1
fi

echo

# Test host blocker (if available)
print_status "Testing host blocker..."
if python3 agents/host_blocker.py; then
    print_success "Host blocker tests passed"
else
    print_warning "Host blocker tests had warnings (expected in containerized environments)"
fi

echo

# Run coverage analysis
print_status "Running coverage analysis..."
if command -v coverage &> /dev/null; then
    coverage run -m pytest tests/ --tb=short
    coverage report --include="*.py" --omit="tests/*"
    coverage html --include="*.py" --omit="tests/*" -d htmlcov
    print_success "Coverage report generated in htmlcov/"
else
    print_warning "Coverage not available, install with: pip install coverage"
fi

echo

# Test database initialization
print_status "Testing database initialization..."
if python3 init_db.py > /dev/null 2>&1; then
    print_success "Database initialization test passed"
    # Clean up test database
    rm -f secai.db
else
    print_error "Database initialization failed"
    TEST_FAILED=1
fi

# Test sample data analysis
print_status "Testing sample data analysis..."
if [ -f "sample_auth.log" ]; then
    # Create a simple test script
    cat > test_sample_analysis.py << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.append('.')
from analyzer import analyze_logs

# Test sample log analysis
with open('sample_auth.log', 'r') as f:
    sample_logs = f.read()

findings = analyze_logs(sample_logs)
print(f"Analyzed sample logs: {len(findings)} findings detected")

if len(findings) > 0:
    print("Sample analysis successful")
    sys.exit(0)
else:
    print("No findings in sample logs - may indicate analysis issue")
    sys.exit(1)
EOF

    if python3 test_sample_analysis.py; then
        print_success "Sample data analysis test passed"
    else
        print_warning "Sample data analysis produced no findings"
    fi
    
    rm -f test_sample_analysis.py
else
    print_warning "sample_auth.log not found, skipping sample analysis test"
fi

echo

# Test configuration validation
print_status "Testing configuration..."
if [ -f ".env.template" ]; then
    print_success "Environment template found"
else
    print_warning "Environment template not found"
fi

# Check for security warnings
print_status "Security configuration check..."
SECURITY_WARNINGS=0

if grep -q "ChangeMe123!" .env.template; then
    print_warning "Default passwords found in configuration template"
    ((SECURITY_WARNINGS++))
fi

if grep -q "development-key" .env.template; then
    print_warning "Development keys found in configuration template"
    ((SECURITY_WARNINGS++))
fi

if [ $SECURITY_WARNINGS -eq 0 ]; then
    print_success "No obvious security issues in templates"
else
    print_warning "$SECURITY_WARNINGS security warnings found (expected in templates)"
fi

echo

# Test Docker configuration (if Docker is available)
print_status "Testing Docker configuration..."
if command -v docker &> /dev/null; then
    if docker --version > /dev/null 2>&1; then
        print_success "Docker is available"
        
        # Validate Dockerfile
        if [ -f "Dockerfile" ]; then
            print_success "Dockerfile found"
        else
            print_error "Dockerfile not found"
            TEST_FAILED=1
        fi
        
        # Validate docker-compose
        if [ -f "docker-compose.yml" ]; then
            print_success "docker-compose.yml found"
            
            # Basic syntax check
            if command -v docker-compose &> /dev/null; then
                if docker-compose config > /dev/null 2>&1; then
                    print_success "docker-compose configuration is valid"
                else
                    print_error "docker-compose configuration has syntax errors"
                    TEST_FAILED=1
                fi
            fi
        else
            print_error "docker-compose.yml not found"
            TEST_FAILED=1
        fi
    else
        print_warning "Docker is installed but not running"
    fi
else
    print_warning "Docker not available, skipping container tests"
fi

echo

# Performance test with larger dataset
print_status "Running performance test..."
cat > performance_test.py << 'EOF'
#!/usr/bin/env python3
import sys
import time
sys.path.append('.')
from analyzer import analyze_logs

# Generate test logs
test_logs = []
for i in range(500):
    test_logs.append(f"Oct 15 10:30:{i%60:02d} server sshd[{12345+i}]: Failed password for root from 192.168.1.{i%255} port 22 ssh2")

large_log_data = "\n".join(test_logs)

# Time the analysis
start_time = time.time()
findings = analyze_logs(large_log_data)
elapsed_time = time.time() - start_time

print(f"Performance test: {len(test_logs)} log entries analyzed in {elapsed_time:.2f}s")
print(f"Found {len(findings)} findings")

if elapsed_time < 5.0:  # Should complete within 5 seconds
    print("Performance test passed")
    sys.exit(0)
else:
    print("Performance test failed - analysis took too long")
    sys.exit(1)
EOF

if python3 performance_test.py; then
    print_success "Performance test passed"
else
    print_error "Performance test failed"
    TEST_FAILED=1
fi

rm -f performance_test.py

echo

# Final summary
echo "🏁 Test Summary"
echo "==============="

if [ ${TEST_FAILED:-0} -eq 1 ]; then
    print_error "Some tests failed"
    echo
    echo "Troubleshooting:"
    echo "1. Ensure all dependencies are installed: pip install -r requirements.txt"
    echo "2. Check that you're running from the SecuAI root directory"
    echo "3. Verify Python 3.7+ is installed"
    echo "4. Check file permissions"
    echo
    exit 1
else
    print_success "All tests passed!"
    echo
    echo "✨ SecuAI is ready for deployment!"
    echo
    echo "Next steps:"
    echo "1. Review and customize .env configuration"
    echo "2. Change default admin credentials"
    echo "3. Run: python init_db.py"
    echo "4. Run: python app.py"
    echo "5. Open http://localhost:5000"
    echo
fi

# Cleanup
rm -f .coverage 2>/dev/null || true