# SecuAI - Log & Network Anomaly Detection System

🚀 **Hackathon MVP** - A complete security monitoring solution with rule-based detection and optional AI enrichment.

![SecuAI Dashboard](https://img.shields.io/badge/Status-Hackathon%20Ready-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-red)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)

## 🎯 Project Overview

SecuAI is a comprehensive log and network anomaly detection system designed for hackathons and rapid prototyping. It provides:

- **Real-time log analysis** with rule-based threat detection
- **Web dashboard** for monitoring and management
- **API endpoints** for integration and automation  
- **Simulated blocking** with safety controls
- **Honeypot integration** for threat intelligence
- **Docker support** for easy deployment
- **Cloud Run ready** for scalable deployment

## ⚡ Quick Start

### Prerequisites (Debian/Ubuntu)

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

# Optional: Docker for containerized deployment
sudo apt install -y docker.io docker-compose
sudo usermod -aG docker $USER  # Re-login after this
```

### 1. Clone and Setup

```bash
git clone <your-repo-url>
cd SecuAI

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Initialize Database

```bash
# Create and seed database with sample data
python init_db.py
```

**🚨 IMPORTANT**: Default admin credentials are:
- **Email**: `admin@secai.local`
- **Password**: `ChangeMe123!`
- **⚠️ CHANGE THESE IMMEDIATELY IN PRODUCTION!**

### 3. Run the Application

```bash
# Development mode
python app.py

# The application will be available at:
# 🌐 Dashboard: http://localhost:5000
# 🔧 Admin Panel: http://localhost:5000/admin
```

### 4. Test the System

```bash
# Run all tests
python run_tests.py

# Or with pytest directly
pytest tests/ -v
```

## 🐳 Docker Deployment

### Local Development

```bash
# Build and run with Docker Compose
docker-compose up --build

# Access the application at http://localhost:5000
```

### Production Docker Build

```bash
# Build production image
docker build -t secuai:latest .

# Run container
docker run -d \
  --name secuai \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  -e SECRET_KEY="your-production-secret-key" \
  -e ADMIN_PASSWORD="your-secure-password" \
  secuai:latest
```

## 🚀 Cloud Run Deployment

### Prerequisites

```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
gcloud init
gcloud auth configure-docker
```

### Deploy to Cloud Run

```bash
# Set your project ID
export PROJECT_ID="your-gcp-project-id"

# Build and push to Container Registry
docker build -t gcr.io/$PROJECT_ID/secuai:latest .
docker push gcr.io/$PROJECT_ID/secuai:latest

# Deploy to Cloud Run
gcloud run deploy secuai \
  --image gcr.io/$PROJECT_ID/secuai:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars="SIMULATE_BLOCKS=true,SECRET_KEY=your-secret-key"
```

**⚠️ Cloud Run Security Note**: Real IP blocking requires external agents or Cloud Firewall API integration. Cloud Run instances operate in simulated mode by default.

## 📊 Features Overview

### 🔍 Detection Capabilities

- **Failed Login Detection**: SSH, FTP, web application login failures
- **Port Scan Detection**: Nmap, SYN floods, reconnaissance activities
- **Web Application Probing**: Admin panel scanning, config file access
- **Suricata Integration**: EVE JSON format parsing
- **SQL Injection Detection**: Database attack pattern recognition
- **Honeypot Integration**: Threat intelligence from honeypot networks

### 🛡️ Security Features

- **Simulated Blocking**: Safe testing environment (default mode)
- **IP Whitelisting**: Protect trusted networks and IPs
- **Admin Authentication**: Secure admin panel access
- **Audit Logging**: Complete activity tracking
- **Safety Controls**: Multiple layers of protection against accidental blocks

### 🌐 Web Interface

- **Real-time Dashboard**: Live threat monitoring
- **Interactive Analytics**: Confidence scoring and threat categorization
- **File Upload**: Drag-and-drop log analysis
- **API Testing**: Built-in API demonstration tools
- **Responsive Design**: Mobile-friendly Bootstrap interface

## 🔧 Configuration

### Environment Variables

Create a `.env` file from the template:

```bash
cp env.template .env
# Edit .env with your settings
```

Key configuration options:

```bash
# Security (CHANGE THESE!)
SECRET_KEY=your-secret-key-here
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=YourSecurePassword123!

# Blocking behavior
SIMULATE_BLOCKS=true          # Keep true for safety
REAL_BLOCKING_ENABLED=false   # Enable only in controlled environments
CONFIDENCE_THRESHOLD=0.7      # Minimum confidence for alerts

# ML Enhancement (optional)
ML_ENABLED=false
ML_ENDPOINT=https://your-ml-service.com/analyze
```

### Database Configuration

SecuAI uses SQLite by default for simplicity. For production, consider PostgreSQL:

```bash
# PostgreSQL example
DATABASE_URL=postgresql://user:password@localhost/secuai
```

## 📡 API Documentation

### Analysis API

```bash
# Analyze log text
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_text": "Oct 15 10:30:15 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2"}'

# Response
{
  "status": "success",
  "findings": [
    {
      "ip": "192.168.1.100",
      "reason": "Multiple failed login attempts (4 attempts)",
      "confidence": 0.8,
      "ml_insights": {
        "threat_level": "high",
        "explanation": "Pattern consistent with automated attack tools"
      }
    }
  ],
  "count": 1
}
```

### Blocking API

```bash
# Recommend blocking an IP
curl -X POST http://localhost:5000/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "action": "recommend"}'

# Approve and simulate block
curl -X POST http://localhost:5000/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "action": "approve"}'
```

### Honeypot Feed API

```bash
# Ingest threat intelligence
curl -X POST http://localhost:5000/api/honeypot \
  -H "Content-Type: application/json" \
  -d '{
    "ips": [
      {
        "ip": "203.0.113.45",
        "attacks": ["web_scanning", "sql_injection"],
        "severity": "high"
      }
    ]
  }'
```

## 🧪 Testing

### Run All Tests

```bash
# Comprehensive test suite
python run_tests.py

# Individual test modules
pytest tests/test_analyzer.py -v      # Analysis engine tests
pytest tests/test_web.py -v           # Web application tests  
pytest tests/test_blocker.py -v       # Blocking system tests
```

### Test Coverage

```bash
# Install coverage tools
pip install pytest-cov

# Run with coverage report
pytest --cov=. --cov-report=html
# Open coverage_html/index.html in browser
```

### Manual Testing

Use the built-in test data:

```bash
# Test with sample logs
curl -X POST http://localhost:5000/upload \
  -F "logfile=@sample_auth.log"

# Load honeypot feed
curl -X POST http://localhost:5000/api/honeypot \
  -H "Content-Type: application/json" \
  -d @honeypot_feed.json
```

## 🔒 Security Considerations

### 🚨 CRITICAL SECURITY WARNINGS

1. **Change Default Credentials**: The default admin password `ChangeMe123!` MUST be changed immediately
2. **HTTPS in Production**: Always use HTTPS in production environments
3. **Firewall Rules**: Real blocking can permanently affect network access
4. **Database Security**: Use strong database passwords and restrict access
5. **API Rate Limiting**: Implement rate limiting for production APIs

### Real Blocking Safety

Real IP blocking is **DISABLED by default** for safety. To enable:

1. **Test Environment Only**: Never enable on production networks without testing
2. **Network Isolation**: Use isolated test networks
3. **Backup Access**: Ensure alternative access methods
4. **Whitelist Critical IPs**: Add your management IPs to whitelist first

```bash
# Enable real blocking (DANGEROUS!)
export REAL_BLOCKING_ENABLED=true
export SIMULATE_BLOCKS=false
export ALLOW_PRIVATE_BLOCKING=true  # Only for testing

# Run with elevated privileges (required for iptables)
sudo python app.py
```

### Cloud Deployment Security

For Cloud Run and production deployments:

- Use Google Secret Manager for sensitive configuration
- Enable Cloud Armor for DDoS protection
- Use Cloud Firewall for real IP blocking instead of host-level rules
- Implement proper IAM and service accounts

## 🎨 Frontend Options

### Default: HTML + Bootstrap + jQuery

The default frontend is production-ready and includes:
- Real-time dashboard updates
- Interactive threat analysis
- File upload interface
- API testing tools

### Modern UI Features

The Flask application includes a modern shadcn-inspired UI with:
- **Dark/Light Theme Toggle** - Click the theme button in the top-right corner
- **Modern Design System** - Clean, responsive interface with CSS custom properties
- **Interactive Components** - Real-time updates and smooth animations
- **Mobile Responsive** - Works great on all devices

**Theme Management**:
- Automatic theme persistence via localStorage
- System theme detection
- Smooth transitions between themes
4. Modify API calls to use the new endpoints

## 📈 Monitoring and Alerting

### Built-in Monitoring

- **Audit Logs**: All security actions are logged
- **System Status**: Component health monitoring
- **Performance Metrics**: Request timing and error rates

### External Integration

Connect to external monitoring systems:

```python
# Example: Send alerts to Slack
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/..."

# Example: Export metrics to Prometheus
PROMETHEUS_ENABLED = True
PROMETHEUS_PORT = 8000
```

## 🤝 Contributing

This is a hackathon MVP project. For improvements:

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open Pull Request**

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run in development mode with auto-reload
export FLASK_ENV=development
export DEBUG=True
python app.py
```

## 📝 License

This project is created for hackathon purposes. Please ensure compliance with all applicable laws and regulations when deploying security monitoring systems.

## 🆘 Troubleshooting

### Common Issues

**Database Issues**
```bash
# Reset database
rm secuai.db
python init_db.py
```

**Permission Errors**
```bash
# Fix file permissions
chmod +x run_tests.py
chmod +x init_db.py
```

**Docker Issues**
```bash
# Clean rebuild
docker-compose down
docker-compose build --no-cache
docker-compose up
```

**Port Already in Use**
```bash
# Find and kill process using port 5000
sudo lsof -ti:5000 | xargs kill -9

# Or use different port
export PORT=8080
python app.py
```

### Getting Help

1. **Check logs**: Application logs are in `secuai.log`
2. **Run tests**: `python run_tests.py` to verify setup
3. **Check configuration**: Verify `.env` file settings
4. **Docker logs**: `docker-compose logs` for container issues

## 🎖️ Credits

**SecuAI** - Built for hackathons and rapid security prototyping

- **Backend**: Flask, SQLAlchemy, Python 3.11+
- **Frontend**: Bootstrap 5, jQuery, HTML5
- **Database**: SQLite (development), PostgreSQL (production)
- **Deployment**: Docker, Google Cloud Run
- **Testing**: pytest, coverage
- **Security**: Rule-based detection + ML enrichment

---

**⚠️ REMINDER**: This is a hackathon MVP. Always test thoroughly before production use and ensure compliance with your organization's security policies.

**🚀 Ready to hack? Start with `python init_db.py` and visit http://localhost:5000**