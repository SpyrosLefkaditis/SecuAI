# SecuAI Makefile
# Convenient commands for development and deployment

.PHONY: help install setup run test clean docker deploy lint format

# Default target
help:
	@echo "🚀 SecuAI - Security Monitoring System"
	@echo "Available commands:"
	@echo "  setup     - Complete project setup (install + database)"
	@echo "  install   - Install Python dependencies"
	@echo "  run       - Run the development server"
	@echo "  test      - Run all tests"
	@echo "  clean     - Clean temporary files and reset database"
	@echo "  docker    - Build and run with Docker"
	@echo "  deploy    - Deploy to Google Cloud Run"
	@echo "  lint      - Run code linting"
	@echo "  format    - Format code with black"
	@echo "  demo      - Run with demo data"

# Project setup
setup: install init-db
	@echo "✅ SecuAI setup complete!"
	@echo "🌐 Run 'make run' to start the server"
	@echo "🔧 Admin login: admin@secai.local / ChangeMe123!"

install:
	@echo "📦 Installing Python dependencies..."
	pip install -r requirements.txt

init-db:
	@echo "🗄️  Initializing database..."
	python init_db.py

# Development
run:
	@echo "🚀 Starting SecuAI development server..."
	@echo "🌐 Dashboard: http://localhost:5000"
	@echo "🔧 Admin Panel: http://localhost:5000/admin"
	python app.py

dev:
	@echo "🔧 Starting development server with auto-reload..."
	export FLASK_ENV=development DEBUG=True && python app.py

# Testing
test:
	@echo "🧪 Running SecuAI test suite..."
	python run_tests.py

test-quick:
	@echo "⚡ Running quick tests..."
	pytest tests/ -x -q

test-coverage:
	@echo "📊 Running tests with coverage..."
	pytest --cov=. --cov-report=html --cov-report=term-missing

# Docker
docker:
	@echo "🐳 Building and running with Docker..."
	docker-compose up --build

docker-build:
	@echo "🔨 Building Docker image..."
	docker build -t secuai:latest .

docker-run:
	@echo "🏃 Running Docker container..."
	docker run -d --name secuai -p 5000:5000 secuai:latest

# Cloud deployment
deploy:
	@echo "☁️  Deploying to Google Cloud Run..."
	@if [ -z "$(PROJECT_ID)" ]; then \
		echo "❌ Please set PROJECT_ID environment variable"; \
		exit 1; \
	fi
	docker build -t gcr.io/$(PROJECT_ID)/secuai:latest .
	docker push gcr.io/$(PROJECT_ID)/secuai:latest
	gcloud run deploy secuai \
		--image gcr.io/$(PROJECT_ID)/secuai:latest \
		--platform managed \
		--region us-central1 \
		--allow-unauthenticated \
		--set-env-vars="SIMULATE_BLOCKS=true"

# Code quality
lint:
	@echo "🔍 Running code linting..."
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

format:
	@echo "🎨 Formatting code with black..."
	black . --line-length=127

# Utility commands
clean:
	@echo "🧹 Cleaning temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf coverage_html
	rm -f .coverage

clean-db:
	@echo "🗑️  Resetting database..."
	rm -f secuai.db
	rm -f blocked_ips.txt
	python init_db.py

# Demo and development helpers
demo: clean-db
	@echo "🎬 Setting up demo environment..."
	python init_db.py
	@echo "✅ Demo ready!"
	@echo "📊 Sample data loaded"
	@echo "🌐 Visit http://localhost:5000"
	@echo "🔧 Admin: admin@secuai.local / ChangeMe123!"

logs:
	@echo "📋 Showing application logs..."
	tail -f secuai.log

analyze-sample:
	@echo "🔍 Analyzing sample log file..."
	curl -X POST http://localhost:5000/upload \
		-F "logfile=@sample_auth.log" \
		|| echo "❌ Server not running? Try 'make run'"

load-honeypot:
	@echo "🍯 Loading honeypot feed..."
	curl -X POST http://localhost:5000/api/honeypot \
		-H "Content-Type: application/json" \
		-d @honeypot_feed.json \
		|| echo "❌ Server not running? Try 'make run'"

# Development environment
venv:
	@echo "🐍 Creating Python virtual environment..."
	python3 -m venv venv
	@echo "✅ Virtual environment created"
	@echo "🔧 Activate with: source venv/bin/activate"

requirements:
	@echo "📋 Generating requirements.txt..."
	pip freeze > requirements.txt

# Frontend development (HTML/CSS/JS)
frontend-dev:
	@echo "🎨 Starting Flask development server with modern UI..."
	python3 app.py

frontend-watch:
	@echo "👀 Watching for CSS/JS changes..."
	@echo "💡 Use browser dev tools for live CSS editing"
	@echo "📁 Static files location: static/css/ and static/js/"

# System checks
check-deps:
	@echo "🔍 Checking system dependencies..."
	@command -v python3 >/dev/null 2>&1 || { echo "❌ Python 3 is required"; exit 1; }
	@command -v pip >/dev/null 2>&1 || { echo "❌ pip is required"; exit 1; }
	@echo "✅ System dependencies OK"

check-config:
	@echo "⚙️  Checking configuration..."
	@test -f .env && echo "✅ .env file exists" || echo "⚠️  .env file missing (optional)"
	@test -f secuai.db && echo "✅ Database exists" || echo "ℹ️  Database not initialized"

status:
	@echo "📊 SecuAI Status"
	@echo "=================="
	@make check-deps
	@make check-config
	@echo "🐳 Docker: $$(command -v docker >/dev/null 2>&1 && echo 'Available' || echo 'Not installed')"
	@echo "☁️  gcloud: $$(command -v gcloud >/dev/null 2>&1 && echo 'Available' || echo 'Not installed')"

# Quick start for new users
quickstart:
	@echo "🚀 SecuAI Quick Start"
	@echo "===================="
	@echo "1. Setting up environment..."
	@make check-deps
	@echo "2. Installing dependencies..."
	@make install
	@echo "3. Initializing database..."
	@make init-db
	@echo "4. Running tests..."
	@make test-quick
	@echo ""
	@echo "✅ Setup complete! 🎉"
	@echo ""
	@echo "Next steps:"
	@echo "  🌐 make run          - Start the server"
	@echo "  🧪 make test         - Run full test suite"
	@echo "  🐳 make docker       - Run with Docker"
	@echo "  🎬 make demo         - Load demo data"