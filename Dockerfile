# SecuAI - Log and Network Anomaly Detector
# Multi-stage Dockerfile for production-ready container

# Build stage
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    pkg-config \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN groupadd -r secuai && useradd -r -g secuai secuai

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder stage
COPY --from=builder /root/.local /home/secuai/.local

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p /app/uploads /app/logs && \
    chown -R secuai:secuai /app && \
    chmod +x /app/init_db.py

# Create .env file with safe defaults
RUN echo "SECRET_KEY=change-this-in-production" > .env && \
    echo "ADMIN_EMAIL=admin@secuai.local" >> .env && \
    echo "ADMIN_PASSWORD=ChangeMe123!" >> .env && \
    echo "SIMULATE_BLOCKS=true" >> .env && \
    echo "DEBUG=false" >> .env && \
    echo "ML_ENABLED=false" >> .env && \
    echo "REAL_BLOCKING_ENABLED=false" >> .env && \
    chown secuai:secuai .env

# Update PATH to include user's local bin
ENV PATH=/home/secuai/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Switch to non-root user
USER secuai

# Initialize database on container start
RUN python init_db.py

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Expose port
EXPOSE 5000

# Start application
CMD ["python", "app.py"]

# Build instructions:
# docker build -t secuai:latest .
# docker run -p 5000:5000 secuai:latest

# For development with volume mounting:
# docker run -p 5000:5000 -v $(pwd):/app secuai:latest

# Security notes:
# - Runs as non-root user
# - Minimal base image
# - No sensitive data in image
# - Health checks enabled
# - Real blocking disabled by default