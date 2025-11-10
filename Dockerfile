# SecuAI - AI-Powered Security Monitoring Platform
# Optimized for Google Cloud Run

# Use official Python runtime as base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/uploads /app/instance /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV PORT=8080

# Initialize database
RUN python init_db.py || true

# Cloud Run uses PORT environment variable (default 8080)
EXPOSE 8080

# Start application with gunicorn for production
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app

# Alternative: Use Flask development server (not recommended for production)
# CMD python app.py

# Build and Deploy Instructions:
# 
# 1. Build locally:
#    docker build -t secuai:latest .
#
# 2. Test locally:
#    docker run -p 8080:8080 -e PORT=8080 secuai:latest
#
# 3. Build for Cloud Run:
#    gcloud builds submit --tag gcr.io/PROJECT-ID/secuai
#
# 4. Deploy to Cloud Run:
#    gcloud run deploy secuai \
#      --image gcr.io/PROJECT-ID/secuai \
#      --platform managed \
#      --region us-central1 \
#      --allow-unauthenticated \
#      --set-env-vars="GEMINI_API_KEY=your-key-here"