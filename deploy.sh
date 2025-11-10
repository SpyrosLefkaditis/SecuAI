#!/bin/bash
# SecuAI Cloud Run Deployment Script

echo "🚀 SecuAI Cloud Run Deployment"
echo "================================"
echo ""

# Step 1: Authenticate with Google Cloud
echo "Step 1: Authenticating with Google Cloud..."
gcloud auth login

# Step 2: Set project (you'll need to create one first or use existing)
echo ""
echo "Step 2: Setting up Google Cloud project..."
echo "If you don't have a project, create one at: https://console.cloud.google.com/projectcreate"
read -p "Enter your Google Cloud Project ID: " PROJECT_ID
gcloud config set project $PROJECT_ID

# Step 3: Enable required APIs
echo ""
echo "Step 3: Enabling required APIs..."
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# Step 4: Set environment variables
echo ""
echo "Step 4: Setting environment variables..."
read -p "Enter your Gemini API Key: " GEMINI_API_KEY
echo "GEMINI_API_KEY=$GEMINI_API_KEY" > .env.cloud

# Step 5: Deploy to Cloud Run
echo ""
echo "Step 5: Deploying to Cloud Run..."
gcloud run deploy secuai \
  --source . \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY=$GEMINI_API_KEY \
  --memory 1Gi \
  --cpu 1 \
  --timeout 300 \
  --max-instances 3

echo ""
echo "✅ Deployment complete!"
echo ""
echo "Your SecuAI app should now be available at the URL shown above."
echo "Add this URL to your Devpost submission!"
