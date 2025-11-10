# SecuAI - Cloud Run Deployment Guide

## Quick Deploy (5 minutes)

### Prerequisites
1. Google Cloud account (get $300 free credits: https://cloud.google.com/free)
2. Gemini API key (from Google AI Studio: https://aistudio.google.com/apikey)

### Deployment Steps

1. **Run the deployment script:**
   ```bash
   ./deploy.sh
   ```

2. **Follow the prompts:**
   - Login to your Google account
   - Enter your Project ID (or create one at console.cloud.google.com)
   - Enter your Gemini API key

3. **Wait for deployment** (~3-5 minutes)

4. **Copy your Cloud Run URL** - it will look like:
   ```
   https://secuai-xxxxxxxxxx-uc.a.run.app
   ```

5. **Add the URL to your Devpost submission!**

---

## Manual Deployment (if script fails)

### 1. Authenticate and configure
```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

### 2. Enable APIs
```bash
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

### 3. Deploy
```bash
gcloud run deploy secuai \
  --source . \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY=YOUR_API_KEY \
  --memory 1Gi \
  --timeout 300
```

---

## Testing Your Deployment

1. Visit your Cloud Run URL
2. The dashboard should load with demo data
3. Check the Alerts page to see AI-powered threat analysis
4. Verify firewall rules are displaying

---

## Troubleshooting

**Database not initializing:**
- Cloud Run creates a new SQLite database on each deployment
- The app automatically initializes the database on startup

**AI analysis not working:**
- Verify your GEMINI_API_KEY environment variable is set
- Check logs: `gcloud run logs read secuai --region us-central1`

**502 Bad Gateway:**
- App might be starting up (takes 10-30 seconds first time)
- Refresh after a minute

---

## Costs

Cloud Run pricing:
- **Free tier**: 2 million requests/month, 360,000 GB-seconds/month
- Your demo should cost **$0** within free tier limits
- Only pay for actual usage (requests + compute time)

---

## Clean Up (After Hackathon)

To avoid any charges after the hackathon:

```bash
gcloud run services delete secuai --region us-central1
```
