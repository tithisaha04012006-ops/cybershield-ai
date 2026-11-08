# 🚀 CyberShield AI – Live Deployment Guide
### How to Deploy & Share Your Public HTTPS URL with Your Hackathon Team

This project is fully configured for zero-friction cloud deployment on **Render** (or any cloud container platform like Railway/Heroku).

---

## 📋 What Was Prepared for Production

1. **`Procfile`**: Configured to launch production WSGI server (`web: gunicorn app:app`).
2. **`render.yaml`**: Pre-configured Blueprint for 1-click Render web service deployment.
3. **`requirements.txt`**: Added `gunicorn>=21.2.0` alongside `Flask`.
4. **Environment Variables**:
   - `PORT`: Dynamically read from Render environment.
   - `SECRET_KEY`: Automatically generated or securely loaded from environment.
   - `DATABASE_PATH`: Configurable path for SQLite storage (defaults to `./cybershield.db`).
5. **Database Initialization**: `database.init_db()` automatically provisions the SQLite tables and seeds realistic starter threat scans on first boot, so the dashboard is populated immediately.

---

## ⚡ 3-Step Deployment Walkthrough

### Step 1: Create an Empty GitHub Repository
1. Open your browser and go to: [https://github.com/new](https://github.com/new)
2. Repository name: `cybershield-ai`
3. Description: `AI-Powered Web Threat Detection & Digital Trust Intelligence - HackMatrix '26`
4. Set to **Public** (recommended so Render can connect for free).
5. **Do NOT check** "Initialize with README" or ".gitignore" (we have already created and committed them).
6. Click **Create repository**.

---

### Step 2: Push Code to GitHub
Run the automated helper script in your project folder, or run these 2 commands in your VS Code terminal:

```bash
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/cybershield-ai.git
git push -u origin main
```
*(Replace `<YOUR_GITHUB_USERNAME>` with your actual GitHub username, e.g., `tithisaha`).*

> **Note on Authorization:** If this is your first time pushing, Windows Credential Manager will open a small GitHub browser sign-in window. Simply click **Authorize** or sign in.

---

### Step 3: Connect to Render (Free 24/7 Hosting)
1. Go to: [https://dashboard.render.com/](https://dashboard.render.com/)
2. Sign in with your **GitHub** account.
3. Click the **New +** button in the top right and select **Web Service**.
4. Click **Connect a repository** and select **`cybershield-ai`**.
5. Render will automatically detect the settings:
   - **Name:** `cybershield-ai`
   - **Region:** Any (e.g., Singapore, Frankfurt, Oregon)
   - **Branch:** `main`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
   - **Instance Type:** `Free`
6. Click **Deploy Web Service** at the bottom.

---

## 🌐 Your Live Public HTTPS Link

Render will build the project in ~60 seconds and display your permanent live HTTPS link at the top left of the dashboard:

```
https://cybershield-ai-xxxx.onrender.com
```

### Pages to Share with Your Team:
- **Main Threat Scanner:** `https://<your-app-name>.onrender.com/`
- **Security Operations Dashboard:** `https://<your-app-name>.onrender.com/dashboard`
- **Live JSON API:** `https://<your-app-name>.onrender.com/api/stats`

Anyone on your 4-member hackathon team can now open this link on their smartphones, laptops, or tablets from anywhere in the world without installing anything!

---

## 🔒 Security & Persistence Details
- **No Secrets in Repo:** No hardcoded passwords, tokens, or private keys exist in the repository.
- **HTTPS Enforcement:** Render automatically provides and renews a free TLS/SSL certificate.
- **SQLite Database:** The database initializes automatically on boot. For persistent storage across cold restarts on Render's free tier, you can optionally attach a free Render Disk at `/data` and set the environment variable `DATABASE_PATH=/data/cybershield.db` in Render's "Environment" tab.
