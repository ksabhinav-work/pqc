# Crypto Scanner — PQC Assessment Tool

Live TLS inspection + post-quantum cryptography rating.

---

## Architecture

```
GitHub Pages (frontend/index.html)
        ↓  fetch /scan?domain=example.com
Render.com (backend/app.py — Flask + gunicorn)
        ↓  raw TCP + TLS + cert parsing
Target server
```

---

## Step 1 — Deploy the backend to Render

1. Push this repo to GitHub (or just the `backend/` folder as its own repo)

2. Go to [render.com](https://render.com) → **New → Web Service**

3. Connect your GitHub repo

4. Set these fields:
   - **Name**: `crypto-scanner-api`
   - **Runtime**: `Python`
   - **Build command**: `pip install -r requirements.txt`
   - **Start command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 30`
   - **Root directory**: `backend` (if using this full repo)

5. Click **Deploy**. Wait ~2 minutes.

6. Note your URL: `https://crypto-scanner-api.onrender.com`

7. Test it:
   ```
   https://crypto-scanner-api.onrender.com/health
   https://crypto-scanner-api.onrender.com/scan?domain=youtube.com
   ```

---

## Step 2 — Update the frontend

1. Open `frontend/index.html`

2. Find this line near the top of the `<script>` block:
   ```js
   const API_BASE = "https://crypto-scanner-api.onrender.com";
   ```

3. Replace the URL with your actual Render URL

---

## Step 3 — Deploy frontend to GitHub Pages

1. Push the `frontend/` folder to a GitHub repo
   (or put `index.html` in the root of any GitHub repo)

2. Go to repo **Settings → Pages**

3. Set source to **Deploy from a branch → main → / (root)**

4. Your site will be live at:
   `https://<your-username>.github.io/<repo-name>/`

---

## Local development

```bash
# Backend
cd backend
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000

# Test
curl "http://localhost:5000/scan?domain=youtube.com"

# Frontend
# Just open frontend/index.html in a browser
# Change API_BASE to http://localhost:5000 for local testing
```

---

## Notes

- **Rate limit**: 10 scans per minute per IP (in-memory, resets on restart)
- **Render free tier**: spins down after 15 min idle — first scan may take ~30s to wake up
- **Outbound TCP**: Render allows outbound connections on any port — TLS probing works
- **CORS**: Flask-CORS is configured to allow all origins (GitHub Pages can call the API)
