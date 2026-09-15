# 🛡️ SecureLens AI — Cybersecurity Scanning & Intelligence Platform

SecureLens AI is an automated cybersecurity auditing platform. Users enter a target URL to perform concurrent security checks (SSL/TLS, HTTP Security Headers, WHOIS domain registration, DNS posture), calculate a composite risk score (0–100%), inspect categorized vulnerabilities, and consult an AI Security Analyst powered by Groq (Llama 3.1).

---

## 🎨 Theme & UI Specification

- **Background**: Near-black (`#0d0f1a`)
- **Surface / Cards**: `#141727`, `#1b1f34`
- **Accent**: Violet (`#8b7bff`)
- **Severity Colors**: Critical (`#ef4444`), High (`#f59e0b`), Medium (`#eab308`), Low (`#22c55e`)
- **Typography**: Space Grotesk (UI interface), IBM Plex Mono (scan telemetry & data)

---

## 🚀 Key Features

1. **Operator Login Gate**: Secure authentication interface issuing JWT tokens.
2. **URL Scan Bar**: Trigger concurrent scanners (SSL, HTTP Headers, WHOIS, DNS) for any domain or URL.
3. **Risk Overview Gauge**: Animated 0–100% circular score meter and real-time finding counters.
4. **Vulnerability List**: Severity badges, finding titles, affected assets, and status indicators.
5. **Scan History Sidebar**: Persistent scan log allowing quick switching between past audits.
6. **Groq AI Analyst Chatbot**: Embedded assistant powered by Llama 3.1 for context-aware remediation advice.
7. **Executive PDF Exporter**: Clean downloadable PDF security assessment report built with ReportLab.

---

## 📁 Project Structure

```
Seclens Ai/
├── frontend/
│   ├── index.html              # Operator login gate
│   ├── dashboard.html          # Main application shell
│   ├── css/
│   │   ├── theme.css           # Design tokens & color variables
│   │   └── layout.css          # Layout, gauge, table & chat styles
│   ├── js/
│   │   ├── auth.js             # Session token & auth logic
│   │   ├── scan.js             # URL scan bar execution
│   │   ├── history.js          # Sidebar history & click-to-load
│   │   ├── vulnerabilities.js  # Risk gauge & finding table renderer
│   │   └── chatbot.js          # Groq AI Analyst chat panel
│   └── assets/
│       └── logo.svg            # Brand mark SVG
│
├── backend/
│   ├── main.py                 # FastAPI application entrypoint
│   ├── auth/
│   │   └── auth.py             # Login & JWT token logic
│   ├── routers/
│   │   ├── scan.py             # POST /scan, GET /scan/history
│   │   ├── ai.py               # POST /chat, GET /chat/{scan_id}
│   │   └── reports.py          # GET /reports/{scan_id}/pdf
│   ├── scanners/
│   │   ├── ssl_checker.py      # SSL certificate inspector
│   │   ├── header_checker.py   # HTTP security headers inspector
│   │   ├── whois_checker.py    # WHOIS domain registrar inspector
│   │   ├── dns_checker.py      # DNS & email security posture (SPF/DMARC)
│   │   └── risk_engine.py      # Composite risk scoring engine
│   ├── ai/
│   │   └── groq_service.py     # Groq Llama 3.1 integration
│   ├── database/
│   │   ├── db.py               # MongoDB Atlas (motor) with SQLite fallback
│   │   └── models.py           # Pydantic data schemas
│   ├── reports/
│   │   └── pdf_generator.py    # ReportLab PDF report builder
│   ├── requirements.txt
│   ├── render.yaml
│   └── .env.example
│
└── README.md
```

---

## ⚙️ Environment Configuration (`backend/.env`)

```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/securelens?retryWrites=true&w=majority
GROQ_API_KEY=gsk_your_groq_api_key_here
JWT_SECRET=securelens_super_secret_jwt_key_2026
OPERATOR_ID=operator
OPERATOR_PASSPHRASE=securelens2026
PORT=8000
```

---

## 🛠️ Quickstart & Local Setup

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Launch FastAPI Application Server

```bash
python main.py
# or
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open in Browser

Navigate to **`http://127.0.0.1:8000`** in your browser.

- **Default Operator Credentials**:
  - **Operator ID**: `operator`
  - **Passphrase**: `securelens2026`

---

## ☁️ Production Deployment

- **Backend (Render)**: Connect repository, set build command to `pip install -r requirements.txt`, start command to `uvicorn main:app --host 0.0.0.0 --port $PORT`, and set environment variables `MONGODB_URI`, `GROQ_API_KEY`, `JWT_SECRET`.
- **Database (MongoDB Atlas)**: Deploy M0 Free Cluster, create a database user, whitelist Render IP (`0.0.0.0/0`), and set `MONGODB_URI`.
- **Frontend (Netlify / Vercel)**: Publish the `frontend/` directory directly as static files, setting backend API proxy rules if hosted on separate domains.
