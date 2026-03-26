# Password Strength Analyzer — v2.1
## Professional Cybersecurity Tool

A production-ready, security-hardened web application that analyzes password strength in real time, detects patterns and breaches, estimates crack times, and generates strong passwords.

---

## Why No Authentication or Database?

This tool is intentionally stateless and database-free — by design, not by oversight.

- Passwords are analyzed in memory only and immediately discarded after each request
- There are no user accounts, sessions, or login flows needed
- A database would mean storing passwords (even temporarily), creating unnecessary attack surface
- No authentication means no credentials to steal, no session tokens to hijack
- This is the correct security architecture for an analysis tool — GDPR compliant by default

---

## Project Structure

```
password-strength-analyzer/
├── app.py                    Flask backend (all analysis logic)
├── requirements.txt          Python dependencies
├── Dockerfile                Multi-stage secure container build
├── docker-compose.yml        Full stack: Nginx + Flask + Redis
├── README.md
│
├── templates/
│   ├── index.html            Main analyzer UI (Jinja2 template)
│   └── docs.html             API documentation page
│
├── static/
│   ├── css/
│   │   ├── style.css         All UI styles
│   │   └── docs.css          API docs page styles
│   └── js/
│       └── analyzer.js       Frontend JavaScript
│
├── tests/
│   └── test_analyzer.py      194-assertion test suite (pytest)
│
└── nginx/
    └── nginx.conf            Production Nginx reverse proxy config
```

---

## Quick Start

```bash
# 1. Extract the project folder
cd password-strength-analyzer

# 2. Create virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac / Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py

# 5. Open in browser
# http://127.0.0.1:5000
```

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v
pytest tests/ -v --cov=app --cov-report=term-missing
```

---

## Production Deployment (Docker)

```bash
export SECRET_KEY=your-very-long-random-secret-key
docker-compose up -d --build
# App available on port 80 via Nginx
```

---

## Environment Variables

SECRET_KEY   — Flask secret key. Must set in production.
FLASK_DEBUG  — false by default. Never set true in production.
REDIS_URL    — Redis URI for rate limiting. Default: memory://

---

## API Endpoints

GET  /         Main analyzer UI
GET  /docs     API documentation
POST /analyze  Analyze a password
POST /report   Download security report (.txt)

POST /analyze body:
{
  "password": "your_password",
  "check_hibp": false
}

---

## Features

- Real-time strength scoring (0-100) on every keystroke
- Entropy calculation in bits
- Pattern detection: keyboard walks, repeats, sequences, dictionary words, years
- Common password check including trivial variants (Password1! etc.)
- zxcvbn integration (install separately: pip install zxcvbn)
- HaveIBeenPwned breach check using k-anonymity
- Crack time estimates: online throttled, online unthrottled, GPU, botnet
- Cryptographically secure password generator (Web Crypto API)
- Downloadable security report — password never included in file
- Full API documentation at /docs
- All security headers: CSP, X-Frame-Options, Referrer-Policy
- Rate limiting: 30 req/60s per IP

---

## Tech Stack

Backend:        Python 3.12 + Flask 3.0
Analysis:       Custom engine + zxcvbn (optional)
Breach check:   HaveIBeenPwned API (k-anonymity)
Rate limiting:  Flask-Limiter + Redis (or in-memory fallback)
Frontend:       HTML5 + CSS3 + Vanilla JS
Production:     Gunicorn + Nginx
Container:      Docker + docker-compose
Tests:          pytest (194 assertions, 0 failures)
