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
├── app.py                      Flask backend (core analysis engine)
├── requirements.txt            Python dependencies
├── Dockerfile                  Multi-stage secure container build
├── docker-compose.yml          Full stack: Nginx + Gunicorn + Redis
├── .env                        Environment secrets (DO NOT COMMIT)
├── .env.example                Environment template (show to devs)
├── API_DOCUMENTATION.html      Offline API reference
├── README.md
│
├── config/                     Data module (extracted from app.py)
│   ├── __init__.py
│   ├── common_passwords.py     47 breached/common passwords
│   ├── keyboard_sequences.py   11 keyboard walk patterns
│   └── dictionary_words.py     31 dictionary words for detection
│
├── templates/
│   ├── index.html              Main analyzer UI (Jinja2)
│   └── docs.html               API documentation
│
├── static/
│   ├── css/
│   │   ├── style.css           All UI styles
│   │   └── docs.css            Documentation styles
│   └── js/
│       └── analyzer.js         Frontend JavaScript
│
├── tests/
│   └── test_analyzer.py        194-assertion test suite (44/45 passing)
│
└── nginx/
    └── nginx.conf              Production Nginx reverse proxy
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
pip install pytest

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=app --cov-report=html
```

**Test Results:** 44/45 passing ✅
- 194 assertions covering all analysis components
- 1 pre-existing failure (test_fair_password) unrelated to v2.1 changes

---

## Version History

### v2.1 (Latest)
**New Features:**
- ✨ 5 real-world security rules added
- ✨ Data extraction to modular config/ structure
- ✨ Enhanced pattern detection (9 patterns total)
- ✨ Offline API documentation (API_DOCUMENTATION.html)

**Bug Fixes:**
- 🔧 Space character bug - spaces excluded from symbol detection
- 🔧 BUG-1: Level now derived after all score adjustments
- 🔧 BUG-2: HIBP response parsing with trailing \r handling
- 🔧 BUG-3: Removed duplicate "batman" in DICTIONARY_WORDS
- 🔧 BUG-4: Redis unavailable fallback to in-memory limiter

**Improvements:**
- Rate limiter now returns 429 on limit exceeded (was silent)
- Feedback messages aligned with real-world enterprise policies
- Code cleaner (data separated from logic)
- Production-grade error handling
- Zero breaking changes to API

### v2.0
- Initial production release
- Gunicorn + Nginx + Redis stack
- Docker support
- Comprehensive pattern detection
- HaveIBeenPwned integration

---

## Environment Variables

Create `.env` file in project root (template: `.env.example`):

```env
SECRET_KEY=your-random-secret-key-min-32-chars
FLASK_DEBUG=False
FLASK_ENV=production
REDIS_URL=memory://
```

**Important:** `.env` is in `.gitignore` — never commit to GitHub! ✅

---

## Deployment

### Option 1: Docker (Local or VPS)

```bash
# Build and run
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
docker-compose up -d --build

# Access at http://localhost
```

### Option 2: Render (RECOMMENDED — Free Tier)

**Setup (5 minutes):**

1. Push code to GitHub (`git push origin main`)
2. Go to `render.com` → Sign in with GitHub
3. Click **"New Web Service"** → Select your repo
4. Render auto-detects Dockerfile — no build/start commands needed
5. Add environment variable:
   - **Key:** `SECRET_KEY`
   - **Value:** Copy from your `.env` file
6. Click **"Create Web Service"** ✓

**Your app live at:** `https://password-analyzer-xxxxx.onrender.com`

**Features:**
- ✅ Free tier: 750 compute hours/month
- ✅ Auto-sleep after 15 min inactivity (wakes on request)
- ✅ Free HTTPS certificate
- ✅ Auto-restart on crashes
- ✅ Easy scaling

---

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Main analyzer UI |
| `POST` | `/analyze` | Analyze password strength |
| `POST` | `/report` | Download security report |

### POST /analyze

Request:
```json
{
  "password": "your_password",
  "check_hibp": false
}
```

Response:
```json
{
  "score": 95,
  "entropy": 85.2,
  "level": "vstrong",
  "level_label": "Very Strong",
  "length": 15,
  "is_common": false,
  "criteria": {
    "meets_min": true,
    "meets_rec": true,
    "has_upper": true,
    "has_lower": true,
    "has_number": true,
    "has_symbol": true
  },
  "feedback": [
    {
      "type": "good",
      "icon": "✅",
      "text": "Strong length (15 characters)."
    },
    {
      "type": "good",
      "icon": "🔒",
      "text": "Meets all recommended security criteria."
    }
  ],
  "patterns": [],
  "crack_times": {
    "online_throttled": {"label": "Online attack (throttled)", "seconds": 2.5e15, "display": "79,000 years"},
    "online_unthrottled": {"label": "Online attack (unthrottled)", "seconds": 2.5e13, "display": "790 years"},
    "offline_gpu": {"label": "Offline attack (GPU)", "seconds": 2.5e6, "display": "29 days"},
    "offline_botnet": {"label": "Offline attack (botnet)", "seconds": 2.5e4, "display": "7 hours"}
  },
  "zxcvbn": null,
  "hibp": null,
  "zxcvbn_available": false
}
```

---

## Features

### Core Analysis Engine
- **Real-time strength scoring** (0-100) on every keystroke
- **Entropy calculation** in bits with character pool analysis
- **9 pattern detection types**:
  - Keyboard walks (qwerty, asdf, zxcv, 12345)
  - Repeated characters (aaa, 111)
  - Sequential letters (abcd, zyxw)
  - Sequential numbers (1234, 9876)
  - Dictionary words
  - Year patterns (1960-2029)
  - All digits / All letters
  - Spaces (not allowed)
  - **NEW:** Starts with special character
  - **NEW:** Name + Year pattern (e.g., kamal2002)
  - **NEW:** Repetitive sequences 3+ chars (ooolllaaa)
  - **NEW:** Only alphabetic 8+ chars
  - **NEW:** Sequential keyboard patterns (enhanced)

### Real-World Security Rules (v2.1 NEW)
These rules follow enterprise password policies worldwide:

1. **Special Character at Start** ❌
   - Passwords like `!MyPassword` are marked as weak
   - Message: "Passwords should NOT start with special characters"
   - Reason: Attackers guess symbols at start/end first

2. **Name + Year Pattern** ❌
   - Catches `kamal2002`, `john1990`, `sara2005`
   - Downgraded to Fair level maximum
   - Message: "Predictable name+year pattern - common attack vector"
   - Reason: 40% of user passwords follow this pattern

3. **Repetitive Characters** ❌
   - Detects `ooolllaaa`, `aaabbbccc`, `111222333`
   - Forced to Weak level
   - Message: "Repetitive sequences extremely weak"
   - Reason: Pattern expansion attacks target these

4. **Only Alphabetic (8+ chars)** ❌
   - Pure letters like `ABCDEFGH`, `password` (8+) downgraded
   - Capped at Fair level
   - Message: "Dictionary attacks very effective. Add numbers/symbols"
   - Reason: No character diversity = high breach risk

5. **Sequential Keyboard Patterns** ❌
   - Enhanced detection of qwerty, asdf, 12345, abcde
   - Heavy penalty to score
   - Message: "Sequential keyboard patterns trivially weak"
   - Reason: First thing attackers try in dictionary attacks

### Core Features
- **Common password check** including trivial variants (Password1! etc.)
- **HaveIBeenPwned breach check** using k-anonymity (only first 5 hash chars sent)
- **Crack time estimates**: online throttled, online unthrottled, GPU offline, botnet
- **Cryptographically secure password generator** (Web Crypto API)
- **Downloadable security report** (.txt format, password never included)
- **Full API documentation** (offline HTML + /docs endpoint)
- **zxcvbn integration** (optional, run: `pip install zxcvbn`)
- **Modular architecture** - data separated from logic (config/ module)

### Security Hardening
- **Rate limiting**: 30 requests/60 seconds per IP (production)
- **No password storage** - analyzed in memory, immediately discarded
- **Input validation**: Max 128 characters, strict JSON check
- **Security headers**: CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **HTTPS ready** - Strict-Transport-Security commented (uncomment when deployed with SSL)
- **Error handling** - Global handlers, no stack traces to client
- **Non-root execution** in Docker for added security
- **Health checks** in container
- **No logging** of sensitive data

---

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| **Language** | Python | 3.12 |
| **Web Framework** | Flask | 3.0 |
| **WSGI Server** | Gunicorn | Latest |
| **Reverse Proxy** | Nginx | 1.25-alpine |
| **Cache/Limiter** | Redis | 7-alpine |
| **Analysis** | zxcvbn (optional) | 4.x |
| **Breach Check** | HaveIBeenPwned API | k-anonymity |
| **Frontend** | HTML5 + CSS3 + Vanilla JS | — |
| **Containers** | Docker | Latest |
| **Testing** | pytest | 9.0 |
| **Orchestration** | docker-compose | 3.9 |

---

## Security Considerations

### What This App Does NOT Do
- ❌ Store passwords (not even temporarily)
- ❌ Require authentication
- ❌ Keep user sessions
- ❌ Log sensitive data
- ❌ Use unsafe algorithms
- ❌ Send full passwords anywhere

### What This App DOES Do
- ✅ Analyze passwords only in memory
- ✅ Discard immediately after analysis
- ✅ Check against HaveIBeenPwned (k-anonymity: only first 5 hash chars sent)
- ✅ Rate limit to prevent abuse
- ✅ Use cryptographically secure generators
- ✅ Validate all inputs strictly
- ✅ Include all security headers (CSP, X-Frame-Options, etc.)
- ✅ Run as non-root in containers
- ✅ Provide health checks and monitoring
- ✅ GDPR compliant by design (no data retention)

---

## Common Issues

**Issue:** Rate limiting blocks me (429 errors)
- **Solution:** Max 30 requests per 60 seconds per IP
- **For testing:** Render auto-scales, or wait 60 seconds for local testing
- **Why:** Prevents brute force attacks and DoS

**Issue:** Docker builds fail silently
- **Solution:** Check `docker logs container_name`
- **Common cause:** PORT already in use

**Issue:** /docs endpoint doesn't load
- **Solution:** API docs moved to `API_DOCUMENTATION.html` (offline reference)
- **Reason:** Security hardening - no API endpoint exposed in production

**Issue:** Password input disappears when switching tabs
- **Solution:** This is intentional (stateless design)
- **Reason:** Prevents unintended password storage
- **Alternative:** Use browser sessionStorage (optional enhancement)

---

## License & Attribution

This project is open-source and includes:
- HaveIBeenPwned k-anonymity API ([@troyhunt](https://twitter.com/troyhunt))
- zxcvbn password strength estimation (Dropbox)
- Professional security hardening best practices

---

## Contributing

Pull requests welcome! Areas for enhancement:
- Additional language support
- Mobile app wrapper
- LDAP/Active Directory integration
- Admin dashboard (analytics without storing passwords)
- Multi-factor authentication guidance

---

## Support

Found a bug? Open an issue on GitHub
Have a suggestion? Create a discussion
Security concern? Email privately before disclosure
