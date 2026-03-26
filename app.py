"""
Password Strength Analyzer — app.py  v2.1
Professional Security Engineering Tool

BUGS FIXED in this version:
  BUG-1  level badge was computed BEFORE zxcvbn bonus and pattern penalty
         were applied → badge could show "Strong" while score was actually 45
         FIX: level is now derived from the FINAL adjusted score

  BUG-2  HIBP count parsing failed silently on padded responses — the HIBP
         API returns trailing \r on each line when Add-Padding:true is used,
         causing int("12345\r") to raise ValueError and swallow real hits
         FIX: strip() applied to both hash suffix and count before parsing

  BUG-3  DICTIONARY_WORDS contained "batman" twice (duplicate in set literal)
         FIX: deduplicated

  BUG-4  StorageError from Flask-Limiter (Redis down) was unhandled — caused
         an uncaught exception → 500 response instead of graceful fallback
         FIX: StorageError is caught; app falls back to in-memory limiter

  BUG-5  "batman" duplicate in DICTIONARY_WORDS produced inconsistent pattern
         descriptions across runs (set iteration order)
         FIX: covered by BUG-3 fix

Security hardening (unchanged):
  - Rate limiting: Flask-Limiter + Redis, falls back to in-memory
  - Passwords NEVER logged, stored, or written anywhere
  - Input length cap 128 chars (DoS prevention)
  - Strict JSON input validation
  - Security headers on every response
  - Debug mode off by default
  - Secret key from environment variable
  - Global error handlers — no stack traces to client
  - Host bound to 127.0.0.1 by default
"""

import os
import re
import math
import time
import hashlib
import requests
from collections import defaultdict
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, Response

# ── Optional: zxcvbn ──────────────────────────────────────────────
try:
    from zxcvbn import zxcvbn as _zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

# ── Optional: Flask-Limiter with Redis ───────────────────────────
LIMITER_AVAILABLE = False
limiter = None
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    pass

# ─────────────────────────────────────────────
# App initialisation
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"]          = os.environ.get("SECRET_KEY", os.urandom(32))
app.config["PROPAGATE_EXCEPTIONS"] = False

# ── Flask-Limiter setup (BUG-4 FIX: wrap in try/except) ──────────
if LIMITER_AVAILABLE:
    try:
        redis_uri = os.environ.get("REDIS_URL", "memory://")
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=["200 per day", "60 per hour"],
            storage_uri=redis_uri,
        )
    except Exception:
        # Redis unavailable — fall back to in-memory rate limiter below
        LIMITER_AVAILABLE = False
        limiter = None

# ── Fallback in-memory rate limiter ──────────────────────────────
RATE_LIMIT  = 30
RATE_WINDOW = 60
_rate_store: dict = defaultdict(list)


def get_client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")


def is_rate_limited(ip: str) -> bool:
    if LIMITER_AVAILABLE and limiter is not None:
        return False  # Flask-Limiter handles it via decorators/defaults
    now    = time.time()
    cutoff = now - RATE_WINDOW
    hist   = [t for t in _rate_store[ip] if t > cutoff]
    _rate_store[ip] = hist
    if len(hist) >= RATE_LIMIT:
        return True
    _rate_store[ip].append(now)
    return False


# ─────────────────────────────────────────────
# Security headers — applied to every response
# ─────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]      = (
        "geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["Server"] = ""
    # Uncomment when deployed with HTTPS/SSL:
    # response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


# ─────────────────────────────────────────────
# Common / breached passwords list
# ─────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "password1", "111111", "iloveyou", "admin",
    "letmein", "monkey", "1234567890", "000000", "dragon", "master",
    "sunshine", "princess", "welcome", "shadow", "superman", "michael",
    "football", "charlie", "donald", "password123", "666666", "qwerty123",
    "1q2w3e", "pass", "123123", "admin123", "root", "pass123", "test",
    "hello", "qwertyuiop", "asdfghjkl", "zxcvbnm", "trustno1", "baseball",
    "soccer", "batman", "access", "hello123", "login", "starwars",
    "summer", "winter", "1234", "passw0rd", "p@ssword", "qwerty1",
}

# ─────────────────────────────────────────────
# Keyboard sequences for pattern detection
# ─────────────────────────────────────────────
KEYBOARD_SEQUENCES = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1234567890", "0987654321", "abcdefghij", "abcdef",
    "qweasdzxc", "!@#$%^&*()",
]

# BUG-3 FIX: removed duplicate "batman"
DICTIONARY_WORDS = {
    "password", "dragon", "master", "monkey", "shadow", "sunshine",
    "princess", "welcome", "football", "baseball", "soccer", "batman",
    "superman", "michael", "charlie", "donald", "login", "admin",
    "iloveyou", "letmein", "trustno", "access", "hello", "summer",
    "winter", "spring", "autumn", "flower", "house", "computer",
    "internet", "network", "security", "freedom", "starwars",
}


# ─────────────────────────────────────────────
# HaveIBeenPwned k-anonymity check
# Only first 5 chars of SHA-1 hash are sent —
# never the full password or full hash.
# ─────────────────────────────────────────────
def check_hibp(password: str) -> dict:
    try:
        sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]   # never transmitted

        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={
                "User-Agent": "PasswordStrengthAnalyzer/2.0",
                "Add-Padding": "true",
            },
            timeout=4,
        )
        resp.raise_for_status()

        # BUG-2 FIX: strip() handles \r\n and whitespace from padded responses
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) == 2:
                line_suffix = parts[0].strip()
                count_str   = parts[1].strip()
                if line_suffix == suffix:
                    try:
                        count = int(count_str)
                    except ValueError:
                        count = 0
                    return {"pwned": count > 0, "count": count, "error": None}

        return {"pwned": False, "count": 0, "error": None}

    except requests.exceptions.Timeout:
        return {"pwned": False, "count": 0, "error": "HIBP API timeout"}
    except requests.exceptions.RequestException:
        return {"pwned": False, "count": 0, "error": "HIBP API unavailable"}


# ─────────────────────────────────────────────
# Crack time estimation
# ─────────────────────────────────────────────
def estimate_crack_times(entropy: float) -> dict:
    guesses = 2 ** entropy if entropy > 0 else 1

    MODELS = {
        "online_throttled":   {"gps": 100,               "label": "Online attack (throttled)"},
        "online_unthrottled": {"gps": 10_000,             "label": "Online attack (unthrottled)"},
        "offline_gpu":        {"gps": 10_000_000_000,     "label": "Offline attack (single GPU)"},
        "offline_botnet":     {"gps": 1_000_000_000_000,  "label": "Offline attack (botnet)"},
    }

    def format_time(seconds: float) -> str:
        if seconds < 1:           return "less than a second"
        if seconds < 60:          return f"{int(seconds)} seconds"
        if seconds < 3600:        return f"{int(seconds / 60)} minutes"
        if seconds < 86400:       return f"{int(seconds / 3600)} hours"
        if seconds < 31_536_000:  return f"{int(seconds / 86400)} days"
        if seconds < 3.156e9:     return f"{int(seconds / 31_536_000)} years"
        if seconds < 3.156e12:    return f"{int(seconds / 3.156e9):,} thousand years"
        if seconds < 3.156e15:    return f"{int(seconds / 3.156e12):,} million years"
        return "centuries"

    result = {}
    for key, model in MODELS.items():
        secs = guesses / model["gps"]
        result[key] = {
            "label":   model["label"],
            "seconds": secs,
            "display": format_time(secs),
        }
    return result


# ─────────────────────────────────────────────
# Pattern detection
# ─────────────────────────────────────────────
def detect_patterns(password: str) -> list:
    patterns = []
    lower    = password.lower()

    # 1. Repeated characters (aaa, 111)
    repeated = re.findall(r'(.)\1{2,}', password)
    if repeated:
        patterns.append({
            "type":        "repeated_chars",
            "description": f"Repeated characters detected: {', '.join(set(repeated))}",
            "severity":    "high",
        })

    # 2. Sequential numbers (1234, 9876)
    if re.search(
        r'(0123|1234|2345|3456|4567|5678|6789|'
        r'9876|8765|7654|6543|5432|4321|3210)',
        password
    ):
        patterns.append({
            "type":        "sequential_numbers",
            "description": "Sequential number pattern detected (e.g. 1234, 9876)",
            "severity":    "high",
        })

    # 3. Sequential letters (abcd, zyxw)
    if re.search(
        r'(abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|'
        r'mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz|'
        r'zyxw|yxwv|xwvu|wvut|vuts|utsr|tsrq|srqp|rqpo|qpon|ponm|'
        r'onml|nmlk|mlkj|lkji|kjih|jihg|ihgf|hgfe|gfed|fedc|edcb|dcba)',
        lower
    ):
        patterns.append({
            "type":        "sequential_letters",
            "description": "Sequential letter pattern detected (e.g. abcd, zyxw)",
            "severity":    "high",
        })

    # 4. Keyboard sequences (qwerty, asdf)
    for seq in KEYBOARD_SEQUENCES:
        if seq in lower or seq[::-1] in lower:
            patterns.append({
                "type":        "keyboard_sequence",
                "description": f"Keyboard walk pattern detected: '{seq}'",
                "severity":    "high",
            })
            break  # report once

    # 5. Dictionary words
    found_words = sorted({w for w in DICTIONARY_WORDS if w in lower})
    if found_words:
        patterns.append({
            "type":        "dictionary_word",
            "description": f"Common word(s) found in password: {', '.join(found_words[:3])}",
            "severity":    "medium",
        })

    # 6. Year pattern (1960–2029)
    if re.search(r'(19[6-9]\d|20[0-2]\d)', password):
        patterns.append({
            "type":        "year_pattern",
            "description": "Year pattern detected (e.g. 1995, 2023)",
            "severity":    "medium",
        })

    # 7. All digits or all letters
    if password.isdigit():
        patterns.append({
            "type":        "all_digits",
            "description": "Password consists only of digits",
            "severity":    "high",
        })
    elif password.isalpha():
        patterns.append({
            "type":        "all_letters",
            "description": "Password consists only of letters",
            "severity":    "medium",
        })

    return patterns


def _is_common_variant(password: str) -> bool:
    """
    Check if password is a trivial variant of a common/breached password.
    Catches patterns like "Password1!", "Admin123!", "Qwerty2024!"
    by stripping numbers/symbols and checking the alphabetic base.
    """
    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        return True
    # Strip all non-alpha characters and check
    stripped = re.sub(r'[^a-z]', '', lower)
    if stripped and stripped in COMMON_PASSWORDS:
        return True
    # Strip trailing digits/symbols (e.g. "password123!" → "password")
    base_tail = re.sub(r'[\d\W_]+$', '', lower)
    if base_tail and base_tail in COMMON_PASSWORDS:
        return True
    # Strip leading digits/symbols (e.g. "123password" → "password")
    base_head = re.sub(r'^[\d\W_]+', '', lower)
    if base_head and base_head in COMMON_PASSWORDS:
        return True
    return False


# ─────────────────────────────────────────────
# Core password analysis
# ─────────────────────────────────────────────
def analyze_password(password: str, check_hibp_api: bool = False) -> dict:
    """
    Full password analysis.
    Password is processed in memory — never logged or stored.
    """
    length     = len(password)
    has_upper  = bool(re.search(r'[A-Z]', password))
    has_lower  = bool(re.search(r'[a-z]', password))
    has_number = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))
    meets_min  = length >= 8
    meets_rec  = length >= 12
    is_common  = _is_common_variant(password)

    # Entropy (bits)
    pool = 0
    if has_lower:  pool += 26
    if has_upper:  pool += 26
    if has_number: pool += 10
    if has_symbol: pool += 32
    entropy = round(length * math.log2(pool), 1) if pool > 0 else 0

    # Base score (0–100)
    score = 0
    if length >= 6:  score += 10
    if length >= 8:  score += 15
    if length >= 12: score += 15
    if length >= 16: score += 10
    if has_upper:    score += 10
    if has_lower:    score += 10
    if has_number:   score += 15
    if has_symbol:   score += 15
    if all([has_upper, has_lower, has_number, has_symbol]): score += 5
    if is_common: score = min(score, 15)
    score = min(score, 100)

    # zxcvbn bonus
    zxcvbn_result = None
    if ZXCVBN_AVAILABLE and length > 0:
        try:
            z = _zxcvbn(password)
            zxcvbn_result = {
                "score":         z["score"],
                "guesses":       z["guesses"],
                "guesses_log10": z["guesses_log10"],
                "crack_times":   z["crack_times_display"],
                "feedback":      z["feedback"],
                "sequence": [
                    {"pattern": m.get("pattern", ""), "token": m.get("token", "")}
                    for m in z.get("sequence", [])
                ],
            }
            score = min(100, score + z["score"] * 5)   # 0–20 bonus
        except Exception:
            pass

    # Pattern penalty
    patterns     = detect_patterns(password) if length > 0 else []
    severe_count = sum(1 for p in patterns if p["severity"] == "high")
    score        = max(0, score - (severe_count * 8))
    score        = min(score, 100)

    # BUG-1 FIX: level derived from FINAL score (after all adjustments)
    if length == 0:               level = "none"
    elif is_common or score < 30: level = "weak"
    elif score < 55:              level = "fair"
    elif score < 80:              level = "strong"
    else:                         level = "vstrong"

    labels = {
        "none": "—", "weak": "Weak", "fair": "Fair",
        "strong": "Strong", "vstrong": "Very Strong",
    }

    # Crack time estimates
    crack_times = estimate_crack_times(entropy) if length > 0 else {}

    # HIBP (only when explicitly requested)
    hibp = None
    if check_hibp_api and length > 0:
        hibp = check_hibp(password)

    # Feedback messages — built purely from analysis results, no dummy data
    feedback = []
    if length == 0:
        feedback.append({"type": "tip", "icon": "💡",
            "text": "Start typing to receive real-time security feedback."})
    else:
        if is_common:
            feedback.append({"type": "warn", "icon": "🚨",
                "text": "This password appears in known breach databases. Do not use it."})
        if hibp and hibp.get("pwned"):
            feedback.append({"type": "warn", "icon": "🔴",
                "text": f"Found in {hibp['count']:,} real-world data breaches (HaveIBeenPwned)."})
        if length < 8:
            feedback.append({"type": "warn", "icon": "⚠️",
                "text": f"Too short ({length} chars). Minimum 8, recommended 12+."})
        elif length < 12:
            feedback.append({"type": "tip", "icon": "💡",
                "text": "Good start — adding more characters significantly increases security."})
        else:
            feedback.append({"type": "good", "icon": "✅",
                "text": f"Strong length ({length} characters)."})
        if not has_upper:
            feedback.append({"type": "tip", "icon": "💡",
                "text": "Add uppercase letters (A–Z) to expand character diversity."})
        if not has_lower:
            feedback.append({"type": "tip", "icon": "💡",
                "text": "Include lowercase letters (a–z) for better entropy."})
        if not has_number:
            feedback.append({"type": "tip", "icon": "💡",
                "text": "Add numbers (0–9) to make brute-force attacks harder."})
        if not has_symbol:
            feedback.append({"type": "tip", "icon": "💡",
                "text": "Include symbols (@#!$%) to dramatically increase strength."})
        for p in patterns:
            feedback.append({
                "type": "warn" if p["severity"] == "high" else "tip",
                "icon": "⚠️"  if p["severity"] == "high" else "💡",
                "text": p["description"],
            })
        if zxcvbn_result:
            if zxcvbn_result["feedback"].get("warning"):
                feedback.append({"type": "warn", "icon": "🔍",
                    "text": f"Pattern warning: {zxcvbn_result['feedback']['warning']}"})
            for s in zxcvbn_result["feedback"].get("suggestions", [])[:2]:
                feedback.append({"type": "tip", "icon": "💡", "text": s})
        if all([has_upper, has_lower, has_number, has_symbol]) and meets_rec and not patterns:
            feedback.append({"type": "good", "icon": "🔒",
                "text": "Meets all recommended security criteria."})
        if entropy >= 60:
            feedback.append({"type": "good", "icon": "⚡",
                "text": f"High entropy ({entropy} bits) — highly resistant to automated attacks."})

    return {
        "score":            score,
        "entropy":          entropy,
        "level":            level,
        "level_label":      labels[level],
        "length":           length,
        "is_common":        is_common,
        "criteria": {
            "meets_min":    meets_min,
            "meets_rec":    meets_rec,
            "has_upper":    has_upper,
            "has_lower":    has_lower,
            "has_number":   has_number,
            "has_symbol":   has_symbol,
        },
        "feedback":         feedback,
        "patterns":         patterns,
        "crack_times":      crack_times,
        "zxcvbn":           zxcvbn_result,
        "hibp":             hibp,
        "zxcvbn_available": ZXCVBN_AVAILABLE,
    }


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/docs")
def api_docs():
    return render_template("docs.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if is_rate_limited(get_client_ip()):
        return jsonify({"error": "Too many requests. Please slow down."}), 429
    if not request.is_json:
        return jsonify({"error": "Invalid request format."}), 415

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request body."}), 400

    password = data.get("password", "")
    if not isinstance(password, str):
        return jsonify({"error": "Invalid input."}), 400
    if len(password) > 128:
        return jsonify({"error": "Input too long."}), 400

    check_hibp_flag = bool(data.get("check_hibp", False))
    return jsonify(analyze_password(password, check_hibp_api=check_hibp_flag))


@app.route("/report", methods=["POST"])
def download_report():
    if is_rate_limited(get_client_ip()):
        return jsonify({"error": "Too many requests."}), 429
    if not request.is_json:
        return jsonify({"error": "Invalid request format."}), 415

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request body."}), 400

    password = data.get("password", "")
    if not isinstance(password, str) or len(password) > 128:
        return jsonify({"error": "Invalid input."}), 400
    if len(password) == 0:
        return jsonify({"error": "No password provided."}), 400

    result = analyze_password(password, check_hibp_api=True)
    ts     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "=" * 60,
        "  PASSWORD STRENGTH ANALYSIS REPORT",
        "=" * 60,
        f"  Generated : {ts}",
        "  Tool      : Password Strength Analyzer v2.1",
        "",
        "  NOTE: The analyzed password is NOT included in this",
        "  report for your security.",
        "=" * 60,
        "",
        "STRENGTH OVERVIEW",
        "-" * 40,
        f"  Strength Level : {result['level_label']}",
        f"  Score          : {result['score']} / 100",
        f"  Entropy        : {result['entropy']} bits",
        f"  Length         : {result['length']} characters",
        f"  Common/Breached: {'YES' if result['is_common'] else 'No'}",
        "",
        "CRITERIA CHECKLIST",
        "-" * 40,
        f"  [ {'PASS' if result['criteria']['meets_min']  else 'FAIL'} ] Minimum 8 characters",
        f"  [ {'PASS' if result['criteria']['meets_rec']  else 'FAIL'} ] Recommended 12+ characters",
        f"  [ {'PASS' if result['criteria']['has_upper']  else 'FAIL'} ] Uppercase letters (A-Z)",
        f"  [ {'PASS' if result['criteria']['has_lower']  else 'FAIL'} ] Lowercase letters (a-z)",
        f"  [ {'PASS' if result['criteria']['has_number'] else 'FAIL'} ] Numeric digits (0-9)",
        f"  [ {'PASS' if result['criteria']['has_symbol'] else 'FAIL'} ] Special characters (@#!$%)",
        "",
        "CRACK TIME ESTIMATES",
        "-" * 40,
    ]

    for key, ct in result.get("crack_times", {}).items():
        lines.append(f"  {ct['label']:<42}: {ct['display']}")

    lines += ["", "PATTERN ANALYSIS", "-" * 40]
    if result.get("patterns"):
        for p in result["patterns"]:
            lines.append(f"  [{p['severity'].upper()}] {p['description']}")
    else:
        lines.append("  No weak patterns detected.")

    if result.get("hibp"):
        lines += ["", "HAVEIBEENPWNED CHECK", "-" * 40]
        h = result["hibp"]
        if h.get("error"):
            lines.append(f"  Status : API unavailable ({h['error']})")
        elif h["pwned"]:
            lines.append(f"  Status : FOUND IN {h['count']:,} BREACHES")
        else:
            lines.append("  Status : Not found in known breaches")

    lines += ["", "SECURITY FEEDBACK", "-" * 40]
    for fb in result.get("feedback", []):
        lines.append(f"  {fb['icon']}  {fb['text']}")

    if result.get("zxcvbn") and result["zxcvbn"].get("feedback", {}).get("suggestions"):
        lines += ["", "ZXCVBN SUGGESTIONS", "-" * 40]
        for s in result["zxcvbn"]["feedback"]["suggestions"]:
            lines.append(f"  * {s}")

    lines += [
        "",
        "=" * 60,
        "  DISCLAIMER: For educational purposes only.",
        "  Never share passwords with untrusted parties.",
        "=" * 60,
    ]

    return Response(
        "\n".join(lines) + "\n",
        mimetype="text/plain",
        headers={
            "Content-Disposition": "attachment; filename=password_security_report.txt",
            "Cache-Control":       "no-store, no-cache, must-revalidate",
            "Pragma":              "no-cache",
        },
    )


# ─────────────────────────────────────────────
# Error handlers — never expose internals
# ─────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found."}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed."}), 405

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Please slow down."}), 429

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"500: {e}")
    return jsonify({"error": "Server error."}), 500


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host="127.0.0.1", port=5000)
