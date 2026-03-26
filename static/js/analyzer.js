/**
 * Password Strength Analyzer — analyzer.js  v2.1
 *
 * BUGS FIXED in this version:
 *
 *  BUG-6  hibpBtn was re-enabled via inline assignment after the fetch, but
 *         NOT inside a finally block — so if fetchAnalysis() threw (network
 *         error), the button stayed permanently disabled after one failed click.
 *         FIX: all hibpBtn state changes moved into try/finally.
 *
 *  BUG-7  hibpResult was hidden on EVERY new keystroke inside renderResult().
 *         User flow: type password → check HIBP → type one more char → HIBP
 *         result disappeared instantly, which was confusing and incorrect.
 *         FIX: hibpResult is only hidden inside resetUI() (called when input
 *         is fully cleared). It persists across keystrokes after HIBP check.
 *
 *  BUG-8  reportBtn.innerHTML was reset inside a finally block using a
 *         template literal — if innerHTML assignment failed (e.g. element
 *         detached from DOM), it would throw inside finally and swallow the
 *         original error. FIX: use a dedicated resetReportBtn() helper that
 *         catches its own error independently.
 *
 *  BUG-9  gen-length <input> had inline style="background:var(--surface2)..."
 *         which violates the app's own CSP header (style-src 'self', no
 *         unsafe-inline). In strict CSP browsers the input had no styling.
 *         FIX: inline style removed from HTML; styles moved to style.css
 *         under the class .gen-length-input.
 *
 * Security (unchanged):
 *  - Passwords NEVER written to console or any storage
 *  - No localStorage / sessionStorage
 *  - No third-party scripts or tracking
 *  - Debounced input
 *  - Password generator uses Web Crypto API (CSPRNG)
 *  - All fetch() calls go to same-origin only
 */

"use strict";

/* ── DOM REFERENCES ─────────────────────────────────── */
const passwordInput  = document.getElementById("password-input");
const toggleBtn      = document.getElementById("toggle-vis");
const eyeIcon        = document.getElementById("eye-icon");
const strengthBadge  = document.getElementById("strength-badge");
const segments       = [1,2,3,4].map(i => document.getElementById("seg" + i));
const scoreNum       = document.getElementById("score-num");
const lengthNum      = document.getElementById("length-num");
const entropyNum     = document.getElementById("entropy-num");
const feedbackList   = document.getElementById("feedback-list");
const commonWarn     = document.getElementById("common-warning");
const meterTrack     = document.querySelector(".meter-track");

const crackSection    = document.getElementById("crack-section");
const crackGrid       = document.getElementById("crack-grid");
const patternsSection = document.getElementById("patterns-section");
const patternsList    = document.getElementById("patterns-list");
const hibpSection     = document.getElementById("hibp-section");
const hibpBtn         = document.getElementById("hibp-btn");
const hibpResult      = document.getElementById("hibp-result");
const reportSection   = document.getElementById("report-section");
const reportBtn       = document.getElementById("report-btn");

const criteriaMap = {
  "c-length":   { el: document.getElementById("c-length"),   icon: document.getElementById("ci-length") },
  "c-length12": { el: document.getElementById("c-length12"), icon: document.getElementById("ci-length12") },
  "c-upper":    { el: document.getElementById("c-upper"),    icon: document.getElementById("ci-upper") },
  "c-lower":    { el: document.getElementById("c-lower"),    icon: document.getElementById("ci-lower") },
  "c-number":   { el: document.getElementById("c-number"),   icon: document.getElementById("ci-number") },
  "c-symbol":   { el: document.getElementById("c-symbol"),   icon: document.getElementById("ci-symbol") },
};

/* ── ICON SVG STRINGS ───────────────────────────────── */
const SVG_EYE_OPEN = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
  <circle cx="12" cy="12" r="3"/>`;

const SVG_EYE_CLOSED = `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8
  a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8
  a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/>
  <line x1="1" y1="1" x2="23" y2="23"/>`;

const SVG_SHIELD = `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`;

const SVG_DOWNLOAD = `<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
  <polyline points="7 10 12 15 17 10"/>
  <line x1="12" y1="15" x2="12" y2="3"/>`;

const SVG_REFRESH = `<path d="M23 4v6h-6"/><path d="M1 20v-6h6"/>
  <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0019.49 15"/>`;

function makeSvg(inner) {
  return `<svg width="14" height="14" fill="none" stroke="currentColor"
    stroke-width="2" viewBox="0 0 24 24" aria-hidden="true">${inner}</svg>`;
}


/* ── FLASK API CALL ─────────────────────────────────── */
async function fetchAnalysis(password, checkHibp = false) {
  try {
    const res = await fetch("/analyze", {
      method:      "POST",
      headers:     { "Content-Type": "application/json" },
      body:        JSON.stringify({ password, check_hibp: checkHibp }),
      credentials: "same-origin",
    });
    if (res.status === 429) { showRateLimitWarning(); return null; }
    if (!res.ok) return null;
    return await res.json();
  } catch {
    // Never log — password might be in scope
    return null;
  }
}


/* ── RESET UI ───────────────────────────────────────── */
function resetUI() {
  strengthBadge.textContent = "—";
  strengthBadge.className   = "strength-badge";
  segments.forEach(s => (s.className = "meter-seg"));
  if (meterTrack) meterTrack.setAttribute("aria-valuenow", "0");

  scoreNum.textContent   = "0";
  lengthNum.textContent  = "0";
  entropyNum.textContent = "0";

  Object.values(criteriaMap).forEach(({ el, icon }) => {
    el.className     = "criterion";
    icon.textContent = "?";
  });

  commonWarn.classList.remove("show");

  feedbackList.innerHTML = `
    <div class="feedback-item tip">
      <span class="feedback-icon" aria-hidden="true">💡</span>
      <span>Start typing to receive real-time security feedback and improvement tips.</span>
    </div>`;

  crackSection.style.display    = "none";
  patternsSection.style.display = "none";
  hibpSection.style.display     = "none";
  reportSection.style.display   = "none";

  // BUG-7 FIX: HIBP result only cleared when input is fully empty
  hibpResult.style.display = "none";
  hibpResult.textContent   = "";
  hibpResult.className     = "hibp-result";
  hibpBtn.disabled         = false;
}


/* ── RENDER RESULT ──────────────────────────────────── */
function renderResult(data) {
  // Strength badge
  strengthBadge.textContent = data.level_label;
  strengthBadge.className   = "strength-badge" + (data.level !== "none" ? " " + data.level : "");

  // Meter segments
  const segCount = { none:0, weak:1, fair:2, strong:3, vstrong:4 }[data.level] ?? 0;
  segments.forEach((s, i) => {
    s.className = "meter-seg" + (i < segCount ? " filled-" + data.level : "");
  });
  if (meterTrack) meterTrack.setAttribute("aria-valuenow", segCount);

  // Stats
  scoreNum.textContent   = data.score;
  lengthNum.textContent  = data.length;
  entropyNum.textContent = data.entropy;

  // Criteria checklist
  const c = data.criteria;
  setCriterion("c-length",   c.meets_min);
  setCriterion("c-length12", c.meets_rec);
  setCriterion("c-upper",    c.has_upper);
  setCriterion("c-lower",    c.has_lower);
  setCriterion("c-number",   c.has_number);
  setCriterion("c-symbol",   c.has_symbol);

  // Common breach banner
  data.is_common
    ? commonWarn.classList.add("show")
    : commonWarn.classList.remove("show");

  // Feedback
  feedbackList.innerHTML = (data.feedback || [])
    .map(f => `
      <div class="feedback-item ${escapeHtml(f.type)}">
        <span class="feedback-icon" aria-hidden="true">${f.icon}</span>
        <span>${escapeHtml(f.text)}</span>
      </div>`)
    .join("");

  // Crack times
  if (data.crack_times && Object.keys(data.crack_times).length > 0) {
    renderCrackTimes(data.crack_times);
    crackSection.style.display = "block";
  } else {
    crackSection.style.display = "none";
  }

  // Pattern detection
  renderPatterns(data.patterns || []);
  patternsSection.style.display = "block";

  // Show HIBP + report if password present
  // BUG-7 FIX: do NOT touch hibpResult here — it persists across keystrokes
  if (data.length > 0) {
    hibpSection.style.display   = "block";
    reportSection.style.display = "block";
  }
}


/* ── CRACK TIMES ────────────────────────────────────── */
function renderCrackTimes(crackTimes) {
  const ORDER = ["online_throttled", "online_unthrottled", "offline_gpu", "offline_botnet"];

  function dangerClass(secs) {
    if (secs < 3600)       return "danger";
    if (secs < 2_592_000)  return "warning";   // < 30 days
    if (secs < 31_536_000) return "safe";       // < 1 year
    return "strong";
  }

  crackGrid.innerHTML = ORDER
    .filter(k => crackTimes[k])
    .map(k => {
      const ct  = crackTimes[k];
      const cls = dangerClass(ct.seconds);
      return `
        <div class="crack-item ${cls}">
          <span class="crack-item-label">${escapeHtml(ct.label)}</span>
          <span class="crack-item-value">${escapeHtml(ct.display)}</span>
        </div>`;
    })
    .join("");
}


/* ── PATTERN DETECTION ──────────────────────────────── */
function renderPatterns(patterns) {
  if (patterns.length === 0) {
    patternsList.innerHTML = `
      <div class="pattern-item none">
        <span class="pattern-icon" aria-hidden="true">✅</span>
        <span>No weak patterns detected.</span>
      </div>`;
    return;
  }
  patternsList.innerHTML = patterns.map(p => {
    const icon = p.severity === "high" ? "⚠️" : "💡";
    return `
      <div class="pattern-item ${escapeHtml(p.severity)}">
        <span class="pattern-icon" aria-hidden="true">${icon}</span>
        <span>${escapeHtml(p.description)}</span>
      </div>`;
  }).join("");
}


/* ── HIBP CHECK (user-initiated) ────────────────────── */
hibpBtn.addEventListener("click", async () => {
  const password = passwordInput.value;
  if (!password) return;

  // BUG-6 FIX: all state changes inside try/finally so button always re-enables
  hibpBtn.disabled    = true;
  hibpBtn.textContent = "Checking...";
  hibpResult.style.display = "none";

  let data = null;
  try {
    data = await fetchAnalysis(password, true);
  } finally {
    // BUG-6 FIX: always re-enable button regardless of success/failure
    hibpBtn.disabled   = false;
    hibpBtn.innerHTML  = `${makeSvg(SVG_SHIELD)} Check HaveIBeenPwned`;
  }

  if (!data || !data.hibp) {
    hibpResult.className     = "hibp-result error";
    hibpResult.textContent   = "⚠️ Unable to reach HaveIBeenPwned API. Check your connection.";
    hibpResult.style.display = "block";
    return;
  }

  const h = data.hibp;
  if (h.error) {
    hibpResult.className   = "hibp-result error";
    hibpResult.textContent = `⚠️ API error: ${escapeHtml(h.error)}`;
  } else if (h.pwned) {
    hibpResult.className   = "hibp-result pwned";
    hibpResult.textContent = `🔴 Found in ${h.count.toLocaleString()} real-world data breaches. Do not use this password.`;
  } else {
    hibpResult.className   = "hibp-result clean";
    hibpResult.textContent = "✅ Not found in known breach databases.";
  }
  hibpResult.style.display = "block";
});


/* ── REPORT DOWNLOAD ────────────────────────────────── */
// BUG-8 FIX: reset helper isolates innerHTML errors from the main try/finally
function resetReportBtn() {
  try {
    reportBtn.disabled  = false;
    reportBtn.innerHTML = `${makeSvg(SVG_DOWNLOAD)} Download Security Report`;
  } catch { /* element detached — silently ignore */ }
}

reportBtn.addEventListener("click", async () => {
  const password = passwordInput.value;
  if (!password) return;

  reportBtn.disabled    = true;
  reportBtn.textContent = "Generating...";

  try {
    const res = await fetch("/report", {
      method:      "POST",
      headers:     { "Content-Type": "application/json" },
      body:        JSON.stringify({ password }),
      credentials: "same-origin",
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = "password_security_report.txt";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch {
    /* silently fail — never log password */
  } finally {
    resetReportBtn();  // BUG-8 FIX: always safe reset
  }
});


/* ── HELPERS ────────────────────────────────────────── */
function setCriterion(key, passed) {
  const { el, icon } = criteriaMap[key];
  el.className     = "criterion " + (passed ? "passed" : "failed");
  icon.textContent = passed ? "✓" : "✗";
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  "&amp;")
    .replace(/</g,  "&lt;")
    .replace(/>/g,  "&gt;")
    .replace(/"/g,  "&quot;")
    .replace(/'/g,  "&#39;");
}

function showRateLimitWarning() {
  feedbackList.innerHTML = `
    <div class="feedback-item warn">
      <span class="feedback-icon" aria-hidden="true">⚠️</span>
      <span>Too many requests. Please wait a moment before continuing.</span>
    </div>`;
}


/* ── DEBOUNCE + INPUT ───────────────────────────────── */
function debounce(fn, delay) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
}

const handleInput = debounce(async () => {
  const password = passwordInput.value;
  if (password.length === 0) { resetUI(); return; }
  const data = await fetchAnalysis(password);
  if (data) renderResult(data);
}, 200);

passwordInput.addEventListener("input", handleInput);
passwordInput.addEventListener("contextmenu", e => e.preventDefault());


/* ── TOGGLE VISIBILITY ──────────────────────────────── */
let isVisible = false;
toggleBtn.addEventListener("click", () => {
  isVisible          = !isVisible;
  passwordInput.type = isVisible ? "text" : "password";
  eyeIcon.innerHTML  = isVisible ? SVG_EYE_CLOSED : SVG_EYE_OPEN;
});


/* ── PASSWORD GENERATOR ─────────────────────────────── */
function generatePassword() {
  const useUpper   = document.getElementById("gen-upper").checked;
  const useLower   = document.getElementById("gen-lower").checked;
  const useNumbers = document.getElementById("gen-numbers").checked;
  const useSymbols = document.getElementById("gen-symbols").checked;
  const lengthEl   = document.getElementById("gen-length");
  const length     = Math.min(Math.max(parseInt(lengthEl.value, 10) || 16, 12), 64);

  let charset = "";
  if (useUpper)   charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (useLower)   charset += "abcdefghijklmnopqrstuvwxyz";
  if (useNumbers) charset += "0123456789";
  if (useSymbols) charset += "!@#$%^&*()-_=+[]{}|;:,.<>?";
  if (!charset)   charset  = "abcdefghijklmnopqrstuvwxyz";

  // CSPRNG — cryptographically secure, unlike Math.random()
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, v => charset[v % charset.length]).join("");
}

document.getElementById("gen-btn").addEventListener("click", () => {
  const pwd = generatePassword();
  document.getElementById("gen-text").textContent = pwd;
  document.getElementById("gen-output").classList.add("show");
});

document.getElementById("copy-btn").addEventListener("click", () => {
  const text = document.getElementById("gen-text").textContent;
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("copy-btn");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy"; }, 1800);
  }).catch(() => { /* clipboard unavailable — silently skip */ });
});


/* ── SCROLL REVEAL ──────────────────────────────────── */
const revealObserver = new IntersectionObserver(
  entries => entries.forEach(e => { if (e.isIntersecting) e.target.classList.add("visible"); }),
  { threshold: 0.08 }
);
document.querySelectorAll(".reveal").forEach(el => revealObserver.observe(el));


/* ── CLEAR ON TAB HIDE ──────────────────────────────── */
document.addEventListener("visibilitychange", () => {
  if (document.hidden && passwordInput.value) {
    passwordInput.value = "";
    resetUI();
  }
});


/* ── INIT: set correct button HTML ─────────────────── */
(function initButtons() {
  if (hibpBtn)   hibpBtn.innerHTML   = `${makeSvg(SVG_SHIELD)} Check HaveIBeenPwned`;
  if (reportBtn) reportBtn.innerHTML = `${makeSvg(SVG_DOWNLOAD)} Download Security Report`;
  const genBtn = document.getElementById("gen-btn");
  if (genBtn)    genBtn.innerHTML    = `${makeSvg(SVG_REFRESH)} Generate Password`;
})();
