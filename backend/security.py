"""
EduBild Security Layer
======================
Provides:
  - JWT token creation & verification (HS256)
  - Fernet symmetric encryption for activity logs at rest
  - CSRF token generation & validation
  - Secret scrubbing for log output
  - Rate limiting state (in-memory per-IP counter)
  - .env encryption helpers (encrypt/decrypt secrets to disk)

Usage
-----
  from backend.security import (
      create_access_token, verify_token,
      encrypt_text, decrypt_text,
      generate_csrf_token, verify_csrf_token,
      scrub_secrets,
      RateLimiter,
  )
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

# ── Optional dependency guards ────────────────────────────────────────────────
# All security features degrade gracefully when optional packages are absent so
# the backend can start even on a minimal install.

try:
    from jose import JWTError, jwt as _jose_jwt
    _JWT_BACKEND = "jose"
except ImportError:
    try:
        import jwt as _pyjwt_mod
        _JWT_BACKEND = "pyjwt"
    except ImportError:
        _JWT_BACKEND = None

try:
    from cryptography.fernet import Fernet, InvalidToken
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


# ── Configuration (read from env / fallback) ──────────────────────────────────

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


# Try to read secrets from config first, fall back to environment, then generate
def _load_secrets():
    try:
        from backend.config import settings as _s
        return (
            _s.dashboard_secret_key or _env("DASHBOARD_SECRET_KEY") or secrets.token_hex(32),
            int(_s.jwt_expire_minutes),
            _s.log_encryption_key or _env("LOG_ENCRYPTION_KEY"),
            _s.csrf_secret or _env("CSRF_SECRET") or secrets.token_hex(24),
        )
    except Exception:
        return (
            _env("DASHBOARD_SECRET_KEY") or secrets.token_hex(32),
            int(_env("JWT_EXPIRE_MINUTES", "480")),
            _env("LOG_ENCRYPTION_KEY"),
            _env("CSRF_SECRET") or secrets.token_hex(24),
        )


JWT_SECRET, JWT_EXPIRE_MINUTES, _FERNET_KEY_RAW, _CSRF_SECRET = _load_secrets()
JWT_ALGORITHM = "HS256"

_fernet: Optional[Any] = None
if _CRYPTO_OK and _FERNET_KEY_RAW:
    try:
        _fernet = Fernet(_FERNET_KEY_RAW.encode())
    except Exception:
        _fernet = None


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Return a signed JWT containing `data`."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=JWT_EXPIRE_MINUTES))
    to_encode["exp"] = expire

    if _JWT_BACKEND == "jose":
        return _jose_jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    elif _JWT_BACKEND == "pyjwt":
        return _pyjwt_mod.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    else:
        # Fallback: simple HMAC-signed base64 token (no external deps)
        import base64, json
        # Store exp as a Unix timestamp float so verify_token can compare numerically
        fallback_data = to_encode.copy()
        if isinstance(fallback_data.get("exp"), datetime):
            fallback_data["exp"] = fallback_data["exp"].timestamp()
        payload = base64.urlsafe_b64encode(
            json.dumps(fallback_data, default=str).encode()
        ).decode()
        sig = hmac.new(JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and verify a JWT.  Returns the payload dict on success, None on failure.
    Checks expiry automatically.
    """
    try:
        if _JWT_BACKEND == "jose":
            payload = _jose_jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        elif _JWT_BACKEND == "pyjwt":
            payload = _pyjwt_mod.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        else:
            # Fallback verification
            import base64, json
            parts = token.rsplit(".", 1)
            if len(parts) != 2:
                return None
            payload_b64, sig = parts
            expected = hmac.new(JWT_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            data = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
            # Check expiry manually
            exp = data.get("exp")
            if exp and datetime.now(timezone.utc).timestamp() > exp:
                return None
            return data
    except Exception:
        return None


# ── Fernet encryption (logs at rest) ─────────────────────────────────────────

def encrypt_text(plaintext: str) -> str:
    """
    Encrypt a string with Fernet symmetric encryption.
    Returns the ciphertext as a UTF-8 string.
    Falls back to returning the original text if cryptography is unavailable
    or no key is configured.
    """
    if _fernet is None:
        return plaintext
    try:
        return _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    except Exception:
        return plaintext


def decrypt_text(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string.  Returns original on error."""
    if _fernet is None:
        return ciphertext
    try:
        return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except Exception:
        return ciphertext


def generate_fernet_key() -> str:
    """Utility: generate a new Fernet key (call once, save to .env)."""
    if not _CRYPTO_OK:
        raise ImportError("cryptography package not installed: pip install cryptography")
    return Fernet.generate_key().decode()


# ── CSRF token ────────────────────────────────────────────────────────────────
# CSRF tokens are short-lived HMAC-signed timestamps.
# The dashboard sends the token in the X-CSRF-Token header; the API verifies it.

_CSRF_TTL_SECONDS = 3600  # 1 hour


def generate_csrf_token(session_id: str = "default") -> str:
    """Generate a CSRF token tied to a session ID."""
    ts = str(int(time.time()))
    raw = f"{session_id}:{ts}"
    sig = hmac.new(_CSRF_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{ts}.{sig}"


def verify_csrf_token(token: str, session_id: str = "default") -> bool:
    """Verify a CSRF token.  Returns False if expired or tampered."""
    try:
        ts_str, sig = token.split(".", 1)
        ts = int(ts_str)
        if time.time() - ts > _CSRF_TTL_SECONDS:
            return False
        raw = f"{session_id}:{ts_str}"
        expected = hmac.new(_CSRF_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


# ── Secret scrubbing ──────────────────────────────────────────────────────────
# Patterns that should NEVER appear in logs.  All matched values are replaced
# with [REDACTED] before any log output reaches disk or the dashboard.

_SECRET_PATTERNS = [
    re.compile(r"(AIza[0-9A-Za-z\-_]{35})", re.I),          # Google/Gemini API key
    re.compile(r"(sk-[A-Za-z0-9]{20,})", re.I),             # OpenAI-style keys
    re.compile(r"(Bearer\s+[A-Za-z0-9\-._~+/]+=*)", re.I),  # Bearer tokens
    re.compile(r"(password\s*[:=]\s*\S+)", re.I),            # password= in logs
    re.compile(r"(secret\s*[:=]\s*\S+)", re.I),             # secret= in logs
    re.compile(r"(token\s*[:=]\s*[A-Za-z0-9\-._~+/]{8,})", re.I),
]


def scrub_secrets(text: str) -> str:
    """Replace any detected secret patterns in `text` with [REDACTED]."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


# ── In-memory rate limiter ────────────────────────────────────────────────────

class RateLimiter:
    """
    Token-bucket rate limiter keyed by IP address (or any string identifier).

    Usage:
        limiter = RateLimiter(max_requests=60, window_seconds=60)

        @app.middleware("http")
        async def rate_limit_middleware(request, call_next):
            ip = request.client.host
            if not limiter.allow(ip):
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
            return await call_next(request)
    """

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: Dict[str, list] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        # Purge old timestamps
        self._buckets[key] = [t for t in self._buckets[key] if t > window_start]
        if len(self._buckets[key]) >= self.max_requests:
            return False
        self._buckets[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        now = time.time()
        window_start = now - self.window_seconds
        active = [t for t in self._buckets[key] if t > window_start]
        return max(0, self.max_requests - len(active))


# ── Kill switch: DOM integrity check ─────────────────────────────────────────
# Injected into the browser page — returns True if unexpected scripts or iframes
# have been added to the page (potential XSS / code injection signal).

KILL_SWITCH_JS = """
() => {
    const EXPECTED_DOMAINS = ['linkedin.com', 'licdn.com', 'linkedin.sc.omtrdc.net'];
    const suspicious = [];

    // Check all script src attributes
    document.querySelectorAll('script[src]').forEach(s => {
        try {
            const host = new URL(s.src).hostname;
            if (!EXPECTED_DOMAINS.some(d => host.endsWith(d))) {
                suspicious.push({ type: 'script', src: s.src });
            }
        } catch(e) {}
    });

    // Check all iframes
    document.querySelectorAll('iframe[src]').forEach(f => {
        try {
            const host = new URL(f.src).hostname;
            if (!EXPECTED_DOMAINS.some(d => host.endsWith(d))) {
                suspicious.push({ type: 'iframe', src: f.src });
            }
        } catch(e) {}
    });

    return suspicious;
}
"""


async def run_kill_switch(page: Any, logger: Any) -> bool:
    """
    Run the DOM integrity check on `page`.
    Returns True (= KILL the action) if suspicious external resources are found.
    Logs warnings for each suspicious element found.
    """
    try:
        findings = await page.evaluate(KILL_SWITCH_JS)
        if findings:
            for f in findings:
                logger.critical(
                    "[kill-switch] SUSPICIOUS DOM ELEMENT: type=%s src=%s",
                    f.get("type"), scrub_secrets(f.get("src", ""))
                )
            return True  # abort
        return False
    except Exception as e:
        logger.warning("[kill-switch] evaluation error (non-fatal): %s", e)
        return False
