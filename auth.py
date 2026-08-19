from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import time
from collections import Counter
from datetime import datetime, timezone

import pyotp

_COOKIE_SECRET = os.environ.get("COOKIE_SECRET", "supersafe-dev-secret-change-me")
COOKIE_NAME = "supersafe_session"
_COOKIE_DAYS = 30

USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")
_PBKDF2_ITERATIONS = 100_000


# ── User storage ────────────────────────────────────────────────────────────

def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def _save_users(users: dict) -> None:
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def user_exists(username: str) -> bool:
    return username in _load_users()


# ── Password hashing ────────────────────────────────────────────────────────

def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Return (salt_hex, hash_hex) for the given password."""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


# ── Password strength ───────────────────────────────────────────────────────

_ENTROPY_THRESHOLD = 3.0


def _shannon_entropy(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def password_strength(password: str) -> dict:
    """Score a password against a fixed checklist. Returns score/label/checks/passes_threshold."""
    checks = {
        "At least 10 characters": len(password) >= 10,
        "Contains an uppercase letter": any(c.isupper() for c in password),
        "Contains a lowercase letter": any(c.islower() for c in password),
        "Contains a digit": any(c.isdigit() for c in password),
        "Contains a symbol": any(not c.isalnum() for c in password),
        "Not easily guessable (high entropy)": _shannon_entropy(password) >= _ENTROPY_THRESHOLD,
    }
    score = sum(checks.values())
    if score <= 2:
        label = "Weak"
    elif score <= 4:
        label = "Fair"
    elif score <= 5:
        label = "Good"
    else:
        label = "Strong"
    return {
        "score": score,
        "max_score": len(checks),
        "label": label,
        "checks": checks,
        "passes_threshold": score >= 5,
    }


# ── Registration / authentication ──────────────────────────────────────────

def register_user(username: str, password: str) -> tuple[bool, str | None]:
    username = username.strip()
    if not username:
        return False, "Please choose a username."
    if not re.match(r"^[a-zA-Z0-9._-]+$", username):
        return False, "Username may only contain letters, numbers, dots, underscores, and hyphens."
    if not password:
        return False, "Please choose a password."
    if user_exists(username):
        return False, "That username is already taken."
    if not password_strength(password)["passes_threshold"]:
        return False, "Password doesn't meet the strength requirements above."

    users = _load_users()
    salt_hex, hash_hex = hash_password(password)
    users[username] = {
        "salt": salt_hex,
        "password_hash": hash_hex,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_users(users)
    return True, None


def authenticate_user(username: str, password: str) -> bool:
    users = _load_users()
    record = users.get(username.strip())
    if not record:
        return False
    _, expected_hash = hash_password(password, bytes.fromhex(record["salt"]))
    return hmac.compare_digest(expected_hash, record["password_hash"])


# ── Shared user-record access (used by passkeys.py too) ────────────────────

def load_users() -> dict:
    return _load_users()


def save_users(users: dict) -> None:
    _save_users(users)


def get_user(username: str) -> dict | None:
    return _load_users().get(username.strip())


# ── TOTP-based two-factor authentication ────────────────────────────────────

TOTP_ISSUER = "Secure Coding Chatbot"


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(username: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def verify_totp_code(secret: str, code: str) -> bool:
    code = code.strip().replace(" ", "")
    if not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


def is_totp_enabled(username: str) -> bool:
    record = get_user(username)
    return bool(record and record.get("totp_enabled") and record.get("totp_secret"))


def get_totp_secret(username: str) -> str | None:
    record = get_user(username)
    return record.get("totp_secret") if record else None


def enable_totp(username: str, secret: str) -> None:
    users = _load_users()
    record = users.get(username.strip())
    if not record:
        return
    record["totp_secret"] = secret
    record["totp_enabled"] = True
    _save_users(users)


def disable_totp(username: str) -> None:
    users = _load_users()
    record = users.get(username.strip())
    if not record:
        return
    record.pop("totp_secret", None)
    record["totp_enabled"] = False
    _save_users(users)


# ── Remember-me session tokens ──────────────────────────────────────────────

def create_session_token(username: str) -> str:
    expiry = int(time.time()) + _COOKIE_DAYS * 86_400
    payload = f"{username}:{expiry}"
    sig = hmac.new(_COOKIE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: str) -> str | None:
    """Return the username if the token is validly signed and unexpired, else None."""
    try:
        username, expiry, sig = token.rsplit(":", 2)
        payload = f"{username}:{expiry}"
        expected = hmac.new(_COOKIE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(expiry) < int(time.time()):
            return None
        return username
    except Exception:
        return None
