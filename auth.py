import hashlib
import hmac
import math
import os
import re
import secrets
import time
from collections import Counter
from typing import Optional

import yaml

USERS_FILE = "users.yaml"

# ── Session tokens (for "Remember me" cookies) ────────────────────────────────

_COOKIE_SECRET = os.environ.get("COOKIE_SECRET", "supersafe-dev-secret-change-me")
COOKIE_NAME = "supersafe_session"
_COOKIE_DAYS = 30


def create_session_token(username: str) -> str:
    expiry = int(time.time()) + _COOKIE_DAYS * 86_400
    payload = f"{username}:{expiry}"
    sig = hmac.new(_COOKIE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: str) -> Optional[str]:
    """Return username if the token is valid and unexpired, else None."""
    try:
        last = token.rfind(":")
        payload, sig = token[:last], token[last + 1:]
        expected = hmac.new(_COOKIE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        second_last = payload.rfind(":")
        username, expiry = payload[:second_last], int(payload[second_last + 1:])
        if expiry < int(time.time()):
            return None
        return username
    except Exception:
        return None

# ── Password strength ──────────────────────────────────────────────────────────

_SPECIAL = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")

_REQUIREMENTS = [
    ("length",    "At least 8 characters",               lambda p: len(p) >= 8),
    ("uppercase", "At least one uppercase letter (A–Z)",  lambda p: any(c.isupper() for c in p)),
    ("lowercase", "At least one lowercase letter (a–z)",  lambda p: any(c.islower() for c in p)),
    ("digit",     "At least one number (0–9)",             lambda p: any(c.isdigit() for c in p)),
    ("special",   "At least one special character (!@#…)", lambda p: any(c in _SPECIAL for c in p)),
    ("entropy",   "Sufficient complexity (not repetitive)",
     lambda p: _entropy(p) >= 3.0),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def check_password_strength(password: str) -> dict:
    """Return score (1–4), label, per-check results, and entropy."""
    checks = {key: fn(password) for key, _, fn in _REQUIREMENTS}
    labels = {key: label for key, label, _ in _REQUIREMENTS}
    passed = sum(checks.values())
    entropy = round(_entropy(password), 2)

    if passed <= 2:
        score, badge = 1, "🔴 Weak"
    elif passed <= 4:
        score, badge = 2, "🟠 Fair"
    elif passed == 5:
        score, badge = 3, "🟡 Good"
    else:
        score, badge = 4, "🟢 Strong"

    return {
        "score": score,
        "badge": badge,
        "checks": checks,
        "labels": labels,
        "entropy": entropy,
        "passed_all": all(checks.values()),
    }


# ── Password helpers ───────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
    return f"{salt}:{key}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, key = stored.split(":", 1)
        new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
        return hmac.compare_digest(new_key, key)
    except Exception:
        return False


# ── User store (YAML file) ─────────────────────────────────────────────────────

def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return yaml.safe_load(f) or {}


def _save_users(users: dict) -> None:
    with open(USERS_FILE, "w") as f:
        yaml.safe_dump(users, f)


def register_user(username: str, password: str) -> tuple[bool, str]:
    username = username.strip()
    if not username:
        return False, "Username cannot be empty."
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return False, "Username may only contain letters, numbers, dots, underscores, and hyphens."
    strength = check_password_strength(password)
    if not strength["passed_all"]:
        failed = [strength["labels"][k] for k, ok in strength["checks"].items() if not ok]
        return False, "Password too weak. Fix: " + "; ".join(failed) + "."
    users = _load_users()
    if username in users:
        return False, "Username already taken."
    users[username] = {"password": _hash_password(password)}
    _save_users(users)
    return True, "Account created! You can now sign in."


def login_user(username: str, password: str) -> tuple[bool, str]:
    username = username.strip()
    users = _load_users()
    if username not in users:
        return False, "Username not found."
    if not _verify_password(password, users[username].get("password", "")):
        return False, "Incorrect password."
    return True, username

