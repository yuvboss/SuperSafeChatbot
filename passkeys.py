from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

import streamlit as st
import streamlit.components.v1 as components
import webauthn
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from auth import get_user, load_users, save_users

RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
RP_NAME = "Secure Coding Chatbot"
RP_ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:8501")

_bridge = components.declare_component(
    "webauthn_bridge", path=os.path.join(os.path.dirname(__file__), "webauthn_bridge")
)


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


# ── Stored credential access ────────────────────────────────────────────────

def user_passkeys(username: str) -> list[dict]:
    record = get_user(username)
    return record.get("passkeys", []) if record else []


def remove_passkey(username: str, credential_id_b64: str) -> None:
    users = load_users()
    record = users.get(username.strip())
    if not record:
        return
    record["passkeys"] = [
        p for p in record.get("passkeys", []) if p["credential_id"] != credential_id_b64
    ]
    save_users(users)


# ── Registration ─────────────────────────────────────────────────────────────

def begin_registration(username: str, nickname: str) -> None:
    exclude = [
        PublicKeyCredentialDescriptor(id=_b64d(p["credential_id"])) for p in user_passkeys(username)
    ]
    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_name=username,
        user_display_name=username,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    st.session_state["_passkey_reg_challenge"] = _b64e(options.challenge)
    st.session_state["_passkey_reg_nickname"] = nickname
    st.session_state["_passkey_reg_options"] = webauthn.options_to_json(options)


def complete_registration(credential: dict) -> tuple[bool, str | None]:
    username = st.session_state.get("username")
    challenge_b64 = st.session_state.get("_passkey_reg_challenge")
    if not username or not challenge_b64:
        return False, "Registration session expired. Please try again."
    try:
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=_b64d(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGIN,
        )
    except Exception as exc:
        return False, f"Could not verify passkey: {exc}"

    users = load_users()
    record = users.get(username)
    if not record:
        return False, "User not found."
    nickname = st.session_state.get("_passkey_reg_nickname") or "Passkey"
    record.setdefault("passkeys", []).append(
        {
            "credential_id": _b64e(verification.credential_id),
            "public_key": _b64e(verification.credential_public_key),
            "sign_count": verification.sign_count,
            "name": nickname,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    save_users(users)
    for key in ("_passkey_reg_challenge", "_passkey_reg_nickname", "_passkey_reg_options"):
        st.session_state.pop(key, None)
    return True, None


# ── Authentication ───────────────────────────────────────────────────────────

def begin_authentication(username: str | None) -> None:
    allow = None
    if username:
        allow = [
            PublicKeyCredentialDescriptor(id=_b64d(p["credential_id"]))
            for p in user_passkeys(username)
        ]
    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    st.session_state["_passkey_auth_challenge"] = _b64e(options.challenge)
    st.session_state["_passkey_auth_options"] = webauthn.options_to_json(options)


def complete_authentication(credential: dict) -> tuple[str | None, str | None]:
    """Verify an assertion and return (username, error)."""
    challenge_b64 = st.session_state.get("_passkey_auth_challenge")
    if not challenge_b64:
        return None, "Authentication session expired. Please try again."

    raw_id = credential.get("rawId") or credential.get("id")
    if not raw_id:
        return None, "Malformed passkey response."
    cred_id = base64url_to_bytes(raw_id)

    users = load_users()
    owner_username, passkey_record = None, None
    for uname, record in users.items():
        for pk in record.get("passkeys", []):
            if _b64d(pk["credential_id"]) == cred_id:
                owner_username, passkey_record = uname, pk
                break
        if owner_username:
            break

    if not owner_username:
        return None, "This passkey isn't registered with any account here."

    try:
        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=_b64d(challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGIN,
            credential_public_key=_b64d(passkey_record["public_key"]),
            credential_current_sign_count=passkey_record["sign_count"],
        )
    except Exception as exc:
        return None, f"Passkey verification failed: {exc}"

    passkey_record["sign_count"] = verification.new_sign_count
    save_users(users)
    for key in ("_passkey_auth_challenge", "_passkey_auth_options"):
        st.session_state.pop(key, None)
    return owner_username, None


# ── UI widget ────────────────────────────────────────────────────────────────

def ceremony_widget(action: str, options_json: str, label: str, key: str) -> dict | None:
    """Renders the passkey button; returns the bridge result dict once the browser ceremony finishes."""
    nonce_key = f"{key}_nonce"
    nonce = st.session_state.setdefault(nonce_key, os.urandom(8).hex())
    result = _bridge(
        action=action, options=options_json, label=label, nonce=nonce, key=key, default=None
    )
    if result and result.get("nonce") == nonce:
        st.session_state[nonce_key] = os.urandom(8).hex()
        return result
    return None
