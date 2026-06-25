import os
import streamlit as st
import extra_streamlit_components as stx
from datetime import datetime, timedelta
from dotenv import load_dotenv
from detection import detect
from masking import mask
from claude_client import stream_response, generate_summary
from achievements import ALL_ACHIEVEMENTS, check_new_achievements
from auth import (
    login_user, register_user, check_password_strength,
    create_session_token, verify_session_token, COOKIE_NAME,
)

load_dotenv()

st.set_page_config(page_title="SuperSafe", page_icon="🔐", layout="wide")

API_KEY_PRESENT = bool(os.environ.get("ANTHROPIC_API_KEY"))


cookies = stx.CookieManager(key="cookie_mgr")

WELCOME = (
    "👋 Welcome to **SuperSafe**! I'm your AI security mentor.\n\n"
    "Paste any code (or upload a file) and click **Scan Code** to check for hardcoded "
    "credentials like API keys, passwords, and secrets. You can also ask me any security "
    "question in the chat, or pick a **Lesson** from the sidebar."
)

LESSONS = [
    (
        "Why Secrets Are Dangerous",
        "Can you explain why hardcoded secrets in code are dangerous? Cover real-world "
        "consequences and common attack vectors concisely.",
    ),
    (
        "Using .env + os.getenv()",
        "Give me a practical tutorial on using .env files with python-dotenv and os.getenv() "
        "to manage secrets securely, with a before/after code example.",
    ),
    (
        "What Is Entropy Detection?",
        "Explain Shannon entropy, how it detects hardcoded secrets, and why high-entropy "
        "strings are suspicious — in simple terms a developer would understand.",
    ),
    (
        "Secrets in Git History",
        "Explain the risks of committing secrets to a git repository (including in git history) "
        "and how to remediate it if it happens.",
    ),
]


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _show_login():
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.title("SuperSafe 🔐")
        st.caption("Your AI security mentor")
        st.divider()

        tab_in, tab_reg = st.tabs(["Sign In", "Register"])

        with tab_in:
            username = st.text_input("Username", key="si_user")
            password = st.text_input("Password", type="password", key="si_pass")
            remember = st.checkbox("Remember me for 30 days", key="si_remember")
            if st.button("Sign In", use_container_width=True, key="si_btn"):
                if not username or not password:
                    st.error("Please enter your username and password.")
                else:
                    ok, result = login_user(username, password)
                    if ok:
                        st.session_state.logged_in = True
                        st.session_state.username = result
                        if remember:
                            cookies.set(
                                COOKIE_NAME,
                                create_session_token(result),
                                expires_at=datetime.now() + timedelta(days=30),
                            )
                        st.rerun()
                    else:
                        st.error(result)

        with tab_reg:
            new_user = st.text_input("Username", key="reg_user")
            new_pass = st.text_input("Password", type="password", key="reg_pass")
            confirm = st.text_input("Confirm Password", type="password", key="reg_confirm")

            # Real-time strength meter
            if new_pass:
                strength = check_password_strength(new_pass)
                st.markdown(f"**Password strength:** {strength['badge']} &nbsp; `{strength['entropy']} bits entropy`")
                st.progress(strength["score"] / 4)
                for key, passed in strength["checks"].items():
                    icon = "✅" if passed else "❌"
                    st.caption(f"{icon} {strength['labels'][key]}")

            if st.button("Create Account", use_container_width=True, key="reg_btn"):
                if not new_user or not new_pass:
                    st.error("Please fill in all fields.")
                elif new_pass != confirm:
                    st.error("Passwords don't match.")
                else:
                    ok, msg = register_user(new_user, new_pass)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)


# ── Cookie auto-login ──────────────────────────────────────────────────────────
if not st.session_state.get("logged_in"):
    token = cookies.get(COOKIE_NAME)
    if token:
        username_from_cookie = verify_session_token(token)
        if username_from_cookie:
            st.session_state.logged_in = True
            st.session_state.username = username_from_cookie
            st.rerun()

# ── Auth gate ──────────────────────────────────────────────────────────────────
if not st.session_state.get("logged_in"):
    _show_login()
    st.stop()


# ── Session state init (runs only when logged in) ──────────────────────────────
def _init_state():
    defaults = {
        "messages": [{"role": "assistant", "content": WELCOME}],
        "api_messages": [],
        "scans_total": 0,
        "previous_findings_count": -1,
        "findings_fixed": 0,
        "clean_scans_streak": 0,
        "unlocked_achievements": set(),
        "new_achievement_alerts": [],
        "pending_lesson": None,
        "last_summary": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"👤 **{st.session_state.username}**")
    if st.button("Sign Out", use_container_width=True):
        cookies.delete(COOKIE_NAME)
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    if not API_KEY_PRESENT:
        st.warning("No API key — AI responses are placeholders.", icon="⚠️")

    st.divider()

    st.subheader("Session Stats")
    c1, c2 = st.columns(2)
    c1.metric("Scans", st.session_state.scans_total)
    c2.metric("Fixed", st.session_state.findings_fixed)

    st.divider()

    st.subheader("Achievements")
    unlocked = st.session_state.unlocked_achievements
    for a in ALL_ACHIEVEMENTS:
        if a.id in unlocked:
            st.markdown(f"{a.emoji} **{a.name}**")
            st.caption(a.description)
        else:
            st.caption(f"🔒 {a.name}")

    st.divider()

    st.subheader("Lessons")
    for title, prompt in LESSONS:
        if st.button(title, key=f"lesson_{title}", use_container_width=True):
            st.session_state.pending_lesson = prompt

# ── Main ───────────────────────────────────────────────────────────────────────
st.title("SuperSafe 🔐")
st.caption("Your AI security mentor — paste code to scan for hardcoded secrets")

if not API_KEY_PRESENT:
    st.info(
        "**API key not configured.** Add `ANTHROPIC_API_KEY` to your `.env` file to enable AI responses. "
        "Detection, masking, and gamification work fully without it.",
        icon="ℹ️",
    )

# Achievement alerts earned on the previous action
if st.session_state.new_achievement_alerts:
    for a in st.session_state.new_achievement_alerts:
        st.success(f"{a.emoji} **Achievement unlocked: {a.name}** — {a.description}")
    st.balloons()
    st.session_state.new_achievement_alerts = []

# Chat history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# ── Pending lesson (triggered by sidebar button) ───────────────────────────────
if st.session_state.pending_lesson:
    lesson = st.session_state.pending_lesson
    st.session_state.pending_lesson = None

    with st.chat_message("user"):
        st.markdown(lesson)

    api_msgs = st.session_state.api_messages + [{"role": "user", "content": lesson}]
    with st.chat_message("assistant"):
        response = st.write_stream(stream_response(api_msgs))

    st.session_state.messages.append({"role": "user", "content": lesson})
    st.session_state.messages.append({"role": "assistant", "content": response})
    st.session_state.api_messages.append({"role": "user", "content": lesson})
    st.session_state.api_messages.append({"role": "assistant", "content": response})
    st.rerun()

# ── Scan form ──────────────────────────────────────────────────────────────────
with st.form("scan_form", clear_on_submit=True):
    code_input = st.text_area(
        "Paste your code here", height=200, placeholder="# Paste code to scan..."
    )
    uploaded = st.file_uploader(
        "...or upload a file",
        type=["py", "js", "ts", "env", "txt", "yaml", "yml", "json"],
    )
    submitted = st.form_submit_button("Scan Code 🔍")

if submitted:
    source_name = "pasted code"
    if uploaded is not None:
        code_input = uploaded.read().decode("utf-8", errors="replace")
        source_name = uploaded.name

    if not code_input or not code_input.strip():
        st.warning("Please paste code or upload a file to scan.")
    else:
        preview = code_input[:2000] + ("…" if len(code_input) > 2000 else "")

        findings = detect(code_input)
        masked_code = mask(code_input, findings)

        if findings:
            table = "| Line | Type | Method |\n|:-----|:-----|:-------|\n"
            table += "\n".join(
                f"| {f['line_number']} | {f['type']} | {f['method']} |" for f in findings
            )
            user_display = (
                f"**Scanning `{source_name}`** — {len(findings)} issue(s) detected\n\n"
                f"{table}\n\n"
                f"```\n{preview}\n```"
            )
        else:
            user_display = (
                f"**Scanning `{source_name}`** — ✅ No issues found\n\n```\n{preview}\n```"
            )

        with st.chat_message("user"):
            st.markdown(user_display)

        st.session_state.scans_total += 1
        prev = st.session_state.previous_findings_count

        if findings:
            st.session_state.clean_scans_streak = 0
            findings_summary = "\n".join(
                f"- Line {f['line_number']}: {f['type']} (detected via {f['method']})"
                for f in findings
            )
            api_user_content = (
                f"I submitted code for security scanning. Findings:\n\n{findings_summary}\n\n"
                f"Sanitized code (secrets replaced with [REDACTED]):\n```\n{masked_code}\n```\n\n"
                "Please explain each finding, why it's dangerous, and how to fix it using environment variables."
            )
        else:
            st.session_state.clean_scans_streak += 1
            if prev > 0:
                st.session_state.findings_fixed += prev
                st.success(f"🎉 You fixed {prev} finding(s) — great work!")
            api_user_content = (
                "I submitted code for security scanning and no hardcoded credentials were detected. "
                "Please give a brief encouraging message and a quick reminder of good security practices."
            )

        st.session_state.previous_findings_count = len(findings)

        new_achievements = check_new_achievements(st.session_state)
        if new_achievements:
            st.session_state.new_achievement_alerts = new_achievements

        api_msgs = st.session_state.api_messages + [{"role": "user", "content": api_user_content}]
        with st.chat_message("assistant"):
            response = st.write_stream(stream_response(api_msgs))

        st.session_state.messages.append({"role": "user", "content": user_display})
        st.session_state.messages.append({"role": "assistant", "content": response})
        st.session_state.api_messages.append({"role": "user", "content": api_user_content})
        st.session_state.api_messages.append({"role": "assistant", "content": response})
        st.rerun()

# ── Free-form chat ─────────────────────────────────────────────────────────────
if user_text := st.chat_input("Ask a security question or request a lesson..."):
    with st.chat_message("user"):
        st.markdown(user_text)

    api_msgs = st.session_state.api_messages + [{"role": "user", "content": user_text}]
    with st.chat_message("assistant"):
        response = st.write_stream(stream_response(api_msgs))

    st.session_state.messages.append({"role": "user", "content": user_text})
    st.session_state.messages.append({"role": "assistant", "content": response})
    st.session_state.api_messages.append({"role": "user", "content": user_text})
    st.session_state.api_messages.append({"role": "assistant", "content": response})
    st.rerun()

# ── Session summary ────────────────────────────────────────────────────────────
if st.session_state.api_messages:
    st.divider()
    if st.button("📋 Get Session Summary"):
        with st.spinner("Generating summary…"):
            st.session_state.last_summary = generate_summary(st.session_state.api_messages)

    if st.session_state.last_summary:
        with st.expander("Session Summary", expanded=True):
            st.markdown(st.session_state.last_summary)
