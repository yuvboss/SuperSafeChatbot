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
    authenticate_user,
    register_user,
    password_strength,
    create_session_token,
    verify_session_token,
    COOKIE_NAME,
)

load_dotenv()

st.set_page_config(page_title="Secure Coding Chatbot", page_icon="🔐", layout="wide")

API_KEY_PRESENT = bool(os.environ.get("ANTHROPIC_API_KEY"))


cookies = stx.CookieManager(key="cookie_mgr")

WELCOME = (
    "👋 Welcome to **Secure Coding Chatbot**! I'm your AI security mentor.\n\n"
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
        "strings are suspicious, in simple terms a developer would understand.",
    ),
    (
        "Secrets in Git History",
        "Explain the risks of committing secrets to a git repository (including in git history) "
        "and how to remediate it if it happens.",
    ),
]


# ── Auth helpers ───────────────────────────────────────────────────────────────

_STRENGTH_COLORS = {"Weak": "#e5484d", "Fair": "#f5a623", "Good": "#cddc39", "Strong": "#30a46c"}

_AUTH_CSS = """
<style>
.stApp {
    background: radial-gradient(circle at 15% 0%, rgba(99,102,241,0.28) 0%, transparent 45%),
                radial-gradient(circle at 85% 15%, rgba(236,72,153,0.24) 0%, transparent 45%),
                linear-gradient(180deg, #eef2ff 0%, #e0e7ff 45%, #fdf2f8 100%);
}
.hero-badge {
    width: 68px; height: 68px; border-radius: 20px; margin: 0 auto 1.1rem;
    display: flex; align-items: center; justify-content: center;
    background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
    box-shadow: 0 10px 28px rgba(99,102,241,0.35);
    font-size: 2rem;
}
.auth-header { text-align: center; margin-bottom: 1.75rem; }
.auth-header h1 {
    font-size: 2.6rem; font-weight: 800; margin: 0 0 0.3rem;
    background: linear-gradient(135deg, #4338ca 0%, #a21caf 100%);
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
}
.auth-header p { font-size: 1.05rem; color: #475569; margin: 0; }
.auth-header .byline { font-size: 0.8rem; color: #94a3b8; margin-top: 0.35rem; }
.feature-card {
    background: rgba(255,255,255,0.75); border: 1px solid rgba(99,102,241,0.15);
    border-radius: 16px; padding: 1.4rem 1.2rem; height: 100%;
    box-shadow: 0 6px 20px rgba(15,23,42,0.05);
}
.feature-icon {
    width: 42px; height: 42px; border-radius: 12px; margin-bottom: 0.7rem;
    display: flex; align-items: center; justify-content: center; font-size: 1.4rem;
    background: linear-gradient(135deg, rgba(99,102,241,0.16), rgba(139,92,246,0.16));
}
.feature-title { font-weight: 700; margin-bottom: 0.25rem; color: #1e293b; }
.feature-desc { font-size: 0.88rem; color: #475569; line-height: 1.5; }
.strength-label { font-weight: 600; font-size: 0.9rem; margin: 0.25rem 0 0.4rem; }
.strength-check { font-size: 0.85rem; line-height: 1.6; opacity: 0.85; }
div[data-testid="stVerticalBlockBorderWrapper"]:has(.auth-card-marker) {
    border-radius: 20px !important;
    box-shadow: 0 12px 40px rgba(15,23,42,0.08) !important;
}
.st-key-landing_cta button,
.st-key-su_btn button,
.st-key-si_btn button {
    background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%) !important;
    color: white !important; border: none !important; font-weight: 600 !important;
    box-shadow: 0 10px 28px rgba(99,102,241,0.35) !important;
}
</style>
"""


def _render_strength_meter(password: str):
    if not password:
        return None
    result = password_strength(password)
    color = _STRENGTH_COLORS[result["label"]]
    pct = round(100 * result["score"] / result["max_score"])
    st.markdown(
        f'<div class="strength-label" style="color:{color};">'
        f'Password strength: {result["label"]} ({result["score"]}/{result["max_score"]})</div>'
        f'<div style="background:rgba(127,127,127,0.25); border-radius:4px; height:8px; overflow:hidden;">'
        f'<div style="background:{color}; width:{pct}%; height:100%;"></div></div>',
        unsafe_allow_html=True,
    )
    checklist = "<br>".join(
        f'<span class="strength-check">{"✅" if ok else "◻️"} {label}</span>'
        for label, ok in result["checks"].items()
    )
    st.markdown(checklist, unsafe_allow_html=True)
    return result


def _remember_me(username: str):
    cookies.set(
        COOKIE_NAME,
        create_session_token(username),
        expires_at=datetime.now() + timedelta(days=30),
    )


def _log_in(username: str, remember: bool):
    st.session_state.logged_in = True
    st.session_state.username = username
    if remember:
        _remember_me(username)
    st.rerun()


def _show_landing():
    st.markdown(_AUTH_CSS, unsafe_allow_html=True)
    _, col, _ = st.columns([1, 3, 1])
    with col:
        st.markdown(
            '<div class="hero-badge">🔐</div>'
            '<div class="auth-header"><h1>Secure Coding Chatbot</h1>'
            '<p>Catch hardcoded secrets before they catch you.</p>'
            '<p class="byline">by SuperSafe</p></div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<p style="text-align:center; max-width:560px; margin:0 auto 2rem; color:#334155;">'
            "Secure Coding Chatbot is an AI-powered security mentor for developers. Paste your code and it "
            "scans for hardcoded API keys, passwords, and tokens, then coaches you through fixing "
            "them the right way, with environment variables, not guesswork.</p>",
            unsafe_allow_html=True,
        )

        f1, f2, f3 = st.columns(3)
        features = [
            (f1, "🔍", "Instant detection", "Regex + entropy analysis catches secrets other tools miss"),
            (f2, "🤖", "AI-guided fixes", "Claude explains why it's risky and how to fix it"),
            (f3, "🏆", "Learn as you go", "Lessons and achievements built right into the workflow"),
        ]
        for target, icon, title, desc in features:
            with target:
                st.markdown(
                    f'<div class="feature-card">'
                    f'<div class="feature-icon">{icon}</div>'
                    f'<div class="feature-title">{title}</div>'
                    f'<div class="feature-desc">{desc}</div>'
                    f"</div>",
                    unsafe_allow_html=True,
                )

        st.write("")
        _, btn_col, _ = st.columns([1, 2, 1])
        with btn_col:
            if st.button("Sign Up / Sign In →", use_container_width=True, key="landing_cta"):
                st.session_state.show_auth = True
                st.rerun()


def _show_auth():
    st.markdown(_AUTH_CSS, unsafe_allow_html=True)
    _, col, _ = st.columns([1, 2, 1])
    with col:
        st.markdown(
            '<div class="hero-badge">🔐</div>'
            '<div class="auth-header"><h1>Secure Coding Chatbot</h1>'
            '<p>Your AI security mentor</p>'
            '<p class="byline">by SuperSafe</p></div>',
            unsafe_allow_html=True,
        )

        with st.container(border=True):
            st.markdown('<span class="auth-card-marker"></span>', unsafe_allow_html=True)
            sign_in_tab, sign_up_tab = st.tabs(["Sign In", "Sign Up"])

            with sign_in_tab:
                username = st.text_input("Username", key="si_user", autocomplete="username")
                password = st.text_input(
                    "Password", type="password", key="si_pass", autocomplete="current-password"
                )
                remember = st.checkbox("Remember me for 30 days", key="si_remember")
                if st.button("Sign In", use_container_width=True, key="si_btn"):
                    if not username or not password:
                        st.error("Please enter your username and password.")
                    elif authenticate_user(username, password):
                        _log_in(username.strip(), remember)
                    else:
                        st.error("Incorrect username or password.")

            with sign_up_tab:
                new_username = st.text_input(
                    "Choose a username", key="su_user", autocomplete="username"
                )
                new_password = st.text_input(
                    "Choose a password", type="password", key="su_pass", autocomplete="new-password"
                )
                confirm_password = st.text_input(
                    "Confirm password", type="password", key="su_confirm", autocomplete="new-password"
                )
                _render_strength_meter(new_password)

                if st.button("Create Account", use_container_width=True, key="su_btn"):
                    if new_password != confirm_password:
                        st.error("Passwords don't match.")
                    else:
                        ok, error = register_user(new_username, new_password)
                        if ok:
                            st.success("Account created!")
                            _log_in(new_username.strip(), remember=False)
                        else:
                            st.error(error)


# ── Cookie auto-login ──────────────────────────────────────────────────────────
if not st.session_state.get("logged_in"):
    token = cookies.get(COOKIE_NAME)
    username_from_token = verify_session_token(token) if token else None
    if username_from_token:
        st.session_state.logged_in = True
        st.session_state.username = username_from_token
        st.rerun()

# ── Auth gate ──────────────────────────────────────────────────────────────────
if not st.session_state.get("logged_in"):
    if st.session_state.get("show_auth"):
        _show_auth()
    else:
        _show_landing()
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
        "current_view": "main",
        "lesson_chats": {},
        "last_summary": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"Signed in as **{st.session_state.username}**")
    if st.button("Sign Out", use_container_width=True):
        cookies.delete(COOKIE_NAME)
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    if not API_KEY_PRESENT:
        st.warning("No API key, so AI responses are placeholders.", icon="⚠️")

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
    if st.button("🏠 Main Chat", key="nav_main", use_container_width=True):
        st.session_state.current_view = "main"
        st.rerun()
    for title, prompt in LESSONS:
        label = f"💬 {title}" if title in st.session_state.lesson_chats else title
        if st.button(label, key=f"lesson_{title}", use_container_width=True):
            st.session_state.current_view = title
            if title not in st.session_state.lesson_chats:
                st.session_state.lesson_chats[title] = {
                    "messages": [],
                    "api_messages": [],
                    "prompt": prompt,
                }
            st.rerun()

# ── Main ───────────────────────────────────────────────────────────────────────
st.title("Secure Coding Chatbot 🔐")
st.caption("Your AI security mentor, paste code to scan for hardcoded secrets")

if not API_KEY_PRESENT:
    st.info(
        "**API key not configured.** Add `ANTHROPIC_API_KEY` to your `.env` file to enable AI responses. "
        "Detection, masking, and gamification work fully without it.",
        icon="ℹ️",
    )

# Achievement alerts earned on the previous action
if st.session_state.new_achievement_alerts:
    for a in st.session_state.new_achievement_alerts:
        st.success(f"{a.emoji} **Achievement unlocked: {a.name}**, {a.description}")
    st.balloons()
    st.session_state.new_achievement_alerts = []

if st.session_state.current_view != "main":
    # ── Lesson chat (private thread per lesson, resumable for the session) ─────
    lesson_title = st.session_state.current_view
    lesson = st.session_state.lesson_chats[lesson_title]

    st.subheader(f"📘 {lesson_title}")
    if st.button("← Back to main chat"):
        st.session_state.current_view = "main"
        st.rerun()
    st.divider()

    for msg in lesson["messages"]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if not lesson["messages"]:
        with st.chat_message("user"):
            st.markdown(lesson["prompt"])
        with st.chat_message("assistant"):
            response = st.write_stream(stream_response([{"role": "user", "content": lesson["prompt"]}]))

        lesson["messages"].append({"role": "user", "content": lesson["prompt"]})
        lesson["messages"].append({"role": "assistant", "content": response})
        lesson["api_messages"].append({"role": "user", "content": lesson["prompt"]})
        lesson["api_messages"].append({"role": "assistant", "content": response})
        st.rerun()

    if user_text := st.chat_input(
        f"Ask a follow-up about {lesson_title}...", key=f"lesson_input_{lesson_title}"
    ):
        with st.chat_message("user"):
            st.markdown(user_text)

        api_msgs = lesson["api_messages"] + [{"role": "user", "content": user_text}]
        with st.chat_message("assistant"):
            response = st.write_stream(stream_response(api_msgs))

        lesson["messages"].append({"role": "user", "content": user_text})
        lesson["messages"].append({"role": "assistant", "content": response})
        lesson["api_messages"].append({"role": "user", "content": user_text})
        lesson["api_messages"].append({"role": "assistant", "content": response})
        st.rerun()

else:
    # ── Main scan + chat ─────────────────────────────────────────────────────────
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # ── Scan form ────────────────────────────────────────────────────────────────
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
            findings = detect(code_input)
            masked_code = mask(code_input, findings)
            preview = masked_code[:2000] + ("…" if len(masked_code) > 2000 else "")

            if findings:
                table = "| Line | Type | Method |\n|:-----|:-----|:-------|\n"
                table += "\n".join(
                    f"| {f['line_number']} | {f['type']} | {f['method']} |" for f in findings
                )
                user_display = (
                    f"**Scanning `{source_name}`**, {len(findings)} issue(s) detected\n\n"
                    f"{table}\n\n"
                    f"```\n{preview}\n```"
                )
            else:
                user_display = (
                    f"**Scanning `{source_name}`**, ✅ No issues found\n\n```\n{preview}\n```"
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
                    st.success(f"🎉 You fixed {prev} finding(s), great work!")
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

    # ── Free-form chat ───────────────────────────────────────────────────────────
    if user_text := st.chat_input("Ask a security question..."):
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

    # ── Session summary ──────────────────────────────────────────────────────────
    if st.session_state.api_messages:
        st.divider()
        if st.button("📋 Get Session Summary"):
            with st.spinner("Generating summary…"):
                st.session_state.last_summary = generate_summary(st.session_state.api_messages)

        if st.session_state.last_summary:
            with st.expander("Session Summary", expanded=True):
                st.markdown(st.session_state.last_summary)
