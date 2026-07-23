# SuperSafe 🔐

SuperSafe is an AI-powered security mentor for developers. Paste in code (or upload a file) and it scans for hardcoded credentials — API keys, passwords, tokens — then coaches you through fixing them the right way, with environment variables instead of guesswork.

## Features

- **Detection** — regex pattern matching (AWS keys, GitHub tokens, generic passwords/secrets) combined with Shannon entropy analysis to catch high-randomness strings that don't match a known format
- **Secret masking** — any detected credential is redacted before the code is ever sent to Claude, and before it's shown back in the chat
- **AI diagnostics** — Claude explains each finding, why it's risky, and how to fix it
- **Interactive coaching loop** — keep resubmitting your code until it's clean
- **Auth** — username/password accounts with PBKDF2-hashed passwords and a real-time password strength meter
- **Gamification** — achievements for hitting scanning milestones (first scan, clean sheet, fixing credentials, streaks)
- **Session summaries** — Claude-generated recap of what you found and fixed
- **File upload** — scan `.py`, `.js`, `.ts`, `.env`, `.yaml`, `.yml`, `.json`, `.txt` files directly
- **Placeholder mode** — the app runs fully without an API key; AI responses show a placeholder instead of crashing

## Running locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Then open the local URL Streamlit prints (usually `http://localhost:8501`).

## Configuration

Copy `.env.example` to `.env` and fill in:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
COOKIE_SECRET=a-long-random-string
```

- `ANTHROPIC_API_KEY` enables real AI responses (Claude). Without it, the app still runs — detection, masking, auth, and achievements all work, and AI responses show a placeholder message.
- `COOKIE_SECRET` signs the "Remember me" login cookie. Use a long random string in production; anyone with this value could forge a login cookie.

## Architecture notes

- All chat and scan state lives in `st.session_state` — nothing persists across a page reload except login.
- User accounts are the one exception to "no persistence": they're stored in a local, git-ignored `users.json` (hashed passwords only, never plaintext). On Streamlit Cloud this file resets on every redeploy, so accounts don't survive deploys — an accepted limitation for this demo, not a bug.
- Detected credentials are masked *before* code is sent to the Claude API or displayed in the chat transcript.

## Tech stack

- [Streamlit](https://streamlit.io/) (deployed to Streamlit Cloud)
- [Claude API](https://docs.claude.com/) via the `anthropic` SDK
- Python 3.9+
