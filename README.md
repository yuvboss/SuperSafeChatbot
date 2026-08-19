# Secure Coding Chatbot 🔐

*A SuperSafe product.*

Secure Coding Chatbot is an AI-powered security mentor for developers. Paste in code, upload a file, or upload a `.zip` of a whole directory, and it scans for hardcoded credentials, API keys, passwords, tokens, then coaches you through fixing them the right way, with environment variables instead of guesswork.

## Features

- **Detection**, regex pattern matching (AWS keys, GitHub tokens, generic passwords/secrets) combined with Shannon entropy analysis to catch high-randomness strings that don't match a known format
- **Secret masking**, any detected credential is redacted before the code is ever sent to Claude, and before it's shown back in the chat
- **AI diagnostics**, Claude explains each finding, why it's risky, and how to fix it
- **Suggested fixes with review**, when there's a real finding, Claude proposes a corrected version of the file, shown as a red/green diff against your (masked) original; Accept downloads the fixed file, Deny leaves it untouched, and either way Claude follows up explaining exactly what changed and why once you've decided
- **Directory scanning**, upload a `.zip` of a project instead of one file at a time; each flagged file gets its own diff and Accept/Deny, then "Build & Download Fixed Zip" hands back the archive with only the accepted fixes applied
- **Interactive coaching loop**, keep resubmitting your code until it's clean
- **Lessons**, each lesson opens its own private chat thread with Claude, separate from the main scan chat, and stays available to resume for the rest of the session
- **Auth**, username/password accounts with PBKDF2-hashed passwords and a real-time password strength meter
- **Gamification**, achievements for hitting scanning milestones (first scan, clean sheet, fixing credentials, streaks)
- **Session summaries**, Claude-generated recap of what you found and fixed
- **File upload**, scan `.py`, `.js`, `.ts`, `.env`, `.yaml`, `.yml`, `.json`, `.txt` files directly, or a `.zip` of a directory
- **Placeholder mode**, the app runs fully without an API key; AI responses show a placeholder instead of crashing (fix diffs are unavailable in this mode since there's no AI to generate them)

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
GEMINI_API_KEY=your-gemini-api-key-here
COOKIE_SECRET=a-long-random-string
```

- `GEMINI_API_KEY` enables real AI responses (Gemini). Without it, the app still runs, detection, masking, auth, and achievements all work, and AI responses show a placeholder message.
- `COOKIE_SECRET` signs the "Remember me" login cookie. Use a long random string in production; anyone with this value could forge a login cookie.

## Architecture notes

- All chat and scan state lives in `st.session_state`, nothing persists across a page reload except login.
- User accounts are the one exception to "no persistence", stored in a local, git-ignored `users.json` (hashed passwords only, never plaintext). On Streamlit Cloud this file resets on every redeploy, so accounts don't survive deploys, an accepted limitation for this demo, not a bug.
- Detected credentials are masked *before* code is sent to the Gemini API or displayed in the chat transcript.
- Directory scans are handled entirely in memory (extract, scan, rebuild), with limits on file count/size to guard against oversized or malicious archives; there's no way for a hosted app to write back to your local filesystem, so "applying" fixes means downloading a rebuilt `.zip`, not an in-place overwrite.
- Lesson chats are separate threads kept in session state alongside the main chat; they persist for the session but reset on reload, same as everything else except login.

## Tech stack

- [Streamlit](https://streamlit.io/) (deployed to Streamlit Cloud)
- [Gemini API](https://ai.google.dev/gemini-api/docs) via the `google-genai` SDK
- Python 3.9+
