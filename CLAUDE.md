# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SuperSafe is a Streamlit web app that acts as an AI-powered security mentor. It helps developers identify and fix hardcoded credentials (API keys, passwords, secrets) in submitted code, then coaches them to remediate using environment variables.

## Tech Stack

- **Language:** Python
- **Web framework:** Streamlit (deployed to Streamlit Cloud)
- **AI engine:** Claude API (`anthropic` SDK)
- **Version control:** GitHub — github.com/yuvboss/SuperSafeChatbot

## Running the App

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Key Architecture Constraints

- **No persistence:** All state lives in `st.session_state`. Nothing is written to disk or a database.
- **Secret masking:** Any detected credentials in user-submitted code must be redacted/masked *before* the code is sent to the Claude API. Never send raw secrets to the model.
- **Deployable:** The app must run cleanly on Streamlit Cloud — avoid local-only dependencies.

## Detection Logic

Two methods are used together to flag hardcoded credentials:

1. **Regex pattern matching** — targets known formats (AWS keys, GitHub tokens, generic `password =`, etc.)
2. **Shannon entropy analysis** — flags high-randomness strings with entropy > 4.5 bits, which are likely secrets even without a known format

## Core Features

- **Educational modules:** Text lessons on why hardcoded secrets are dangerous and how to use `.env` + `os.getenv()` correctly
- **AI diagnostics:** Submit code → detect issues → explain findings via Claude
- **Interactive loop:** Users iterate and resubmit until the issue is resolved; the chatbot mentors toward the correct fix

## Stretch Goals (not required for MVP)

- Gamification: achievements for remediating flagged issues
- Session summaries: AI-generated recap of mistakes and growth areas
