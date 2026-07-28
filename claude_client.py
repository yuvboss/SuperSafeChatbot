from __future__ import annotations

import os
import re
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """You are Secure Coding Chatbot, an expert security mentor for developers. Your job is to:
1. Explain why detected credentials are dangerous in clear, friendly language
2. Show the developer exactly how to fix the issue using .env files and os.getenv()
3. Generate short educational lessons when asked about security concepts
4. Encourage iteration, praise improvement, guide them toward the correct fix

Always be encouraging, never alarmist. Focus on teaching, not just flagging. Keep responses concise and actionable."""

MODEL = "claude-sonnet-4-6"

_PLACEHOLDER_RESPONSE = (
    "*(AI response placeholder, add `ANTHROPIC_API_KEY` to your `.env` file to enable real responses.)*\n\n"
    "Once connected, Secure Coding Chatbot will explain any findings, show you exactly how to fix them using "
    "environment variables, and coach you toward secure code."
)

_SUMMARY_PLACEHOLDER = (
    "**Session Summary** *(placeholder, add `ANTHROPIC_API_KEY` to enable AI summaries)*\n\n"
    "Once connected, Secure Coding Chatbot will recap: credentials found, what you fixed, "
    "key lessons learned, and suggested next steps."
)


def _has_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def stream_response(messages: list):
    if not _has_key():
        yield _PLACEHOLDER_RESPONSE
        return
    client = Anthropic()
    with client.messages.stream(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=messages,
    ) as stream:
        for text in stream.text_stream:
            yield text


_FIX_CODE_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)

_FIX_PLACEHOLDER = {
    "explanation": _PLACEHOLDER_RESPONSE,
    "fixed_code": None,
    "raw_response": _PLACEHOLDER_RESPONSE,
}


def _parse_fix_response(text: str) -> dict:
    """Split a generate_fix() response into explanation prose and an optional
    fixed-code block. Falls back to treating the whole reply as explanation
    (fixed_code=None) if the model didn't follow the requested format."""
    marker = "FIXED_CODE:"
    if marker not in text:
        return {"explanation": text.strip(), "fixed_code": None, "raw_response": text}

    explanation, _, rest = text.partition(marker)
    explanation = explanation.replace("EXPLANATION:", "", 1).strip()

    fence_match = _FIX_CODE_FENCE_RE.search(rest)
    fixed_code = fence_match.group(1).rstrip("\n") if fence_match else None

    return {"explanation": explanation, "fixed_code": fixed_code, "raw_response": text}


def generate_fix(filename: str, findings: list, masked_code: str, history: list | None = None) -> dict:
    """Ask Claude to explain the findings AND propose a corrected version of
    the file. `history` is the prior api_messages conversation, so this call
    stays in context like the other chat turns. Returns
    {"explanation": str, "fixed_code": str | None, "raw_response": str};
    fixed_code is None whenever no fix could be parsed out, which callers use
    to decide whether to show a diff at all."""
    findings_summary = "\n".join(
        f"- Line {f['line_number']}: {f['type']} (detected via {f['method']})" for f in findings
    )
    user_content = (
        f"I submitted `{filename}` for security scanning. Findings:\n\n{findings_summary}\n\n"
        f"Sanitized code (secrets replaced with [REDACTED]):\n```\n{masked_code}\n```\n\n"
        "Respond in exactly this format, with no extra text before or after:\n\n"
        "EXPLANATION:\n"
        "<explain each finding, why it's dangerous, and how to fix it using environment variables>\n\n"
        "FIXED_CODE:\n"
        "```\n"
        "<the complete corrected file content, with every flagged value replaced by an environment-variable "
        "lookup appropriate for the file's language (e.g. os.getenv() in Python), and nothing else changed>\n"
        "```"
    )

    if not _has_key():
        placeholder = dict(_FIX_PLACEHOLDER)
        placeholder["api_user_content"] = user_content
        return placeholder

    client = Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=1536,
        system=SYSTEM_PROMPT,
        messages=(history or []) + [{"role": "user", "content": user_content}],
    )
    result = _parse_fix_response(response.content[0].text)
    result["api_user_content"] = user_content
    return result


def generate_summary(messages: list) -> str:
    if not _has_key():
        return _SUMMARY_PLACEHOLDER
    client = Anthropic()
    summary_prompt = (
        "Please give me a concise session summary covering: "
        "1) What hardcoded credentials were found, "
        "2) What I fixed during this session, "
        "3) Key security lessons from this session, "
        "4) Suggested next steps to improve my security practices."
    )
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=messages + [{"role": "user", "content": summary_prompt}],
    )
    return response.content[0].text
