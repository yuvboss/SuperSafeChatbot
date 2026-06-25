import os
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """You are SuperSafe, an expert security mentor for developers. Your job is to:
1. Explain why detected credentials are dangerous in clear, friendly language
2. Show the developer exactly how to fix the issue using .env files and os.getenv()
3. Generate short educational lessons when asked about security concepts
4. Encourage iteration — praise improvement, guide them toward the correct fix

Always be encouraging, never alarmist. Focus on teaching, not just flagging. Keep responses concise and actionable."""

MODEL = "claude-sonnet-4-6"

_PLACEHOLDER_RESPONSE = (
    "*(AI response placeholder — add `ANTHROPIC_API_KEY` to your `.env` file to enable real responses.)*\n\n"
    "Once connected, SuperSafe will explain any findings, show you exactly how to fix them using "
    "environment variables, and coach you toward secure code."
)

_SUMMARY_PLACEHOLDER = (
    "**Session Summary** *(placeholder — add `ANTHROPIC_API_KEY` to enable AI summaries)*\n\n"
    "Once connected, SuperSafe will recap: credentials found, what you fixed, "
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
