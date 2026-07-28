import difflib
import html

_DIFF_CSS = """
<style>
.diff-box {
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 0.82rem; line-height: 1.5; border-radius: 10px; overflow: auto;
    max-height: 420px; border: 1px solid rgba(127,127,127,0.25); padding: 0.5rem 0;
}
.diff-line { white-space: pre; padding: 0 0.75rem; }
.diff-add { background: rgba(48,164,108,0.18); color: #1a7f4b; }
.diff-del { background: rgba(229,72,77,0.16); color: #c53030; }
.diff-hunk { color: #8b5cf6; opacity: 0.8; margin: 0.25rem 0; }
.diff-ctx { opacity: 0.65; }
@media (prefers-color-scheme: dark) {
    .diff-add { background: rgba(48,164,108,0.22); color: #6fe3a5; }
    .diff-del { background: rgba(229,72,77,0.22); color: #ff8a8a; }
}
</style>
"""

_CLASS_FOR_PREFIX = {"+": "diff-add", "-": "diff-del", "@": "diff-hunk"}


def unified_diff_html(old_code: str, new_code: str, old_label: str = "Before", new_label: str = "After") -> str:
    """Render a red(removed)/green(added) unified diff as a self-contained HTML block."""
    diff_lines = difflib.unified_diff(
        old_code.splitlines(), new_code.splitlines(),
        fromfile=old_label, tofile=new_label, lineterm="", n=3,
    )

    rows = []
    for line in diff_lines:
        if line.startswith("+++") or line.startswith("---"):
            continue
        css_class = _CLASS_FOR_PREFIX.get(line[:1], "diff-ctx")
        rows.append(f'<div class="diff-line {css_class}">{html.escape(line)}</div>')

    if not rows:
        rows.append('<div class="diff-line diff-ctx">(no differences)</div>')

    return _DIFF_CSS + f'<div class="diff-box">{"".join(rows)}</div>'
