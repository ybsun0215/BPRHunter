from __future__ import annotations

import json
import re

import config
from .llm_client import call_llm


REFINE_SYSTEM_PROMPT = """
@Persona: You are a programmer fixing broken Python code by
cross-referencing it against the smali bytecode.

The smali bytecode and/or algorithm specification is provided as
context.  The code you wrote failed verification against real traffic.

Instructions:
1. Read the failing code, the verification error, and the smali context.
2. Find the mismatch between the code and the smali/algorithm.
3. Fix ONLY the bug — do not rewrite working logic.
4. Pay special attention to:
   - Canonical string structure (count the \n sections in smali!)
   - Content hash source (x-demo-content-sha256 header vs SHA256(body))
   - HMAC target (is it signing string-to-sign or canonical request?)
   - Header sorting (case-insensitive in smali?)
   - Path encoding (URL encoding rules in smali)
5. Output ONLY the corrected Python code — no markdown fences, no explanation.
"""


# ---------------------------------------------------------------------------
# Extract inference conclusions from chat history (local, no LLM call)
# ---------------------------------------------------------------------------

def _extract_inference_conclusions(
    history: list[dict],
) -> str:
    # ── 1. Extract final algorithm spec & smali tool results ──
    final_spec = ""
    smali_snippets: list[str] = []
    reasoning_parts: list[str] = []

    for msg in history:
        role = msg.get("role", "")
        content_text = msg.get("content", "")

        if role == "assistant":
            try:
                data = json.loads(msg.get("content", "{}"))
                action = data.get("next_action", "")
                reasoning = data.get("analysis_reasoning", "")
                if "generate_code" in action and reasoning:
                    final_spec = reasoning
                elif reasoning:
                    reasoning_parts.append(reasoning[:300])
            except (json.JSONDecodeError, TypeError):
                pass

        elif role == "user" and "Tool result:" in content_text:
            # Extract the smali method body (after the header line)
            smali = content_text
            # Keep full smali — it IS the authoritative source
            smali_snippets.append(smali)

    # ── 2. Build output based on spec quality ──
    parts: list[str] = []

    if len(final_spec) > 500:
        # Detailed spec available — use as primary
        parts.append("=" * 60)
        parts.append("ALGORITHM SPECIFICATION — follow this EXACTLY:")
        parts.append("=" * 60)
        parts.append(final_spec)
        # Add smali as supplementary reference (truncated to save context)
        if smali_snippets:
            parts.append("")
            parts.append("=" * 60)
            parts.append("REFERENCE SMALI (supplementary — spec above is authoritative):")
            parts.append("=" * 60)
            for s in smali_snippets:
                parts.append(s[:2000])
    else:
        # No detailed spec — smali is the primary source
        if final_spec:
            parts.append(f"NOTE: The inference LLM only said: {final_spec}")
        parts.append("=" * 60)
        parts.append("SMALI BYTECODE — this IS the authoritative algorithm source.")
        parts.append("You MUST read the bytecode and implement the EXACT logic.")
        parts.append("=" * 60)
        for s in smali_snippets:
            parts.append(s)  # full smali, no truncation
        # Add inference reasoning as supplementary
        if reasoning_parts:
            parts.append("")
            parts.append("=" * 60)
            parts.append("INFERENCE ANALYSIS (supplementary guide):")
            parts.append("=" * 60)
            parts.append("\n".join(reasoning_parts))

    return "\n\n".join(parts)


def _extract_code_from_chat_history(history: list[dict] | None) -> str:
    """Extract generated Python code from chat history."""
    if not history:
        return ""
    for msg in reversed(history):
        if msg.get("role") != "assistant":
            continue
        try:
            data = json.loads(msg.get("content", "{}"))
            code = data.get("_generated_code", "")
            if code and "def update_vf" in code:
                return code
        except (json.JSONDecodeError, TypeError):
            # Raw code output (not JSON-wrapped)
            content = msg.get("content", "")
            if "def update_vf" in content:
                return _strip_fences(content)
    return ""


def refine_domain_script(
    code: str,
    feedback: str,
    context: str = "",
) -> str:
    """Re-call the LLM with the failing code, feedback, and optionally the
    original inference analysis so it can cross-check its algorithm."""
    user_msg = (
        f"The generated code failed verification.\n"
        f"Feedback: {feedback}\n\n"
    )
    if context:
        user_msg += (
            f"REFERENCE — the smali inference analysis your code must implement:\n"
            f"{context}\n\n"
            f"Cross-check your code against this analysis line by line. "
            f"The bug is in your implementation.\n\n"
        )
    user_msg += "Please fix the code. Output only valid Python."
    messages = [
        {"role": "assistant", "content": code},
        {"role": "user", "content": user_msg},
    ]
    raw = call_llm(
        system=REFINE_SYSTEM_PROMPT,
        messages=messages,
        model=config.CODEGEN_MODEL,
        reasoning_effort=None,
        enable_thinking=False,
    )
    return _strip_fences(raw)


def _strip_fences(text: str) -> str:
    import re
    # Strip markdown code fences: ```python, ```, ~~~
    text = re.sub(r"```[a-z]*\s*", "", text)
    text = re.sub(r"~~~\s*", "", text)
    # Strip leading "python" language tag on its own line
    text = re.sub(r"^\s*python\s*\n", "\n", text, flags=re.IGNORECASE)
    return text.strip()
