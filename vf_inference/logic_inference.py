from __future__ import annotations

import json
import re

import config
from .llm_client import call_llm
from .tool_dispatcher import dispatch, ACTION_GENERATE_CODE

INFERENCE_SYSTEM_PROMPT = """
@Persona: You are a Smali code analyst who needs to reason step by step
from the code to infer the generation logic of the target field.

@Terminology:
1. search_function(file_path, function_name):
   - Used to search for the specific implementation of a given function
     within a Smali file.
2. retrieve_credential(parameter):
   - Used to obtain the concrete value of a credential-type parameter
     (such as secret, secretKey, etc.).
3. generate_code():
   - Used when you have FULLY understood the algorithm and are ready to
     output it as a step-by-step specification that a programmer can
     translate to Python mechanically.

@Instructions:
1. Analyze the current Smali code context and identify which parts of
   the target field's generation logic remain unresolved.
2. Based on the context, infer the next action to perform:
   - If further details of a function implementation are needed, use
     search_function(file_path, function_name).
   - If the concrete value of a key or credential is needed, use
     retrieve_credential(parameter).
   - If the generation logic and all dependent parameters are fully
     resolved, execute generate_code().

3. CRITICAL — When calling generate_code(), your analysis_reasoning
   MUST begin with a numbered, step-by-step ALGORITHM SPECIFICATION.
   The spec is the ONLY thing the programmer sees — they cannot read
   smali.  Every step must be explicit enough to code from directly.

   YOUR analysis_reasoning MUST start with "1. " (a numbered list).
   If your reasoning does not start with a numbered list, the
   programmer will NOT be able to implement the algorithm.

   For EVERY step, specify:
   - EXACT data sources (which request fields, which header names)
   - EXACT transformations (hash function, encoding, case conversion)
   - EXACT string formats (use templates showing every \n and section)
   - For multi-section strings: show the join expression with ALL
     sections labelled, e.g. '\\n'.join([method, path, '', headers, signed, hash])
   - For HMAC: name the EXACT string being signed

@Format:
{
  "analysis_reasoning": "<numbered step-by-step algorithm spec>",
  "next_action": "generate_code()"
}

@Input:
Target Field: ${target_field}$
Source Function: ${source_functions}$
"""


def run_iterative_inference(
    ctx: dict,
    smali_dir: str,
    credentials: dict,
) -> tuple[dict, list[dict]]:

    chat_history: list[dict] = []

    return _inference_loop(ctx, smali_dir, credentials, chat_history,
                           config.MAX_INFERENCE_ITERATIONS)


def run_inference_with_codegen(
    ctx: dict,
    smali_dir: str,
    credentials: dict,
    vf_list: list[str],
    ephemeral_analyses: str = "",
) -> tuple[dict, list[dict], str]:
    """
    Run inference AND code generation in the SAME chat.

    1. Standard inference loop (search smali, analyse algorithm).
    2. When the LLM signals generate_code(), the analysis is recorded.
    3. A code-gen prompt is appended as the NEXT user message in the
       SAME conversation.
    4. The LLM generates Python code in the same chat context.
    5. Returns (ctx, full_chat_history, generated_code).
    """
    chat_history: list[dict] = []

    # ── Phase 1: Inference loop ──
    ctx, chat_history = _inference_loop(
        ctx, smali_dir, credentials, chat_history,
        config.MAX_INFERENCE_ITERATIONS,
    )

    # ── Phase 2: Code generation (same chat, same model) ──
    print("  [Stage 2.3] Generating code...")

    code_prompt = _build_code_gen_prompt(
        ctx["target_field"], vf_list, ephemeral_analyses,
    )

    # Build the full message list for the code-gen call
    initial_context = (
        f"Target Field: {ctx['target_field']}\n\n"
        f"Source Function Context:\n"
        + json.dumps(ctx.get("source_functions", []), indent=2)
        + f"\n\nAdditional Context:\n{ctx.get('extra_context', 'None')}"
    )

    messages = [{"role": "user", "content": initial_context}]
    messages.extend(chat_history)
    messages.append({"role": "user", "content": code_prompt})

    raw = call_llm(
        system=CODE_GEN_IN_CHAT_PROMPT,
        messages=messages,
        model=config.CODEGEN_MODEL,       # v4-flash for stable code-gen
        reasoning_effort=None,            # no reasoning needed for translation
        enable_thinking=False,
    )

    code = _strip_fences(raw)

    # Record the code-gen exchange in chat history
    chat_history.append({"role": "user", "content": code_prompt})
    chat_history.append({
        "role": "assistant",
        "content": json.dumps({"_generated_code": code}),
    })

    return ctx, chat_history, code


def _build_code_gen_prompt(
    primary_field: str,
    vf_list: list[str],
    ephemeral_analyses: str,
) -> str:
    """Build the user message that triggers code generation in-chat."""
    parts = [
        f"Based on your analysis of '{primary_field}' above, "
        f"generate the complete Python code.",
        "",
        f"VF fields to handle: {', '.join(vf_list)}",
    ]
    if ephemeral_analyses:
        parts.extend([
            "",
            "=" * 50,
            "EPHEMERAL VF ANALYSES (from earlier conversations):",
            "=" * 50,
            ephemeral_analyses,
        ])

    parts.extend([
        "",
        "CODE REQUIREMENTS:",
        "- def update_vf(request: dict) -> dict",
        "- request keys: headers(dict), query(dict), body(str|dict|None), method(str), path(str)",
        "- Ephemeral VFs (timestamp/date): generate ONLY if missing from headers; keep existing values",
        "- Signature VFs: ALWAYS recompute from current request state",
        "- Body: None/''→b'', str→.encode(), dict→json.dumps().encode()",
        "- Content hash: if 'x-sdk-content-sha256' in headers, USE it; else SHA256(body)",
        "- Use request.get('method','GET'), .get('path','/'), .get('headers',{}), .get('query',{})",
        "- Credentials: ACCESS_KEY='PLACEHOLDER_ACCESS', SECRET_KEY='PLACEHOLDER_SECRET'",
        "- Imports: hashlib, hmac, json, datetime, uuid, urllib.parse only",
        "- Output ONLY valid Python code — no markdown fences, no explanation.",
    ])
    return "\n".join(parts)


# ─── Code-gen system prompt (used as the system message for the ────────  

CODE_GEN_IN_CHAT_PROMPT = """
@Persona: You are a programmer who has just finished analysing smali
bytecode.  The conversation above contains your full analysis — you
have read the smali, understood the algorithm, and are ready to code.

@Instructions:
1. Read the user's code-generation request below carefully.
2. Using YOUR OWN analysis from the conversation above, write a
   complete Python function that implements the algorithm exactly.
3. Every detail from your smali analysis is authoritative — follow it
   precisely.  Do not guess or use external knowledge.
4. Output ONLY valid Python code — no markdown fences, no preamble,
   no explanation.
"""


def _strip_fences(text: str) -> str:
    import re
    text = re.sub(r"```[a-z]*\s*", "", text)
    text = re.sub(r"~~~\s*", "", text)
    text = re.sub(r"^\s*python\s*\n", "\n", text, flags=re.IGNORECASE)
    return text.strip()


def resume_inference_for_refine(
    ctx: dict,
    smali_dir: str,
    credentials: dict,
    chat_history: list[dict],
    failing_code: str,
    verification_feedback: str,
    max_iterations: int | None = None,
) -> tuple[dict, list[dict]]:
    """
    Resume the inference loop after code verification failed.

    Appends the generated code and verification failure to the chat history,
    then lets the LLM continue exploring smali with full tool access
    (search_function, retrieve_credential, etc.) to debug its own code.

    When the LLM is confident it has fixed the issue, it calls generate_code().
    """
    if max_iterations is None:
        max_iterations = config.MAX_INFERENCE_ITERATIONS

    # Append the failing code and verification feedback to chat history
    chat_history.append({
        "role": "assistant",
        "content": json.dumps({
            "_generated_code": failing_code,
            "analysis_reasoning": (
                "I have generated Python code implementing the VF logic and it "
                "was verified against real traffic. The verification FAILED."
            ),
        }),
    })

    # Truncate code in feedback to avoid blowing up context
    code_snippet = (
        failing_code[:2000] + "\n...[truncated]"
        if len(failing_code) > 2000 else failing_code
    )

    chat_history.append({
        "role": "user",
        "content": (
            f"The code you generated was verified against real traffic and FAILED.\n\n"
            f"Verification output:\n{verification_feedback}\n\n"
            f"Your generated code (first 2000 chars):\n{code_snippet}\n\n"
            f"You may use search_function, retrieve_credential, etc. to "
            f"investigate the smali code further and find the root cause of "
            f"the mismatch. When you have identified and fixed the bug, "
            f"call generate_code() to produce the corrected script."
        ),
    })

    return _inference_loop(ctx, smali_dir, credentials, chat_history,
                           max_iterations)


def _inference_loop(
    ctx: dict,
    smali_dir: str,
    credentials: dict,
    chat_history: list[dict],
    max_iterations: int,
) -> tuple[dict, list[dict]]:
    """Core inference loop — shared by initial inference and refine-resume."""
    for iteration in range(max_iterations):
        print(f"  [inference iter {iteration + 1}] Calling LLM...")

        result = _llm_infer_next_action(ctx, chat_history)
        reasoning = result.get("analysis_reasoning", "")
        action = result.get("next_action", "generate_code()")

        print(f"  Reasoning: {reasoning[:120]}...")
        print(f"  Action:    {action}")

        chat_history.append({"role": "assistant", "content": json.dumps(result)})

        # Algorithm 2, Line 10: res <- DispatchTool(action, D)
        tool_result = dispatch(action, smali_dir, credentials)

        if tool_result == ACTION_GENERATE_CODE:
            print("  [*] LLM signals generate_code — exiting inference loop.")
            break

        # Algorithm 2, Line 11: ctx <- UpdateContext(ctx, res)
        ctx["extra_context"] += f"\n\n[Tool: {action}]\n{tool_result}"
        chat_history.append({"role": "user", "content": f"Tool result:\n{tool_result}"})

    else:
        print(f"  [!] Reached max inference iterations ({config.MAX_INFERENCE_ITERATIONS}).")

    return ctx, chat_history


# ─── LLM Call ─────────────────────────────────────────────────────────────────

def _llm_infer_next_action(ctx: dict, chat_history: list[dict]) -> dict:
    """Call the LLM with the full conversation history for context continuity."""
    # Build the initial user message with static context
    initial_context = (
        f"Target Field: {ctx['target_field']}\n\n"
        f"Source Function Context:\n"
        + json.dumps(ctx.get("source_functions", []), indent=2)
        + f"\n\nAdditional Context:\n{ctx.get('extra_context', 'None')}"
    )

    # First call: just the initial context
    if not chat_history:
        messages = [{"role": "user", "content": initial_context}]
    else:
        # Subsequent calls: include full history for context continuity
        messages = list(chat_history)  # copy

    raw = call_llm(
        system=INFERENCE_SYSTEM_PROMPT,
        messages=messages,
    )

    try:
        clean = re.sub(r"```json|```", "", raw).strip()
        return json.loads(clean)
    except json.JSONDecodeError:
        return {"analysis_reasoning": raw, "next_action": "generate_code()"}