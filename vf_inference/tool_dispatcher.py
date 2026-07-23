from __future__ import annotations

import re
from pathlib import Path


# Sentinel returned when the LLM decides inference is complete.
ACTION_GENERATE_CODE = "__GENERATE_CODE__"


def dispatch(action: str, smali_dir: str, credentials: dict) -> str:

    action = action.strip()

    if action.startswith("search_function("):
        args = _parse_args(action, "search_function")
        if len(args) >= 2:
            file_path, function_name = args[0], args[1]
            return tool_search_function(smali_dir, file_path, function_name)
        return "Error: search_function requires (file_path, function_name)"

    if action.startswith("retrieve_credential("):
        args = _parse_args(action, "retrieve_credential")
        if args:
            return tool_retrieve_credential(args[0], credentials)
        return "Error: retrieve_credential requires (parameter)"

    if action.startswith("generate_code"):
        return ACTION_GENERATE_CODE

    return f"Error: Unknown action '{action}'"


# ─── Tool: search_function ────────────────────────────────────────────────────

def tool_search_function(smali_dir: str, file_path: str, function_name: str) -> str:

    # Collect candidate files
    target = Path(smali_dir) / file_path
    if target.exists():
        candidates = [target]
    else:
        candidates = list(Path(smali_dir).rglob(Path(file_path).name))

    if not candidates:
        return f"Error: file not found — '{file_path}'"

    # Try each candidate until we find the method
    for candidate in candidates:
        if candidate.is_dir():
            continue
        lines = candidate.read_text(errors="ignore").splitlines()
        result = _extract_method(lines, function_name, str(candidate))
        if not result.startswith("Error:"):
            return result

    # Method not found in any candidate
    return f"Error: method '{function_name}' not found in any file matching '{file_path}'"


def _extract_method(lines: list[str], function_name: str, source_path: str) -> str:

    # Strip full signature down to just the method name
    search_name = function_name
    if "(" in search_name:
        search_name = search_name.split("(", 1)[0]

    # Pattern: .method [modifiers...] methodName(
    # Method names can be: alphanumeric identifiers, <init> (constructor),
    # or <clinit> (static initializer).
    _METHOD_RE = re.compile(r"\.method\s+(?:.*\s)?([\w<>]+)\(.*\)")

    result: list[str] = []
    depth = 0  # track nested .method/.end method blocks

    for line in lines:
        stripped = line.strip()

        # Detect method start — exact name match only
        if stripped.startswith(".method"):
            m = _METHOD_RE.match(stripped)
            if m and m.group(1) == search_name:
                depth = 1
                result.append(line)
                continue

        if depth > 0:
            result.append(line)
            # Track nested method blocks (rare in Smali but defensive)
            if stripped.startswith(".method"):
                depth += 1
            if stripped == ".end method":
                depth -= 1
                if depth == 0:
                    break

    if result:
        return "\n".join(result)
    return f"Error: method '{search_name}' not found in '{source_path}'"


# ─── Tool: retrieve_credential ────────────────────────────────────────────────

def tool_retrieve_credential(parameter: str, credentials: dict) -> str:

    # Exact match first
    if parameter in credentials:
        return f"{parameter} = {credentials[parameter]}"

    # Case-insensitive fallback
    lower_param = parameter.lower()
    for key, value in credentials.items():
        if key.lower() == lower_param:
            return f"{key} = {value}"

    return (
        f"Error: credential '{parameter}' not found. "
        f"Available keys: {list(credentials.keys())}. "
        f"Please provide the value manually."
    )


# ─── Argument Parser ──────────────────────────────────────────────────────────

def _parse_args(action: str, func_name: str) -> list[str]:

    # Find the opening parenthesis after func_name
    prefix = func_name + "("
    start = action.find(prefix)
    if start == -1:
        return []
    start += len(prefix)

    # Count parentheses to find the matching closing paren
    depth = 1
    for i in range(start, len(action)):
        if action[i] == "(":
            depth += 1
        elif action[i] == ")":
            depth -= 1
            if depth == 0:
                raw = action[start:i]
                return [a.strip().strip("'\"") for a in raw.split(",", 1)]
    return []
