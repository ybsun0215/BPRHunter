from __future__ import annotations

import re
from pathlib import Path


# Sentinel returned when the LLM decides inference is complete.
ACTION_GENERATE_CODE = "__GENERATE_CODE__"

VALID_ACTIONS = (
    "search_function(file_path, function_name)",
    "search_text(pattern, file_filter?)",
    "retrieve_credential(parameter)",
    "generate_code()",
)

# Extracts the leading identifier of an action string, e.g. "search_function"
# from "search_function('a', 'b')" or from a bare "search_function".
_ACTION_NAME_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$", re.DOTALL)

# Pattern: .method [modifiers...] methodName(
_METHOD_RE = re.compile(r"\.method\s+(?:.*\s)?([\w<>]+)\(")


def dispatch(action: str, smali_dir: str, credentials: dict,
             result: dict | None = None) -> str:
    """Dispatch an LLM-decided action and return the tool result string.

    Tolerates the action shapes seen in practice instead of failing on the
    first deviation:

    - inline calls with or without quoted arguments:
      ``search_function('a.smali', 'foo')`` / ``search_function(a.smali, foo)``
    - a bare action name whose arguments live in sibling JSON fields
      (``{"next_action": "search_function", "file_path": ..., "function_name": ...}``)
    - an action name embedded in prose
      (``"I will call search_function('a', 'foo') now"``)
    - surrounding whitespace / parentheses spacing

    Every failure path returns an instructive error that tells the LLM the
    valid syntax, so the natural next turn is a corrected retry rather than
    abandoning the tool.
    """
    result = result or {}
    action = str(action or "").strip()

    m = _ACTION_NAME_RE.match(action)
    name = m.group(1) if m else ""
    rest = m.group(2) if m else ""

    # The action name may be embedded in prose — recover the first known tool.
    _KNOWN = ("search_function", "search_text", "retrieve_credential", "generate_code")
    if name not in _KNOWN:
        lowered = action.lower()
        for known in _KNOWN:
            idx = lowered.find(known)
            if idx != -1:
                return dispatch(action[idx:], smali_dir, credentials, result)
        return _unknown_action_error(action)

    if name == "generate_code":
        return ACTION_GENERATE_CODE

    if name == "search_function":
        args = _parse_args(rest)
        if len(args) < 2:
            args = _args_from_result(
                result,
                ("file_path", "path", "file"),
                ("function_name", "func_name", "function", "method_name"),
            )
        if len(args) >= 2:
            return tool_search_function(smali_dir, args[0], args[1])
        return _usage_error("search_function", "file_path, function_name")

    if name == "search_text":
        args = _parse_args(rest)
        if not args:
            p = result.get("pattern") or result.get("query") or result.get("text")
            f = result.get("file_filter") or result.get("file")
            if p:
                args = [str(p)] + ([str(f)] if f else [])
        if args:
            return tool_search_text(
                smali_dir, args[0], args[1] if len(args) > 1 else None,
            )
        return _usage_error("search_text", "pattern, file_filter?")

    # name == "retrieve_credential"
    args = _parse_args(rest)
    if not args:
        args = _args_from_result(result, ("parameter", "param", "name"), ())
    if args:
        return tool_retrieve_credential(args[0], credentials)
    return _usage_error("retrieve_credential", "parameter")


# ─── Tool: search_function ────────────────────────────────────────────────────

def tool_search_function(smali_dir: str, file_path: str, function_name: str) -> str:

    smali_root = Path(smali_dir)
    raw = str(file_path).strip().strip("'\"").replace("\\", "/")
    basename = Path(raw).name

    # Collect candidate files, from most to least specific.
    candidates: list[Path] = []

    direct = smali_root / raw
    if direct.is_file():
        candidates.append(direct)

    if not candidates and raw:
        # An absolute path captured on another machine / layout: if it runs
        # through smali_dir, relativize; otherwise match by basename below.
        root_posix = str(smali_root.resolve()).replace("\\", "/").rstrip("/") + "/"
        if raw.lower().startswith(root_posix.lower()):
            cand = smali_root / raw[len(root_posix):]
            if cand.is_file():
                candidates.append(cand)

    if not candidates and basename:
        candidates = [p for p in smali_root.rglob(basename) if p.is_file()]

    if not candidates:
        return (
            f"Error: file not found — '{file_path}'. "
            f"Retry search_function with a path relative to the smali root "
            f"or just the file name (e.g. '{basename}')."
        )

    # Try each candidate until we find the method
    for candidate in candidates:
        lines = candidate.read_text(errors="ignore").splitlines()
        found = _extract_method(lines, function_name, str(candidate))
        if not found.startswith("Error:"):
            return found

    # Method not found anywhere: show what IS in the file so the model can
    # retry with an exact name instead of dead-ending.
    available = _list_method_names(candidates[0])
    hint = (
        f" Methods declared in '{candidates[0].name}': {', '.join(available)}. "
        f"Retry search_function with the exact method name."
        if available else ""
    )
    return (
        f"Error: method '{function_name}' not found in any file matching "
        f"'{file_path}'.{hint}"
    )


def _extract_method(lines: list[str], function_name: str, source_path: str) -> str:

    # Strip full signature down to just the method name
    search_name = function_name
    if "(" in search_name:
        search_name = search_name.split("(", 1)[0]

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


def _list_method_names(path: Path, limit: int = 40) -> list[str]:
    """Names of the methods declared in a smali file, for retry hints."""
    names: list[str] = []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return names
    for m in _METHOD_RE.finditer(text):
        name = m.group(1)
        if name not in names:
            names.append(name)
        if len(names) >= limit:
            break
    return names


# ─── Tool: search_text (editor-style global search) ──────────────────────────

_HTTP_STACK_HINTS = (
    "okhttp3", "Lokhttp", "org/apache/http", "HttpURLConnection",
    "apache/httpclient",
)

# Corpus is static during a run, so per-file stats are computed once.
_STATS_CACHE: dict[str, dict[str, dict]] = {}


def corpus_stats(smali_dir: str) -> dict[str, dict]:
    """Per-class liveness stats: ``inbound`` = number of method references
    originating in OTHER corpus files, ``http_wired`` = the file touches an
    HTTP client stack (a strong hint it sits on the live request path).
    A class with inbound == 0 and http_wired == False is likely unused
    bundled code (e.g. an orphaned SDK signer)."""
    key = str(Path(smali_dir))
    if key in _STATS_CACHE:
        return _STATS_CACHE[key]

    root = Path(smali_dir)
    texts: dict[str, str] = {}
    try:
        smali_files = list(root.rglob("*.smali"))
    except OSError:
        smali_files = []
    for p in smali_files:
        rel = p.relative_to(root).as_posix()[:-len(".smali")]
        try:
            texts[rel] = p.read_text(errors="ignore")
        except OSError:
            continue

    if len(texts) > 3000:  # defensive cap for very large corpora
        _STATS_CACHE[key] = {}
        return {}

    inbound: dict[str, int] = {rel: 0 for rel in texts}
    for rel, text in texts.items():
        for m in re.finditer(r"L([\w/$-]+);->", text):
            cls = m.group(1)
            if cls != rel and cls in texts:
                inbound[cls] += 1

    stats = {
        rel: {
            "inbound": inbound[rel],
            "http_wired": any(h in text for h in _HTTP_STACK_HINTS),
            "lines": text.count("\n") + 1,
        }
        for rel, text in texts.items()
    }
    _STATS_CACHE[key] = stats
    return stats


def scan_matches(
    smali_dir: str, pattern: str, file_filter: str | None = None,
) -> list[tuple[str, list[tuple[int, str, str | None]]]]:
    """All case-insensitive matches grouped per file, live files first.

    Each hit is (line_number, line_text, enclosing_method) — the enclosing
    method is resolved from .method/.end method boundaries so the LLM knows
    which function a match belongs to without a probe call."""
    root = Path(smali_dir)
    stats = corpus_stats(smali_dir)
    needle = (pattern or "").lower()
    filt = (file_filter or "").strip().strip("'\"").lower().replace("\\", "/")

    groups: list[tuple[str, list[tuple[int, str, str | None]]]] = []
    for p in sorted(root.rglob("*.smali")):
        rel = p.relative_to(root).as_posix()
        if filt and filt not in rel.lower():
            continue
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        if not needle:
            continue
        ranges = _method_ranges(lines)
        hits: list[tuple[int, str, str | None]] = []
        ri = 0
        for i, line in enumerate(lines):
            if needle not in line.lower():
                continue
            lineno = i + 1
            while ri < len(ranges) and lineno > ranges[ri][1]:
                ri += 1
            if ri < len(ranges) and ranges[ri][0] <= lineno <= ranges[ri][1]:
                hits.append((lineno, line.strip(), ranges[ri][2]))
            else:
                hits.append((lineno, line.strip(), None))
        if hits:
            groups.append((rel, hits))

    def liveness(rel: str) -> tuple[bool, int]:
        s = stats.get(rel[:-len(".smali")], {})
        return s.get("http_wired", False), s.get("inbound", 0)

    groups.sort(key=lambda g: (not liveness(g[0])[0], -liveness(g[0])[1], g[0]))
    return groups


def render_search_report(
    smali_dir: str, pattern: str,
    groups: list[tuple[str, list[tuple[int, str, str | None]]]],
    max_files: int = 20, per_file: int = 5,
) -> str:
    """Render groups in the style of an editor search panel:
    'N results - M files', then per file: liveness tags and match lines,
    each annotated with its enclosing method."""
    total = sum(len(h) for _, h in groups)
    if not groups:
        return f"0 results - 0 files (pattern: '{pattern}')"

    stats = corpus_stats(smali_dir)
    out = [f"{total} results - {len(groups)} files "
           f"(pattern: '{pattern}', case-insensitive)"]

    for rel, hits in groups[:max_files]:
        s = stats.get(rel[:-len(".smali")], {})
        tags = [f"inbound refs: {s.get('inbound', '?')}"]
        if s.get("http_wired"):
            tags.append("wired to http stack")
        dead_flag = ""
        if s.get("inbound", 0) == 0 and not s.get("http_wired"):
            dead_flag = "  [no inbound refs — possibly unused code]"
        out.append(f"\n{rel}  [{', '.join(tags)}]{dead_flag}")
        for ln, text, where in hits[:per_file]:
            scope = f"   (in {where})" if where else "   (class scope)"
            out.append(f"  {ln:>6}: {text[:150]}{scope}")
        if len(hits) > per_file:
            out.append(f"         ... +{len(hits) - per_file} more in this file")

    if len(groups) > max_files:
        out.append(f"\n... +{len(groups) - max_files} more files")
    return "\n".join(out)


def tool_search_text(smali_dir: str, pattern: str,
                     file_filter: str | None = None) -> str:
    pattern = str(pattern or "").strip().strip("'\"")
    if not pattern:
        return "Error: search_text requires a non-empty pattern."
    groups = scan_matches(smali_dir, pattern, file_filter)
    return render_search_report(smali_dir, pattern, groups)


# ─── Method-scope resolution (search annotations) ────────────────────────────

_METHOD_HEADER_RE = re.compile(r"^\.method\s+(?:.*?\s)?([\w<>$]+)\(([^)]*)\)(.+)$")

_PRIMITIVES = {
    "Z": "boolean", "B": "byte", "C": "char", "S": "short",
    "I": "int", "J": "long", "F": "float", "D": "double", "V": "void",
}


def _shorten_type(sig: str, pos: int) -> tuple[str, int]:
    """Parse one Smali type at sig[pos]; return (readable, next_pos)."""
    dims = 0
    while pos < len(sig) and sig[pos] == "[":
        dims += 1
        pos += 1
    if pos >= len(sig):
        return "?", pos
    if sig[pos] == "L":
        end = sig.find(";", pos)
        if end == -1:
            return "?", len(sig)
        cls = sig[pos + 1:end]
        short = cls.replace("/", ".").split(".")[-1].split("$")[-1]
        return short + "[]" * dims, end + 1
    short = _PRIMITIVES.get(sig[pos], sig[pos])
    return short + "[]" * dims, pos + 1


def _format_method(header: str) -> str:
    """'.method public static sign([B[BL.../SigningAlgorithm;)[B' ->
    'sign(byte[], byte[], SigningAlgorithm)'."""
    m = _METHOD_HEADER_RE.match(header.strip())
    if not m:
        return header.strip()[:80]
    name, params, _ret = m.group(1), m.group(2), m.group(3)
    shorts, pos = [], 0
    while pos < len(params):
        s, pos = _shorten_type(params, pos)
        shorts.append(s)
    return f"{name}({', '.join(shorts)})"


def _method_ranges(lines: list[str]) -> list[tuple[int, int, str]]:
    """1-based inclusive (start, end, display-name) for every method block."""
    ranges: list[tuple[int, int, str]] = []
    start = None
    header = ""
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(".method"):
            start = i
            header = s
        elif s == ".end method" and start is not None:
            ranges.append((start + 1, i + 1, _format_method(header)))
            start = None
    if start is not None:  # unterminated block — be tolerant
        ranges.append((start + 1, len(lines), _format_method(header)))
    return ranges


# ─── Tool: retrieve_credential ────────────────────────────────────────────────

def tool_retrieve_credential(parameter: str, credentials: dict) -> str:

    parameter = str(parameter).strip().strip("'\"")

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


# ─── Argument parsing ─────────────────────────────────────────────────────────

def _parse_args(argstr: str) -> list[str]:
    """Parse the argument list out of the tail of an action string.

    Handles quoted or bare arguments, whitespace, nested parentheses, and
    commas inside quoted strings. Returns [] when nothing usable is found.
    """
    argstr = (argstr or "").strip()

    if argstr.startswith("("):
        depth = 0
        closed = -1
        for i, ch in enumerate(argstr):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    closed = i
                    break
        argstr = argstr[1:closed] if closed != -1 else argstr[1:]

    args: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    depth = 0

    for ch in argstr:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)

    if buf:
        args.append("".join(buf).strip())

    cleaned: list[str] = []
    for a in args:
        if len(a) >= 2 and a[0] == a[-1] and a[0] in "'\"":
            a = a[1:-1]
        a = a.strip()
        if a:
            cleaned.append(a)
    return cleaned


def _args_from_result(result: dict, first_keys, second_keys) -> list[str]:
    """Pull inline-style arguments out of sibling JSON fields of next_action."""
    def find(keys):
        for k in keys:
            v = result.get(k)
            if v:
                return str(v)
        return None

    first = find(first_keys)
    if first is None:
        return []
    if not second_keys:
        return [first]
    second = find(second_keys)
    return [first, second] if second is not None else []


# ─── Error helpers ────────────────────────────────────────────────────────────

def _unknown_action_error(action: str) -> str:
    return (
        f"Error: Unknown action '{action or '<empty>'}'. "
        f"Valid actions: {'; '.join(VALID_ACTIONS)}. "
        f"Retry now with a valid action — tool arguments go inline, "
        f"e.g. search_function('com/example/sdk/util/HttpUtils.smali', 'urlEncode')."
    )


def _usage_error(name: str, params: str) -> str:
    return (
        f"Error: {name} requires ({params}) but they were missing. "
        f"Retry now as {name}({params}) with the arguments inline."
    )
