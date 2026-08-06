"""
vf_identification.py
Step 1 of Algorithm 2: F <- IdentifyDynamicField(T)

Identifies Verification Fields (VFs) from traffic.
VFs are fields whose values change across requests
but do NOT originate from server responses.
Also provides LocateCodeContext to build the initial
Smali inference context for a given VF.

HAR entries (from har_loader.load_har) are accepted directly.
parse_har_entries() normalises them into the internal format. The request
body remains the exact captured byte string because signatures frequently
depend on whitespace and key ordering:
    {
        "request":  {"headers": {...}, "query": {...}, "body": "..."},
        "response": {"body": {...}}
    }
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from tdg_construction.token_utils import domain_key


# ─── HAR Parser ───────────────────────────────────────────────────────────────

def parse_har_entries(entries: list[dict]) -> list[dict]:

    result = []
    for entry in entries:
        raw_req = entry.get("request", {})
        raw_resp = entry.get("response", {})

        raw_url = raw_req.get("url", "")
        parsed_url = urlparse(raw_url)

        raw_body = raw_req.get("postData", {}).get("text", "")
        if not isinstance(raw_body, str):
            raw_body = "" if raw_body is None else str(raw_body)

        request = {
            "method":  raw_req.get("method", "GET"),
            "url":     raw_url,
            "path":    parsed_url.path or "/",
            "headers": _pairs_to_dict(raw_req.get("headers", [])),
            "query":   _pairs_to_dict(raw_req.get("queryString", [])),
            "body":    raw_body,
            "body_json": _parse_body(raw_body),
        }

        response = {
            "body": _parse_body(raw_resp.get("content", {}).get("text", "")),
        }

        domain = domain_key(raw_url)
        result.append({"domain": domain, "request": request, "response": response})
    return result


def _pairs_to_dict(pairs: list[dict]) -> dict:
    """Converts [{name: k, value: v}, ...] to {k: v}.
    Skips HTTP/2 pseudo-headers (keys starting with ':').
    """
    return {
        p["name"]: p["value"]
        for p in pairs
        if "name" in p and "value" in p and not p["name"].startswith(":")
    }


def _parse_body(text: str) -> dict:
    """
    Tries to parse a JSON string into a dict.
    Returns an empty dict if text is empty or not valid JSON.
    """
    if not text:
        return {}
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def identify_dynamic_fields(traffic: list[dict]) -> dict[str, list[str]]:

    if not traffic:
        return {}

    # Group entries by domain
    by_domain: dict[str, list[dict]] = {}
    for entry in traffic:
        domain = entry.get("domain", "unknown")
        by_domain.setdefault(domain, []).append(entry)

    result: dict[str, list[str]] = {}

    for domain, entries in by_domain.items():
        # Collect all response values for this domain
        response_values: set[str] = set()
        for entry in entries:
            _collect_values(entry.get("response", {}), response_values)

        # Only inspect request headers — query and body are excluded.
        # Track value list per header field (preserving duplicates).
        field_values: dict[str, list[str]] = {}
        for entry in entries:
            headers = entry.get("request", {}).get("headers", {})
            for key, val in headers.items():
                field_values.setdefault(key, []).append(val)

        # Skip domains with only one request — VF detection requires 2+ requests.
        total_requests = len(entries)
        if total_requests < 2:
            continue

        vf_list = []

        for field, value_list in field_values.items():
            value_set = set(value_list)
            # The field must appear in every request of this domain,
            # every occurrence must have a distinct value,
            # and values must not originate from server responses.
            in_all_requests = len(value_list) == total_requests
            all_unique      = len(value_list) == len(value_set)
            from_response   = value_set.issubset(response_values)
            if in_all_requests and all_unique and not from_response:
                vf_list.append(field)

        if vf_list:
            result[domain] = vf_list

    return result


def locate_code_context(field_name: str, smali_dir: str) -> dict:

    smali_path = Path(smali_dir)
    field_lower = field_name.lower()

    # Three tiers of matches
    string_const_matches: list[dict] = []   # Tier 1 — highest signal
    header_put_matches: list[dict] = []     # Tier 2
    substring_matches: list[dict] = []      # Tier 3 — fallback

    for smali_file in smali_path.rglob("*.smali"):
        try:
            lines = smali_file.read_text(errors="ignore").splitlines()
        except Exception:
            continue

        for i, line in enumerate(lines):
            line_lower = line.lower()
            if field_lower not in line_lower:
                continue

            start = max(0, i - 5)
            end = min(len(lines), i + 15)
            snippet = "\n".join(lines[start:end])
            match = {
                "file_path": str(smali_file),
                "line_number": i + 1,
                "snippet": snippet,
            }

            # Tier 1: const-string "field_name" (exact field name as a string constant)
            if "const-string" in line_lower and f'"{field_lower}"' in line_lower:
                direct_callee = _find_direct_callee(lines[i + 1:i + 10], smali_path)
                if direct_callee:
                    match["priority"] = 1
                    match["selection_reason"] = (
                        "Primary field write callsite: the target literal is "
                        "immediately followed by a local computation call."
                    )
                    match["direct_callee"] = direct_callee
                else:
                    match["priority"] = 2
                    match["selection_reason"] = "Exact target-field string literal."
                string_const_matches.append(match)
            # Tier 2: header/parameter set with field name
            elif any(kw in line_lower for kw in ("put", "set", "addheader", ".param")):
                header_put_matches.append(match)
            else:
                substring_matches.append(match)

    # Prefer a domain-facing write callsite where the field literal is followed
    # by a computation call. Include that callee's complete method body before
    # unrelated signer implementations so the LLM follows the observed path.
    string_const_matches.sort(key=lambda item: item.get("priority", 99))
    linked_matches: list[dict] = []
    if string_const_matches:
        direct_callee = string_const_matches[0].get("direct_callee")
        if direct_callee:
            linked = _load_smali_method(smali_path, direct_callee)
            if linked:
                linked_matches.append(linked)

    all_matches = (
        string_const_matches[:1]
        + linked_matches
        + string_const_matches[1:]
        + header_put_matches
        + substring_matches
    )[:30]

    return {
        "target_field": field_name,
        "source_functions": all_matches,
        "extra_context": (
            f"Found {len(string_const_matches)} string-constant matches, "
            f"{len(header_put_matches)} header-put matches, "
            f"{len(substring_matches)} substring matches "
            f"for field '{field_name}' in Smali code. "
            "Matches are priority ordered. Start from source_functions[0] and "
            "follow its direct_callee/source_functions[1] before considering "
            "other implementations. Do not select an unrelated signer merely "
            "because it is more complex."
        ),
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

_INVOKE_RE = re.compile(
    r"invoke-\S+\s+\{[^}]*\},\s+L(?P<class>[^;]+);->(?P<method>[^ (]+)\("
)
_FIELD_SETTER_METHODS = {
    "addheader", "header", "put", "putheader", "set", "setheader",
}


def _find_direct_callee(lines: list[str], smali_root: Path) -> dict | None:
    """Find the first non-setter method invoked after a field literal."""
    for line in lines:
        match = _INVOKE_RE.search(line)
        if not match:
            continue
        method = match.group("method")
        if method.lower() in _FIELD_SETTER_METHODS:
            continue
        class_name = match.group("class")
        if not (smali_root / f"{class_name}.smali").is_file():
            continue
        return {"class": class_name, "method": method}
    return None


def _load_smali_method(smali_root: Path, callee: dict) -> dict | None:
    """Load the complete local Smali method selected by a direct callsite."""
    class_name = callee.get("class", "")
    method_name = callee.get("method", "")
    if not class_name or not method_name:
        return None

    target = smali_root / f"{class_name}.smali"
    if not target.is_file():
        return None
    try:
        lines = target.read_text(errors="ignore").splitlines()
    except OSError:
        return None

    method_marker = re.compile(rf"^\.method\b.*\s{re.escape(method_name)}\(")
    start = None
    for index, line in enumerate(lines):
        if method_marker.search(line.strip()):
            start = index
            break
    if start is None:
        return None

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].strip() == ".end method":
            end = index + 1
            break

    return {
        "file_path": str(target),
        "line_number": start + 1,
        "snippet": "\n".join(lines[start:end]),
        "priority": 1,
        "selection_reason": "Complete method body directly called by primary field write site.",
        "linked_from": callee,
    }

def _collect_values(obj, result: set):
    if isinstance(obj, dict):
        for v in obj.values():
            _collect_values(v, result)
    elif isinstance(obj, list):
        for item in obj:
            _collect_values(item, result)
    elif isinstance(obj, str):
        result.add(obj)


def _flatten_dict(obj: dict, prefix: str = "") -> dict[str, str]:
    items = {}
    for k, v in obj.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            items.update(_flatten_dict(v, full_key))
        elif isinstance(v, (str, int, float)):
            items[full_key] = str(v)
    return items
