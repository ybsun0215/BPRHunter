"""
vf_identification.py
Step 1 of Algorithm 2: F <- IdentifyDynamicField(T)

Identifies Verification Fields (VFs) from traffic.
VFs are fields whose values change across requests
but do NOT originate from server responses.
Also provides LocateCodeContext to build the initial
Smali inference context for a given VF.

HAR entries (from har_loader.load_har) are accepted directly.
parse_har_entries() normalises them into the internal format:
    {
        "request":  {"headers": {...}, "query": {...}, "body": {...}},
        "response": {"body": {...}}
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse


# ─── HAR Parser ───────────────────────────────────────────────────────────────

def parse_har_entries(entries: list[dict]) -> list[dict]:

    result = []
    for entry in entries:
        raw_req = entry.get("request", {})
        raw_resp = entry.get("response", {})

        raw_url = raw_req.get("url", "")
        parsed_url = urlparse(raw_url)

        request = {
            "method":  raw_req.get("method", "GET"),
            "url":     raw_url,
            "path":    parsed_url.path or "/",
            "headers": _pairs_to_dict(raw_req.get("headers", [])),
            "query":   _pairs_to_dict(raw_req.get("queryString", [])),
            "body":    _parse_body(raw_req.get("postData", {}).get("text", "")),
        }

        response = {
            "body": _parse_body(raw_resp.get("content", {}).get("text", "")),
        }

        domain = parsed_url.netloc
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
                string_const_matches.append(match)
            # Tier 2: header/parameter set with field name
            elif any(kw in line_lower for kw in ("put", "set", "addheader", ".param")):
                header_put_matches.append(match)
            else:
                substring_matches.append(match)

    # Merge: tier 1 first, then tier 2, then tier 3; cap at 30 matches total
    all_matches = (string_const_matches + header_put_matches + substring_matches)[:30]

    return {
        "target_field": field_name,
        "source_functions": all_matches,
        "extra_context": (
            f"Found {len(string_const_matches)} string-constant matches, "
            f"{len(header_put_matches)} header-put matches, "
            f"{len(substring_matches)} substring matches "
            f"for field '{field_name}' in Smali code."
        ),
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

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