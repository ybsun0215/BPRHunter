"""
token_utils.py
Shared utility functions used across all token identification modules.
"""

from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlsplit
from datetime import datetime, timezone

from config import MIN_ALNUM_LENGTH, SKIP_FIELD_NAMES


# ─── Domain helpers ──────────────────────────────────────

_DEFAULT_PORTS = {"http": 80, "https": 443}


def domain_key(value: str) -> str:
    """Return one canonical, filesystem-safe key for a URL or Host value.

    Host names are lower-cased and IDNA-normalised. Default HTTP(S) ports are
    omitted; non-default ports use ``__port_<n>`` so VF directories are valid
    on Windows as well as Linux.
    """

    raw = str(value or "").strip()
    if not raw:
        return "unknown"

    has_scheme = "://" in raw
    try:
        parsed = urlsplit(raw if has_scheme else f"//{raw}")
        host = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return "unknown"

    if not host:
        return "unknown"

    host = host.rstrip(".").lower()
    if ":" in host:
        safe_host = "ipv6_" + host.replace(":", "_")
    else:
        try:
            safe_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            safe_host = host

    scheme = parsed.scheme.lower() if has_scheme else ""
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return f"{safe_host}__port_{port}"
    return safe_host


# ─── String helpers ───────────────────────────────────────

def alnum_len(s: str) -> int:
    """Count alphanumeric characters in a string."""
    return sum(1 for c in s if c.isalnum())


def bearer_strip(value: str) -> set:
    """
    Return a set of candidate token values.
    Includes the raw value and, if applicable, the value with
    a common auth prefix (Bearer, Basic, etc.) stripped.
    """
    candidates = {value.strip()}
    for prefix in ("Bearer ", "Basic ", "Digest ", "Token "):
        if value.strip().startswith(prefix):
            candidates.add(value.strip()[len(prefix):].strip())
            break
    return candidates


def should_skip_field(name: str) -> bool:
    """Return True if the field name contains any substring in SKIP_FIELD_NAMES (case-insensitive)."""
    lower = name.lower()
    return any(s in lower for s in SKIP_FIELD_NAMES)


# ─── JSON helpers ─────────────────────────────────────────

def flatten_json(obj, parent_key=""):
    """Recursively flatten a JSON object into a list of (key, value) pairs."""
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            items.extend(flatten_json(v, k))
    elif isinstance(obj, list):
        for item in obj:
            items.extend(flatten_json(item, parent_key))
    else:
        if obj is not None and parent_key:
            items.append((parent_key, str(obj)))
    return items


# ─── Time helpers ─────────────────────────────────────────

def parse_ts(ts: str) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string. Returns None on failure."""
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def ts_diff(ts_later: str, ts_earlier: str) -> float:
    """
    Return (ts_later - ts_earlier) in seconds.
    Returns float('inf') if either timestamp cannot be parsed.
    """
    a, b = parse_ts(ts_later), parse_ts(ts_earlier)
    if a is None or b is None:
        return float("inf")
    return (a - b).total_seconds()


# ─── HAR entry helpers ────────────────────────────────────

def get_host(entry: dict) -> str:
    """Return the same canonical domain key used by Stages 2 and 3."""
    url_key = domain_key(entry.get("request", {}).get("url", ""))
    if url_key != "unknown":
        return url_key

    for h in entry.get("request", {}).get("headers", []):
        if h.get("name", "").lower() == "host":
            return domain_key(h.get("value", ""))
    return "unknown"


def extract_response_values(entry: dict) -> set:
    """
    Extract all candidate token values from a HAR entry's response.
    Covers response headers and JSON/text body.
    """
    values = set()

    for h in entry.get("response", {}).get("headers", []):
        for c in bearer_strip(h.get("value", "")):
            if alnum_len(c) >= MIN_ALNUM_LENGTH:
                values.add(c)

    text = entry.get("response", {}).get("content", {}).get("text", "")
    if text:
        try:
            for _, v in flatten_json(json.loads(text)):
                for c in bearer_strip(str(v)):
                    if alnum_len(c) >= MIN_ALNUM_LENGTH:
                        values.add(c)
        except Exception:
            values.add(text.strip())

    return values


def extract_request_fields(entry: dict) -> list:
    """
    Extract all (field_name, bare_value) pairs from a HAR entry's request.
    Covers headers, query parameters, and POST body (JSON or form-encoded).
    """
    fields = []
    request = entry.get("request", {})

    for h in request.get("headers", []):
        name = h.get("name", "").lower()
        value = h.get("value", "")
        if name and value:
            for c in bearer_strip(value):
                fields.append((name, c))

    url = request.get("url", "")
    for k, vs in parse_qs(urlparse(url).query).items():
        for v in vs:
            for c in bearer_strip(v):
                fields.append((k, c))

    post_data = request.get("postData", {})
    body_text = post_data.get("text", "")
    if body_text:
        try:
            for k, v in flatten_json(json.loads(body_text)):
                for c in bearer_strip(str(v)):
                    fields.append((k, c))
        except Exception:
            mime = post_data.get("mimeType", "")
            if "urlencoded" in mime or "form" in mime:
                for param in post_data.get("params", []):
                    k = param.get("name", "")
                    v = param.get("value", "")
                    if k and v:
                        for c in bearer_strip(v):
                            fields.append((k, c))

    return fields


def extract_request_headers_filtered(entry: dict) -> list:
    """
    Extract request headers, skipping fields in SKIP_FIELD_NAMES.
    Used specifically by the auth token identifier.
    Returns list of (name, value) pairs.
    """
    result = []
    for h in entry.get("request", {}).get("headers", []):
        name = h.get("name", "").lower()
        value = h.get("value", "")
        if name and value and not should_skip_field(name):
            result.append((name, value))
    return result
