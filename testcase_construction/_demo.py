from __future__ import annotations

import copy
import json as _json
import os
from urllib.parse import urlparse as _urlparse

import requests as _requests

import config


# ---------------------------------------------------------------------------
# HAR cache
# ---------------------------------------------------------------------------

_DEMO_HAR_CACHE: list[dict] | None = None
_DEMO_HAR_CACHE_PATH: str | None = None

# Where the original request objects are kept (before VF update mangles them)
_ORIGINAL_REQUESTS: dict[str, dict] = {}


def _load_demo_har() -> list[dict]:
    """Load and cache the demo HAR file."""
    global _DEMO_HAR_CACHE, _DEMO_HAR_CACHE_PATH
    har_path = getattr(config, "DEMO_HAR_PATH", None) or getattr(config, "HAR_FILE", None)
    if har_path is None:
        har_path = os.path.join(config.BASE_DIR, "input", "traffic", "demo.har")
    har_path = os.path.abspath(har_path)

    if _DEMO_HAR_CACHE is None or _DEMO_HAR_CACHE_PATH != har_path:
        with open(har_path, encoding="utf-8") as fh:
            har = _json.load(fh)
        _DEMO_HAR_CACHE = har["log"]["entries"]
        _DEMO_HAR_CACHE_PATH = har_path
    return _DEMO_HAR_CACHE


# ---------------------------------------------------------------------------
# HAR entry lookup
# ---------------------------------------------------------------------------

def _find_har_entry(method: str, url: str) -> dict | None:
    """Find a HAR entry matching the given method and url."""
    entries = _load_demo_har()
    method = method.upper()

    # Exact match
    for entry in entries:
        if entry["request"]["method"].upper() == method and entry["request"]["url"] == url:
            return entry

    # Fallback: strip query string
    base_url = url.split("?")[0] if "?" in url else url
    for entry in entries:
        entry_url = entry["request"]["url"]
        entry_base = entry_url.split("?")[0] if "?" in entry_url else entry_url
        if entry["request"]["method"].upper() == method and entry_base == base_url:
            return entry

    return None


# ---------------------------------------------------------------------------
# Dict-format mock response  (for resp_collect.send_request)
# ---------------------------------------------------------------------------

def mock_response_dict(request: dict) -> tuple[dict, str]:
    """
    Return the original HAR response for *request* as a
    ``(response_dict, error)`` tuple.  Used by ``send_request()``
    in demo mode.
    """
    method = request.get("method", "GET")
    url = request.get("url", "")
    entry = _find_har_entry(method, url)
    if entry is None:
        return {"status": 0, "headers": {}, "body": ""}, \
            f"[DEMO] No matching HAR entry for {method} {url}"
    resp = entry["response"]
    return {
        "status": resp["status"],
        "headers": {h["name"]: h["value"] for h in resp.get("headers", [])},
        "body": resp.get("content", {}).get("text", ""),
    }, ""


# ---------------------------------------------------------------------------
# requests.Response mock  (for case_gen.send_har_request)
# ---------------------------------------------------------------------------

class _MockResponse:
    """Minimal requests.Response stand-in for chain-execution code."""

    def __init__(self, status_code: int, headers: dict, text: str):
        self.status_code = status_code
        self.headers = headers
        self.text = text

    def json(self):
        return _json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise _requests.HTTPError(f"HTTP {self.status_code}")


def mock_requests_response(request: dict):
    """
    Return a mock ``requests.Response``-like object for *request*.
    Used by ``send_har_request()`` in demo mode.
    """
    method = request.get("method", "GET")
    url = request.get("url", "")
    entry = _find_har_entry(method, url)
    if entry is None:
        print(f"[WARN] [DEMO] No matching HAR entry for {method} {url}")
        return None
    resp = entry["response"]
    return _MockResponse(
        status_code=resp["status"],
        headers={h["name"]: h["value"] for h in resp.get("headers", [])},
        text=resp.get("content", {}).get("text", ""),
    )
