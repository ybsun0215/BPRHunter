"""
resp_collect.py — HTTP response collection for Stage 3.

Sends constructed test cases to the target server one at a time
and collects responses.  VF fields are refreshed immediately before
each send so timestamps / signatures / nonces are never stale.

When ``config.DEMO_MODE`` is True, HTTP calls are mocked: the original
HAR response is returned instead of making a real network request.

Each response is returned as a dict::

    {"status": 200, "headers": {...}, "body": "..."}
"""

from __future__ import annotations

import copy

import requests

import config
from .case_gen import TestCase, apply_vf_update, prepare_request_target
from ._demo import mock_response_dict


# ---------------------------------------------------------------------------
# HTTP sender
# ---------------------------------------------------------------------------

def send_request(request: dict) -> tuple[dict, str]:

    # ── Refresh VF fields right before sending (demo or real) ──
    request = apply_vf_update(copy.deepcopy(request))

    # ── Demo mode: return original HAR response ──
    if config.DEMO_MODE:
        return mock_response_dict(request)

    method = request.get("method", "GET").upper()
    url, params = prepare_request_target(request)

    skip_headers = {"content-length", "transfer-encoding"}
    headers = {
        h["name"]: h["value"]
        for h in request.get("headers", [])
        if h["name"].lower() not in skip_headers and not h["name"].startswith(":")
    }

    body = None
    post_data = request.get("postData", {})
    if post_data:
        body = post_data.get("text") or None

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=body,
            timeout=config.HTTP_TIMEOUT,
            verify=config.HTTP_VERIFY_SSL,
            proxies=config.HTTP_PROXIES,
        )
        return {
            "status":  resp.status_code,
            "headers": dict(resp.headers),
            "body":    resp.text,
        }, ""
    except Exception as e:
        return {"status": 0, "headers": {}, "body": ""}, str(e)


# ---------------------------------------------------------------------------
# Test case sender
# ---------------------------------------------------------------------------

def send_test_case(tc: TestCase) -> tuple[dict, str]:

    return send_request(tc.request)
