from __future__ import annotations

import json
import copy
import importlib.util
import os
from dataclasses import dataclass
from typing import Any, Generator, Optional
from urllib.parse import urlparse

import requests

import config


@dataclass
class TestCase:
    base_api_id: str      # API node ID where the auth token is UsedIn
    token_id: str         # Auth token node ID being tested
    chain: list[str]      # Derivation chain, e.g. ["tokenA", "tokenB", "tokenC"]
    request: dict         # HAR request dict with the replaced token value
    new_token_value: str  # The new token value injected into the request


# ---------------------------------------------------------------------------
# TDG
# ---------------------------------------------------------------------------

class TDG:
    def __init__(self, tdg_path: str):
        with open(tdg_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.nodes: dict[str, dict] = {n["id"]: n for n in data["nodes"]}

        self.edges_by_type: dict[str, list[tuple[str, str]]] = {}
        for e in data["edges"]:
            rel = e["type"]
            self.edges_by_type.setdefault(rel, []).append((e["src"], e["dst"]))

    def get_auth_tokens(self) -> list[str]:
        return [nid for nid, n in self.nodes.items() if n["type"] == "auth_token"]

    def get_usedin_apis(self, token_id: str) -> list[str]:
        return [dst for src, dst in self.edges_by_type.get("UsedIn", []) if src == token_id]

    def get_generate_parents(self, token_id: str) -> list[str]:
        return [src for src, dst in self.edges_by_type.get("Generate", []) if dst == token_id]

    def get_issue_api(self, token_id: str) -> str | None:
        for src, dst in self.edges_by_type.get("Issue", []):
            if dst == token_id:
                return src
        return None

    def retrieve_gen_chains(self, auth_token_id: str) -> list[list[str]]:
        chains: list[list[str]] = []

        def dfs(current: str, path: list[str], visited: set[str]):
            if len(path) > config.MAX_CHAIN_DEPTH:
                chains.append(list(reversed(path)))
                return
            parents = self.get_generate_parents(current)
            if not parents:
                chains.append(list(reversed(path)))
                return
            for parent in parents:
                if parent in visited:
                    chains.append(list(reversed(path)))
                    continue
                dfs(parent, path + [parent], visited | {parent})

        dfs(auth_token_id, [auth_token_id], {auth_token_id})
        return chains


# ---------------------------------------------------------------------------
# HAR traffic
# ---------------------------------------------------------------------------

class HARTraffic:
    def __init__(self, har_path: str):
        with open(har_path, "r", encoding="utf-8") as f:
            har = json.load(f)
        self.entries: list[dict] = har.get("log", {}).get("entries", [])

    @staticmethod
    def _strip_query(url: str) -> str:
        """Strip the query string from a URL (everything after '?')."""
        idx = url.find("?")
        return url[:idx] if idx != -1 else url

    def _find_entry(self, api_id: str) -> dict | None:
        """
        Find a HAR entry matching api_id (format: ``METHOD URL``).
        Tries exact URL match first, then falls back to matching without
        query strings (the TDG strips query params from API IDs).
        """
        parts = api_id.split(" ", 1)
        if len(parts) != 2:
            return None
        method, url = parts
        method_upper = method.upper()

        # Pass 1: exact URL match
        for entry in self.entries:
            req = entry.get("request", {})
            if req.get("method", "").upper() == method_upper and req.get("url", "") == url:
                return entry

        # Pass 2: match by stripping query strings from HAR URLs
        # (TDG API IDs don't include query params, but HAR URLs often do)
        tdg_url_clean = self._strip_query(url)
        for entry in self.entries:
            req = entry.get("request", {})
            if req.get("method", "").upper() != method_upper:
                continue
            har_url = req.get("url", "")
            if self._strip_query(har_url) == tdg_url_clean:
                return entry

        return None

    def find_request(self, api_id: str) -> dict | None:
        entry = self._find_entry(api_id)
        if entry is not None:
            return copy.deepcopy(entry.get("request", {}))
        return None

    def find_response_text(self, api_id: str) -> str | None:
        entry = self._find_entry(api_id)
        if entry is not None:
            return entry.get("response", {}).get("content", {}).get("text", "")
        return None


# ---------------------------------------------------------------------------
# Nested dict helpers
# ---------------------------------------------------------------------------

def _find_field_in_dict(d: Any, field_name: str) -> Any:
    if isinstance(d, dict):
        if field_name in d:
            return d[field_name]
        for v in d.values():
            result = _find_field_in_dict(v, field_name)
            if result is not None:
                return result
    elif isinstance(d, list):
        for item in d:
            result = _find_field_in_dict(item, field_name)
            if result is not None:
                return result
    return None


def _replace_field_in_dict(d: Any, field_name: str, new_value: str) -> bool:
    if isinstance(d, dict):
        if field_name in d:
            d[field_name] = new_value
            return True
        for v in d.values():
            if _replace_field_in_dict(v, field_name, new_value):
                return True
    elif isinstance(d, list):
        for item in d:
            if _replace_field_in_dict(item, field_name, new_value):
                return True
    return False


# ---------------------------------------------------------------------------
# Token value extraction and replacement
# ---------------------------------------------------------------------------

def get_token_value_from_request(request: dict, token_field: str) -> str | None:
    field_lower = token_field.lower()

    for header in request.get("headers", []):
        if header.get("name", "").lower() == field_lower:
            return header.get("value", "")

    for param in request.get("queryString", []):
        if param.get("name", "").lower() == field_lower:
            return param.get("value", "")

    post_data = request.get("postData", {})
    if post_data:
        try:
            body = json.loads(post_data.get("text", ""))
            value = _find_field_in_dict(body, token_field)
            if value is not None:
                return str(value)
        except Exception:
            pass
        for param in post_data.get("params", []):
            if param.get("name", "").lower() == field_lower:
                return param.get("value", "")

    return None


def replace_token_in_request(request: dict, token_field: str, new_value: str) -> dict:
    request = copy.deepcopy(request)
    field_lower = token_field.lower()
    replaced = False

    for header in request.get("headers", []):
        if header.get("name", "").lower() == field_lower:
            header["value"] = new_value
            replaced = True

    for param in request.get("queryString", []):
        if param.get("name", "").lower() == field_lower:
            param["value"] = new_value
            replaced = True

    post_data = request.get("postData", {})
    if post_data:
        try:
            body = json.loads(post_data.get("text", ""))
            if _replace_field_in_dict(body, token_field, new_value):
                post_data["text"] = json.dumps(body)
                replaced = True
        except Exception:
            pass
        for param in post_data.get("params", []):
            if param.get("name", "").lower() == field_lower:
                param["value"] = new_value
                replaced = True

    if not replaced:
        request.setdefault("headers", []).append({"name": token_field, "value": new_value})

    return request


# ---------------------------------------------------------------------------
# VF update
# ---------------------------------------------------------------------------

def _get_hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def find_vf_script(hostname: str) -> str | None:
    """Locate the unified VF update script for a host (one script per domain)."""
    host_dir = os.path.join(config.VF_DIR, hostname)
    if not os.path.isdir(host_dir):
        return None
    # Prefer the canonical name from Stage 2
    canonical = os.path.join(host_dir, "update_vf.py")
    if os.path.isfile(canonical):
        return canonical
    # Fallback: any .py file in the directory
    for fname in os.listdir(host_dir):
        if fname.endswith(".py"):
            return os.path.join(host_dir, fname)
    return None


def _har_headers_to_dict(headers):
    """Convert HAR-format headers (list of {name, value}) to a plain dict.
    Returns the input unchanged if it is already a dict or falsy.
    """
    if isinstance(headers, list):
        return {h["name"]: h["value"] for h in headers if "name" in h}
    return headers


def _dict_headers_to_har(headers):
    """Convert a plain dict back to HAR-format headers (list of {name, value}).
    Returns the input unchanged if it is already a list or falsy.
    """
    if isinstance(headers, dict):
        return [{"name": k, "value": str(v)} for k, v in headers.items()]
    return headers


def _har_query_to_dict(query_string):
    """Convert HAR queryString (list of {name, value}) to a plain dict.
    Returns the input unchanged if it is already a dict or falsy.
    """
    if isinstance(query_string, list):
        return {p["name"]: p["value"] for p in query_string if "name" in p}
    return query_string


def _is_ephemeral_field_name(name: str) -> bool:

    lower = name.lower()
    for pattern in ("time", "date", "nonce"):
        if pattern in lower:
            return True
    return False


def _strip_ephemeral_fields(request: dict) -> None:
    """Remove ephemeral VF fields (time, date, nonce) from *request* in-place.

    Call this BEFORE update_vf() in Stage 3 / test-case generation so the
    script fills them with fresh values.  During verification we do NOT
    strip them, so the script keeps the originals and only recomputes the
    signature — allowing exact comparison against expected values.
    """
    for loc in ("headers", "query", "body"):
        container = request.get(loc)
        if not isinstance(container, dict):
            continue
        to_drop = [k for k in container if _is_ephemeral_field_name(k)]
        for k in to_drop:
            del container[k]


def apply_vf_update(request: dict) -> dict:

    hostname = _get_hostname(request.get("url", ""))
    if not hostname:
        return request

    script_path = find_vf_script(hostname)
    if not script_path:
        return request

    try:
        # Build a VF-format request from the HAR-format request
        vf_request = copy.deepcopy(request)

        # ── Convert headers: HAR list → dict ──
        vf_request["headers"] = _har_headers_to_dict(vf_request.get("headers"))

        # ── Convert queryString: HAR list → query dict ──
        vf_request["query"] = _har_query_to_dict(vf_request.get("queryString", []))

        # ── Extract body from postData ──
        if "body" not in vf_request:
            vf_request["body"] = vf_request.get("postData", {}).get("text", "")

        # ── Extract path from URL ──
        url = vf_request.get("url", "")
        try:
            parsed = urlparse(url)
            vf_request["path"] = parsed.path or "/"
        except Exception:
            vf_request["path"] = "/"

        _strip_ephemeral_fields(vf_request)

        spec = importlib.util.spec_from_file_location("vf_updater", script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "update_vf"):
            updated = module.update_vf(vf_request)
            if isinstance(updated, dict):
                # ── Convert headers back: VF dict → HAR list ──
                updated["headers"] = _dict_headers_to_har(updated.get("headers"))
                return updated
    except Exception as e:
        print(f"[WARN] VF update failed for {hostname}: {e}")

    return request


# ---------------------------------------------------------------------------
# HTTP sender (used during chain execution only)
# ---------------------------------------------------------------------------

def send_har_request(request: dict) -> requests.Response | None:
    # ── Demo mode: return original HAR response as mock ──
    if config.DEMO_MODE:
        from ._demo import mock_requests_response
        return mock_requests_response(request)

    # ── Refresh VF fields before sending (consistency with resp_collect.send_request) ──
    request = apply_vf_update(copy.deepcopy(request))

    method = request.get("method", "GET").upper()
    url = request.get("url", "")

    skip_headers = {"content-length", "transfer-encoding"}
    headers = {
        h["name"]: h["value"]
        for h in request.get("headers", [])
        if h["name"].lower() not in skip_headers and not h["name"].startswith(":")
    }

    params = {p["name"]: p["value"] for p in request.get("queryString", [])}

    body = None
    post_data = request.get("postData", {})
    if post_data:
        body = post_data.get("text") or None

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=body,
            timeout=config.HTTP_TIMEOUT,
            verify=config.HTTP_VERIFY_SSL,
            proxies=config.HTTP_PROXIES,
        )
        return response
    except Exception as e:
        print(f"[WARN] HTTP request failed for {url}: {e}")
        return None


# ---------------------------------------------------------------------------
# Chain execution
# ---------------------------------------------------------------------------

def execute_chain(chain: list[str], tdg: TDG, har: HARTraffic) -> str | None:

    if len(chain) <= 1:
        return None

    root_token_id = chain[0]
    root_node = tdg.nodes.get(root_token_id, {})
    root_field = root_node.get("field", root_token_id.split("::")[-1])

    current_value = None
    for api_id in tdg.get_usedin_apis(root_token_id):
        req = har.find_request(api_id)
        if req:
            current_value = get_token_value_from_request(req, root_field)
            if current_value:
                break

    if current_value is None:
        print(f"[WARN] Could not find current value for root token: {root_token_id}")
        return None

    current_token_id = root_token_id

    for next_token_id in chain[1:]:
        next_node = tdg.nodes.get(next_token_id, {})
        next_field = next_node.get("field", next_token_id.split("::")[-1])

        issue_api_id = tdg.get_issue_api(next_token_id)
        if not issue_api_id:
            print(f"[WARN] No Issue API for token: {next_token_id}")
            return None

        issue_request = har.find_request(issue_api_id)
        if not issue_request:
            print(f"[WARN] No HAR request for API: {issue_api_id}")
            return None

        current_node = tdg.nodes.get(current_token_id, {})
        current_field = current_node.get("field", current_token_id.split("::")[-1])
        issue_request = replace_token_in_request(issue_request, current_field, current_value)
        issue_request = apply_vf_update(issue_request)

        response = send_har_request(issue_request)
        if response is None:
            return None

        try:
            resp_body = response.json()
            new_value = _find_field_in_dict(resp_body, next_field)
            # Fallback: look in response headers (many tokens are header-based)
            if new_value is None and hasattr(response, "headers"):
                resp_headers = response.headers
                if isinstance(resp_headers, dict):
                    for hk, hv in resp_headers.items():
                        if hk.lower() == next_field.lower():
                            new_value = hv
                            break
            if new_value is None:
                print(f"[WARN] Field '{next_field}' not found in response for: {issue_api_id}")
                return None
            current_value = str(new_value)
        except Exception as e:
            print(f"[WARN] Failed to parse response JSON from {issue_api_id}: {e}")
            return None

        current_token_id = next_token_id

    return current_value


# ---------------------------------------------------------------------------
# Generator: yields one TestCase at a time (keeps VF fields fresh)
# ---------------------------------------------------------------------------

def generate_test_cases(
    tdg: TDG, har: HARTraffic, dry_run: bool = False
) -> Generator[TestCase, None, None]:

    auth_tokens = tdg.get_auth_tokens()
    print(f"[INFO] Found {len(auth_tokens)} auth token(s).")

    for token_id in auth_tokens:
        token_node = tdg.nodes[token_id]
        token_field = token_node.get("field", token_id.split("::")[-1])

        usedin_apis = tdg.get_usedin_apis(token_id)
        print(f"\n[INFO] Token: {token_id}  field={token_field}  UsedIn APIs: {len(usedin_apis)}")

        if not usedin_apis:
            print(f"[SKIP] No UsedIn APIs.")
            continue

        # Step 1: Base test cases
        for api_id in usedin_apis:
            request = har.find_request(api_id)
            if request is None:
                print(f"[SKIP] No HAR entry for: {api_id}")
                continue
            token_value = get_token_value_from_request(request, token_field) or ""
            yield TestCase(
                base_api_id=api_id,
                token_id=token_id,
                chain=[],
                request=copy.deepcopy(request),
                new_token_value=token_value,
            )

        # Step 2: Chain-based test cases
        chains = [c for c in tdg.retrieve_gen_chains(token_id) if len(c) > 1]
        print(f"Derivation chains: {len(chains)}")

        for chain in chains:
            chain_label = " -> ".join(chain)
            print(f"Chain: {chain_label}")

            if dry_run:
                new_value = f"DRY_RUN_TOKEN[{chain_label}]"
                print(f"  [DRY-RUN] Using placeholder token: {new_value}")
            else:
                new_value = execute_chain(chain, tdg, har)
                if new_value is None:
                    print(f"  [SKIP] Chain yielded no new token value.")
                    continue

            for api_id in usedin_apis:
                request = har.find_request(api_id)
                if request is None:
                    continue

                modified = replace_token_in_request(request, token_field, new_value)
                # VF update runs right before yielding to minimise staleness
                modified = apply_vf_update(modified)

                yield TestCase(
                    base_api_id=api_id,
                    token_id=token_id,
                    chain=chain,
                    request=modified,
                    new_token_value=new_value,
                )


# ---------------------------------------------------------------------------
# Persist test cases
# ---------------------------------------------------------------------------

def save_test_cases(test_cases: list[TestCase]) -> None:

    os.makedirs(config.TESTCASES_DIR, exist_ok=True)

    by_token: dict[str, list[TestCase]] = {}
    for tc in test_cases:
        by_token.setdefault(tc.token_id, []).append(tc)

    for token_id, cases in by_token.items():
        safe_name = token_id.replace("/", "_").replace(":", "_").replace(" ", "_")
        out_path = os.path.join(config.TESTCASES_DIR, f"{safe_name}.json")

        output = [
            {
                "base_api_id":     tc.base_api_id,
                "token_id":        tc.token_id,
                "chain":           tc.chain,
                "new_token_value": tc.new_token_value,
                "request":         tc.request,
            }
            for tc in cases
        ]

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"[INFO] Saved {len(cases)} test cases -> {out_path}")


# ---------------------------------------------------------------------------
# Incremental append (crash-resilient, for generate-one-send-one flow)
# ---------------------------------------------------------------------------

_TESTCASE_LOG_PATH: str | None = None


def _get_testcase_log_path() -> str:
    """Lazily resolve the JSONL log path (one line per test case)."""
    global _TESTCASE_LOG_PATH
    if _TESTCASE_LOG_PATH is None:
        _TESTCASE_LOG_PATH = os.path.join(config.TESTCASES_DIR, "_sent_log.jsonl")
    return _TESTCASE_LOG_PATH


def append_test_case_log(tc: TestCase, response: dict, error: str) -> None:

    os.makedirs(config.TESTCASES_DIR, exist_ok=True)
    record = {
        "base_api_id":     tc.base_api_id,
        "token_id":        tc.token_id,
        "chain":           tc.chain,
        "new_token_value": tc.new_token_value,
        "request":         tc.request,
        "response":        response,   # {"status": 200, "headers": {...}, "body": "..."}
        "error":           error,
    }
    with open(_get_testcase_log_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def clear_test_case_log() -> None:
    """Remove the JSONL sent log (call before starting a fresh run)."""
    path = _get_testcase_log_path()
    if os.path.exists(path):
        os.remove(path)