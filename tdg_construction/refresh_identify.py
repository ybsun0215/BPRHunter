from __future__ import annotations

import json
import csv
from collections import defaultdict

from config import MIN_ALNUM_LENGTH, TIMING_TOLERANCE, REFRESH_TOKEN_CSV
from .token_utils import (
    alnum_len, bearer_strip, get_host,
    extract_response_values, extract_request_fields, ts_diff,
    should_skip_field,
)

# Minimum total string length for a candidate refresh token value
MIN_VALUE_TOTAL_LENGTH = 10


def _load_auth_tokens(auth_csv: str) -> tuple[dict, set]:
    """
    Load auth tokens from a CSV produced by auth_identify.

    Returns:
        auth_tokens:     {host: {field_name: set(values)}}
        all_auth_values: flat set of all known auth token values
    """
    auth_tokens: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    with open(auth_csv, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            host = row["Host"]
            field_name = row["Field Name"]
            for v in json.loads(row["All Values (JSON)"]):
                for c in bearer_strip(v):
                    if alnum_len(c) >= MIN_ALNUM_LENGTH:
                        auth_tokens[host][field_name].add(c)

    all_auth_values: set[str] = set()
    for fields in auth_tokens.values():
        for values in fields.values():
            all_auth_values |= values

    return auth_tokens, all_auth_values


def _extract_response_kv(entry: dict) -> list[tuple[str, str]]:
    """
    Extract (field_name, value) pairs from a HAR entry's response.
    Covers response headers and JSON body (flattened).
    """
    kv_pairs = []
    # Response headers
    for h in entry.get("response", {}).get("headers", []):
        name = h.get("name", "")
        value = h.get("value", "")
        if name and value:
            for c in bearer_strip(value):
                kv_pairs.append((name, c))

    # Response JSON body
    text = entry.get("response", {}).get("content", {}).get("text", "")
    if text:
        try:
            body = json.loads(text)
            for k, v in _flatten_json(body):
                for c in bearer_strip(str(v)):
                    kv_pairs.append((k, c))
        except Exception:
            pass
    return kv_pairs


def _flatten_json(obj, parent_key=""):
    """Recursively flatten a JSON object into a list of (key, value) pairs."""
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            items.extend(_flatten_json(v, k))
    elif isinstance(obj, list):
        for item in obj:
            items.extend(_flatten_json(item, parent_key))
    else:
        if obj is not None and parent_key:
            items.append((parent_key, str(obj)))
    return items


def identify_refresh_tokens(
    entries: list,
    auth_csv: str,
    output_csv: str = REFRESH_TOKEN_CSV,
) -> list:

    # ── Step 1: Load auth tokens ─────────────────────────────────────────────
    print(f"Loading auth tokens from: {auth_csv}")
    auth_tokens, all_auth_values = _load_auth_tokens(auth_csv)
    print(f"Loaded {len(auth_tokens)} hosts, {len(all_auth_values)} auth token values")

    # ── Step 2: Build response snapshot index ────────────────────────────────
    # resp_snapshot: each response entry with its (field, value) pairs and values set
    resp_snapshot: list[dict] = []
    for entry in entries:
        ts = entry.get("startedDateTime", "")
        url = entry.get("request", {}).get("url", "")
        resp_kv = _extract_response_kv(entry)
        vals = set(v for _, v in resp_kv)
        if vals:
            resp_snapshot.append({
                "ts": ts,
                "url": url,
                "values": vals,
                "kv": resp_kv,
                "entry": entry,
            })

    # value → first occurrence info
    resp_value_first: dict[str, dict] = {}
    for snap in resp_snapshot:
        for v in snap["values"]:
            if v not in resp_value_first:
                resp_value_first[v] = {"ts": snap["ts"], "url": snap["url"]}

    # value → first request timestamp, and field_name → set of values used under that name
    value_first_req_ts: dict[str, str] = {}
    field_req_values: dict[str, set] = defaultdict(set)  # field_name → {values seen in requests}
    for entry in entries:
        ts = entry.get("startedDateTime", "")
        for fname, c in extract_request_fields(entry):
            if alnum_len(c) >= MIN_ALNUM_LENGTH:
                field_req_values[fname.lower()].add(c)
                if c not in value_first_req_ts:
                    value_first_req_ts[c] = ts

    print(f"Response value index: {len(resp_value_first)} unique values")

    # ── Step 3: Find token issuance events ───────────────────────────────────
    print("Identifying token issuance events...")
    issuance_events = []

    for snap in resp_snapshot:
        host = get_host(snap["entry"])
        if host not in auth_tokens:
            continue

        for auth_field, known_values in auth_tokens[host].items():
            if snap["values"] & known_values:
                issuance_events.append({
                    "ts":         snap["ts"],
                    "url":        snap["url"],
                    "host":       host,
                    "auth_field": auth_field,
                    "snap":       snap,
                })
                break  # One event per response

    print(f"Found {len(issuance_events)} token issuance events")

    # ── Step 4: Identify refresh token fields and collect all values ──────────
    print("Identifying refresh token fields...")
    # (host, field_name) → {host, field, values_set, auth_field, event_url, co_url, sample_value}
    candidate_fields: dict[tuple[str, str], dict] = {}

    for event in issuance_events:
        host = event["host"]
        event_ts = event["ts"]
        event_url = event["url"]
        auth_field = event["auth_field"]
        known_auth = auth_tokens[host][auth_field]
        resp_kv = event["snap"]["kv"]

        for field_name, candi_value in resp_kv:
            if should_skip_field(field_name):
                continue
            if alnum_len(candi_value) < MIN_ALNUM_LENGTH:
                continue
            if len(candi_value) <= MIN_VALUE_TOTAL_LENGTH:
                continue
            if candi_value in all_auth_values:
                continue

            # Constraint 1: field name must appear in requests (the client sends
            # this token back using the same key in a later API call).
            req_values_for_field = field_req_values.get(field_name.lower(), set())
            if candi_value not in req_values_for_field:
                continue

            # Constraint 2: must be used in at least one later request
            first_req_ts = value_first_req_ts.get(candi_value)
            if first_req_ts is None:
                continue
            if ts_diff(first_req_ts, event_ts) < -TIMING_TOLERANCE:
                continue

            # Co-occurrence: candidate must share a response with a known auth value
            co_url = event_url
            co_found = False
            for snap in resp_snapshot:
                if candi_value not in snap["values"]:
                    continue
                if not known_auth.intersection(snap["values"]):
                    continue
                if ts_diff(event_ts, snap["ts"]) < -TIMING_TOLERANCE:
                    continue
                co_url = snap["url"]
                co_found = True
                break

            if not co_found:
                continue

            key = (host, field_name)
            if key not in candidate_fields:
                candidate_fields[key] = {
                    "host":           host,
                    "field":          field_name,
                    "values":         set(),
                    "auth_field":     auth_field,
                    "event_url":      event_url,
                    "co_url":         co_url,
                }
            candidate_fields[key]["values"].add(candi_value)

    # Build rows: store all values as JSON (no truncation), first value as sample
    rows = []
    for (host, field_name), info in sorted(candidate_fields.items()):
        all_values = sorted(info["values"])
        rows.append({
            "Host":                   host,
            "Refresh Token Field":    field_name,
            "Sample Value":           all_values[0] if all_values else "",
            "All Values (JSON)":      json.dumps(all_values, ensure_ascii=False),
            "Auth Token Field":       info["auth_field"],
            "Refresh Request URL":    info["event_url"],
            "Co-occurrence Resp URL": info["co_url"],
        })

    print(f"Identified {len(rows)} refresh token fields")

    # ── Step 5: Write CSV ────────────────────────────────────────────────────
    fieldnames = [
        "Host", "Refresh Token Field", "Sample Value", "All Values (JSON)",
        "Auth Token Field", "Refresh Request URL", "Co-occurrence Resp URL",
    ]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Done -> {output_csv}")
    print(f"\n{'Host':<35} {'Refresh Token Field':<25} {'Values':>6}  {'Auth Token Field'}")
    print("-" * 80)
    for r in rows:
        n_vals = len(json.loads(r["All Values (JSON)"]))
        print(f"  {r['Host']:<33} {r['Refresh Token Field']:<25} {n_vals:>6}  {r['Auth Token Field']}")

    return rows
