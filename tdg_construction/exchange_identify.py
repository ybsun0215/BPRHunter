from __future__ import annotations

import json
import csv
from collections import defaultdict

from config import MIN_ALNUM_LENGTH, TIMING_TOLERANCE, EXCHANGE_TOKEN_CSV
from .token_utils import (
    alnum_len, bearer_strip, get_host,
    extract_response_values, extract_request_fields, ts_diff,
)


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


def _load_refresh_values(refresh_csv: str) -> set:
    """Load all refresh token sample values from a refresh token CSV."""
    values: set[str] = set()
    try:
        with open(refresh_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                for c in bearer_strip(row.get("Sample Value", "")):
                    if alnum_len(c) >= MIN_ALNUM_LENGTH:
                        values.add(c)
    except FileNotFoundError:
        print("  Refresh token CSV not found, skipping")
    return values


def identify_exchange_tokens(
    entries: list,
    auth_csv: str,
    refresh_csv: str,
    output_csv: str = EXCHANGE_TOKEN_CSV,
) -> list:
    """
    Identify exchange token fields from HAR entries.

    Args:
        entries:     Time-sorted HAR entries (from har_loader.load_har).
        auth_csv:    Path to the auth tokens CSV (output of auth_identify).
        refresh_csv: Path to the refresh tokens CSV (output of refresh_identify).
        output_csv:  Path to write the resulting CSV.

    Returns:
        List of result row dicts.
    """

    # ── Step 1: Load known tokens ────────────────────────────────────────────
    print(f"Loading auth tokens from: {auth_csv}")
    auth_tokens, all_auth_values = _load_auth_tokens(auth_csv)

    print(f"Loading refresh tokens from: {refresh_csv}")
    all_refresh_values = _load_refresh_values(refresh_csv)

    known_tokens = all_auth_values | all_refresh_values
    print(f"Known token values (auth + refresh): {len(known_tokens)}")

    # ── Step 2: Build response value index ───────────────────────────────────
    resp_value_first: dict[str, dict] = {}

    for entry in entries:
        ts   = entry.get("startedDateTime", "")
        url  = entry.get("request", {}).get("url", "")
        vals = extract_response_values(entry)
        for v in vals:
            if v not in resp_value_first:
                resp_value_first[v] = {"ts": ts, "url": url, "values": vals}

    print(f"Response value index: {len(resp_value_first)} unique values")

    # ── Step 3: Count how many requests each value appears in ────────────────
    value_req_count: dict[str, int] = defaultdict(int)
    for entry in entries:
        seen_in_req: set[str] = set()
        for _, c in extract_request_fields(entry):
            if alnum_len(c) < MIN_ALNUM_LENGTH:
                continue
            if c not in seen_in_req:
                value_req_count[c] += 1
                seen_in_req.add(c)

    # ── Step 4: Causal backtracking to find exchange tokens ──────────────────
    print("Running causal backtracking for exchange tokens...")
    rows = []
    seen: set[tuple] = set()

    for entry in entries:
        host = get_host(entry)
        if host not in auth_tokens:
            continue

        ts   = entry.get("startedDateTime", "")
        url  = entry.get("request", {}).get("url", "")
        resp = extract_response_values(entry)

        for auth_field, known_values in auth_tokens[host].items():
            # Only process responses that issue an auth token
            if not (resp & known_values):
                continue

            for field_name, candi_value in extract_request_fields(entry):
                if alnum_len(candi_value) < MIN_ALNUM_LENGTH:
                    continue

                # Must not be an already-known token
                if candi_value in known_tokens:
                    continue

                # Must come from an earlier response
                first_resp = resp_value_first.get(candi_value)
                if first_resp is None:
                    continue
                if ts_diff(ts, first_resp["ts"]) < -TIMING_TOLERANCE:
                    continue

                # The source response must NOT contain any auth/refresh token
                # (otherwise this is a refresh token, not an exchange token)
                if first_resp["values"] & known_tokens:
                    continue

                # Must appear in requests only once (used solely to derive auth)
                if value_req_count.get(candi_value, 0) != 1:
                    continue

                dedup = (host, field_name)
                if dedup in seen:
                    continue
                seen.add(dedup)

                rows.append({
                    "Host":                 host,
                    "Exchange Token Field": field_name,
                    "Sample Value":         candi_value[:80],
                    "Auth Token Field":     auth_field,
                    "Exchange Request URL": url,
                    "Source Response URL":  first_resp["url"],
                })

    rows.sort(key=lambda r: (r["Host"], r["Exchange Token Field"]))
    print(f"Identified {len(rows)} exchange token fields")

    # ── Step 5: Write CSV ────────────────────────────────────────────────────
    fieldnames = [
        "Host", "Exchange Token Field", "Sample Value",
        "Auth Token Field", "Exchange Request URL", "Source Response URL",
    ]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Done -> {output_csv}")
    print(f"\n{'Host':<35} {'Exchange Token Field':<25} {'Auth Token Field'}")
    print("-" * 80)
    for r in rows:
        print(f"  {r['Host']:<33} {r['Exchange Token Field']:<25} {r['Auth Token Field']}")

    return rows
