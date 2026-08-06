from __future__ import annotations

import json
import csv
from collections import defaultdict
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone

from config import MIN_ALNUM_LENGTH, AUTH_TOKEN_CSV
from .token_utils import (
    alnum_len, bearer_strip, domain_key, flatten_json, get_host,
    extract_request_headers_filtered,
)

ENDPOINT_MISS_TOLERANCE = 10

MIN_TRACEABLE_VALUES = 1

MIN_VALUE_TOTAL_LENGTH = 10
# ─────────────────────────────────────────────────────────


def url_key(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def _extract_response_kv(entry: dict) -> list:
    kv = []
    for h in entry.get("response", {}).get("headers", []):
        k = h.get("name", "").lower()
        v = h.get("value", "")
        if k and v:
            for c in bearer_strip(v):
                kv.append((k, c))
    text = entry.get("response", {}).get("content", {}).get("text", "")
    if text:
        try:
            for k, v in flatten_json(json.loads(text)):
                for c in bearer_strip(v):
                    kv.append((k, c))
        except Exception:
            kv.append(("__raw__", text.strip()))
    return kv


def _value_from_response(
    raw_value: str,
    req_ts: str,
    value_to_first_resp: dict,
    value_to_first_req_ts: dict,
) -> dict | None:
    for candidate in bearer_strip(raw_value):
        candidate = candidate.strip()
        hit = value_to_first_resp.get(candidate)
        if hit is None:
            continue
        resp_rec = hit["rec"]
        resp_key = hit["resp_key"]

        fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
        try:
            t_resp = datetime.strptime(resp_rec["started_at"], fmt).replace(tzinfo=timezone.utc)
            t_req  = datetime.strptime(req_ts, fmt).replace(tzinfo=timezone.utc)
            if (t_resp - t_req).total_seconds() > 1.0:
                continue
        except Exception:
            if resp_rec["started_at"] > req_ts:
                continue

        first_req_ts = value_to_first_req_ts.get(candidate)
        if first_req_ts is not None and first_req_ts <= resp_rec["started_at"]:
            continue

        return {
            "resp_url": resp_rec["url"],
            "resp_key": resp_key,
            "resp_ts":  resp_rec["started_at"],
        }
    return None


def _request_has_empty_field(req_headers: list) -> bool:
    """
    Return True if any header field in this request has an empty or blank value.
    Such requests are dropped entirely before any counting.
    """
    for name, value in req_headers:
        if not value or not value.strip():
            return True
        if alnum_len(value.strip()) == 0:
            return True
    return False


def identify_auth_tokens(entries: list, output_csv: str = AUTH_TOKEN_CSV) -> list:

    # ── Step 1: Build per-record view ────────────────────────────────────────
    # Drop any request that contains at least one empty/blank field value.
    records = []
    skipped_empty = 0
    for entry in entries:
        method = entry.get("request", {}).get("method", "").upper()
        req_headers = extract_request_headers_filtered(entry)

        if _request_has_empty_field(req_headers):
            skipped_empty += 1
            continue

        records.append({
            "started_at":  entry.get("startedDateTime", ""),
            "host":        get_host(entry),
            "url":         entry.get("request", {}).get("url", ""),
            "method":      method,
            "req_headers": req_headers,
            "resp_kv":     _extract_response_kv(entry),
        })

    print(f"Requests kept: {len(records)}  (skipped due to empty field: {skipped_empty})")

    # ── Step 2: Build response value index ───────────────────────────────────
    value_to_first_resp: dict[str, dict] = {}
    value_to_first_req_ts: dict[str, str] = {}
    field_all_known_values: dict[str, set] = defaultdict(set)

    for rec in records:
        for k, v in rec["resp_kv"]:
            if alnum_len(v) < MIN_ALNUM_LENGTH:
                continue
            if v not in value_to_first_resp:
                value_to_first_resp[v] = {"rec": rec, "resp_key": k}

        for name, value in rec["req_headers"]:
            for candidate in bearer_strip(value):
                if alnum_len(candidate) < MIN_ALNUM_LENGTH:
                    continue
                if candidate not in value_to_first_req_ts:
                    value_to_first_req_ts[candidate] = rec["started_at"]
                field_all_known_values[name].add(candidate)

    print(f"Response value index: {len(value_to_first_resp)} unique values")

    # ── Step 3: Group records by host ────────────────────────────────────────
    host_requests: dict[str, list] = defaultdict(list)
    for i, rec in enumerate(records):
        rec["_idx"] = i
        host_requests[rec["host"]].append(rec)

    print(f"Total hosts: {len(host_requests)}")

    # ── Step 4: For each host, find fields covering endpoints ─────────────────
    rows = []

    for host, reqs in sorted(host_requests.items()):
        if len(reqs) < 2:
            continue

        endpoint_set: set[tuple] = set()
        endpoint_field_values: dict[tuple, set] = defaultdict(set)
        endpoint_field_first_ts: dict[tuple, str] = {}

        for rec in reqs:
            ep = (rec["method"], url_key(rec["url"]))
            endpoint_set.add(ep)
            seen_fields = set()

            for name, value in rec["req_headers"]:
                valid_candidates = [
                    sv for sv in bearer_strip(value)
                    if alnum_len(sv) >= MIN_ALNUM_LENGTH
                    and len(sv) > MIN_VALUE_TOTAL_LENGTH
                ]
                if not valid_candidates:
                    continue

                if name in seen_fields:
                    continue
                seen_fields.add(name)

                key = (name, ep)
                for sv in valid_candidates:
                    endpoint_field_values[key].add(sv)

                if key not in endpoint_field_first_ts:
                    endpoint_field_first_ts[key] = rec["started_at"]
                elif rec["started_at"] < endpoint_field_first_ts[key]:
                    endpoint_field_first_ts[key] = rec["started_at"]

        # Collect response values per endpoint
        ep_resp_values: dict[tuple, set] = defaultdict(set)
        for rec in reqs:
            ep = (rec["method"], url_key(rec["url"]))
            for _, v in rec["resp_kv"]:
                if alnum_len(v) >= MIN_ALNUM_LENGTH:
                    for c in bearer_strip(v):
                        ep_resp_values[ep].add(c)

        field_covered_endpoints: dict[str, set] = defaultdict(set)
        for (field_name, ep) in endpoint_field_values:
            field_covered_endpoints[field_name].add(ep)

        for field_name, covered in field_covered_endpoints.items():
            known_values = field_all_known_values.get(field_name, set())
            issuing_eps = {
                ep for ep in endpoint_set
                if known_values & ep_resp_values[ep]
            }
            required_eps = endpoint_set - issuing_eps
            if not required_eps:
                continue

            # Rule 2: relaxed coverage — allow at most ENDPOINT_MISS_TOLERANCE
            # non-issuing endpoints to be missing the field.
            missing_eps = required_eps - covered
            if len(missing_eps) > ENDPOINT_MISS_TOLERANCE:
                continue

            # Collect all distinct values across covered endpoints
            all_values: set[str] = set()
            for ep in covered:
                all_values |= endpoint_field_values[(field_name, ep)]

            # Rule 3: traceable value count check
            traceable: list[tuple[str, dict]] = []
            for raw_value in all_values:
                req_ts = min(
                    endpoint_field_first_ts[(field_name, ep)]
                    for ep in covered
                    if raw_value in endpoint_field_values[(field_name, ep)]
                )
                info = _value_from_response(
                    raw_value, req_ts, value_to_first_resp, value_to_first_req_ts
                )
                if info is not None:
                    traceable.append((raw_value, info))

            n_values    = len(all_values)
            n_traceable = len(traceable)

            if n_values > MIN_TRACEABLE_VALUES:
                # Large value set: require at least MIN_TRACEABLE_VALUES traceable.
                # Rejects timestamp/nonce fields that echo a server value by chance.
                if n_traceable < MIN_TRACEABLE_VALUES:
                    continue
            else:
                # Small value set: require at least one traceable value.
                if n_traceable == 0:
                    continue

            sample_value, sample_info = traceable[0]

            rows.append({
                "Host":                   host,
                "Issuer Host":            domain_key(sample_info["resp_url"]),
                "Field Name":             field_name,
                "Endpoint Count":         len(endpoint_set),
                "Missing Endpoint Count": len(missing_eps),
                "Distinct Value Count":   n_values,
                "Traceable Value Count":  n_traceable,
                "Sample Value":           sample_value[:80],
                "Source Response Key":    sample_info["resp_key"],
                "Source Response URL":    sample_info["resp_url"],
                "All Values (JSON)":      json.dumps(list(all_values), ensure_ascii=False),
            })

    rows.sort(key=lambda r: (r["Host"], r["Field Name"]))
    print(f"Identified {len(rows)} auth token fields across all hosts")

    # ── Step 5: Write CSV ────────────────────────────────────────────────────
    fieldnames = [
        "Host", "Issuer Host", "Field Name", "Endpoint Count", "Missing Endpoint Count",
        "Distinct Value Count", "Traceable Value Count",
        "Sample Value", "Source Response Key", "Source Response URL",
        "All Values (JSON)",
    ]

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Done -> {output_csv}")
    print(
        f"\n{'Host':<35} {'Field Name':<30} {'EPs':>5}"
        f"  {'Miss':>4}  {'Values':>6}  {'Trace':>5}"
    )
    print("-" * 95)
    for r in rows:
        print(
            f"  {r['Host']:<33} {r['Field Name']:<30}"
            f" {r['Endpoint Count']:>5}  {r['Missing Endpoint Count']:>4}"
            f"  {r['Distinct Value Count']:>6}  {r['Traceable Value Count']:>5}"
        )

    return rows
