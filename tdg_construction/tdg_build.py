from __future__ import annotations

import csv
import os
import json
from collections import defaultdict
from urllib.parse import urlparse, urlunparse

from config import (
    AUTH_TOKEN_CSV, REFRESH_TOKEN_CSV, EXCHANGE_TOKEN_CSV,
    MIN_ALNUM_LENGTH,
)
from .token_utils import (
    alnum_len, bearer_strip, get_host,
    extract_response_values, extract_request_fields,
)

# ── Output paths ─────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HAR_FILE = os.path.join(BASE_DIR, "input", "traffic", "xxx.har")

TDG_NODES_CSV = os.path.join(BASE_DIR, "output", "tdg", "tdg_nodes.csv")
TDG_EDGES_CSV = os.path.join(BASE_DIR, "output", "tdg", "tdg_edges.csv")
TDG_JSON = os.path.join(BASE_DIR, "output", "tdg", "tdg.json")


# ═════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════

def _flatten_json_resp(obj, parent_key=""):
    """Recursively flatten a JSON object into a list of (key, value) pairs."""
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            items.extend(_flatten_json_resp(v, k))
    elif isinstance(obj, list):
        for item in obj:
            items.extend(_flatten_json_resp(item, parent_key))
    else:
        if obj is not None and parent_key:
            items.append((parent_key, str(obj)))
    return items


def _extract_response_kv(entry: dict) -> list[tuple[str, str]]:
    """Extract (field_name, candidate_value) pairs from a HAR response."""
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
            for k, v in _flatten_json_resp(body):
                for c in bearer_strip(str(v)):
                    kv_pairs.append((k, c))
        except Exception:
            pass
    return kv_pairs


def url_key(url: str) -> str:
    """Strip query string; keep scheme + host + path."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def make_token_id(host: str, field: str) -> str:
    return f"{host}::{field}"


def make_api_id(method: str, url: str) -> str:
    return f"{method} {url_key(url)}"


# ═════════════════════════════════════════════════════════
# Loaders
# ═════════════════════════════════════════════════════════

def load_token_csv(path: str, token_type: str) -> tuple[dict, set]:
    """
    Load a token CSV (any of the three kinds).

    Returns:
        token_map : {host: {field_name: set(values)}}
        token_ids : set of node IDs  (host::field_name)
    """
    token_map: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    token_ids: set[str] = set()

    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            # The field column name differs between CSVs
            field_col = {
                "auth":     "Field Name",
                "refresh":  "Refresh Token Field",
                "exchange": "Exchange Token Field",
            }[token_type]

            for row in reader:
                host  = row["Host"]
                field = row[field_col]
                tid   = make_token_id(host, field)
                token_ids.add(tid)

                # Load values: prefer "All Values (JSON)" if present; fall back to "Sample Value"
                all_json = row.get("All Values (JSON)", "")
                if all_json:
                    for v in json.loads(all_json):
                        for c in bearer_strip(v):
                            if alnum_len(c) >= MIN_ALNUM_LENGTH:
                                token_map[host][field].add(c)
                else:
                    for c in bearer_strip(row.get("Sample Value", "")):
                        if alnum_len(c) >= MIN_ALNUM_LENGTH:
                            token_map[host][field].add(c)

    except FileNotFoundError:
        print(f"  Warning: {path} not found, skipping")

    return token_map, token_ids

def load_generate_edges_from_csv() -> set[tuple[str, str, str]]:
    gen_edges: set[tuple[str, str, str]] = set()

    # refresh token --> auth token
    try:
        with open(REFRESH_TOKEN_CSV, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                host    = row["Host"]
                src_tid = make_token_id(host, row["Refresh Token Field"])
                dst_tid = make_token_id(host, row["Auth Token Field"])
                gen_edges.add((src_tid, "Generate", dst_tid))
    except FileNotFoundError:
        print(f"  Warning: {REFRESH_TOKEN_CSV} not found")

    # exchange token --> auth token
    try:
        with open(EXCHANGE_TOKEN_CSV, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                host    = row["Host"]
                src_tid = make_token_id(host, row["Exchange Token Field"])
                dst_tid = make_token_id(host, row["Auth Token Field"])
                gen_edges.add((src_tid, "Generate", dst_tid))
    except FileNotFoundError:
        print(f"  Warning: {EXCHANGE_TOKEN_CSV} not found")

    return gen_edges

# ═════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════

def build_tdg(entries: list) -> dict:

    # ── Step 1: Load all identified tokens ───────────────────────────────────
    print("Loading identified tokens...")
    auth_map,     auth_ids     = load_token_csv(AUTH_TOKEN_CSV,     "auth")
    refresh_map,  refresh_ids  = load_token_csv(REFRESH_TOKEN_CSV,  "refresh")
    exchange_map, exchange_ids = load_token_csv(EXCHANGE_TOKEN_CSV, "exchange")

    print(f"  Auth tokens:     {len(auth_ids)}")
    print(f"  Refresh tokens:  {len(refresh_ids)}")
    print(f"  Exchange tokens: {len(exchange_ids)}")

    # Build reverse index: bare value  -->  [(host, field, token_type), ...]
    # A single value may match multiple tokens (e.g. same JWT used across hosts),
    # so we store a list and resolve by host preference at lookup time.
    value_to_token: dict[str, list[tuple[str, str, str]]] = {}

    for host, fields in auth_map.items():
        for field, values in fields.items():
            for v in values:
                value_to_token.setdefault(v, []).append((host, field, "auth_token"))

    for host, fields in refresh_map.items():
        for field, values in fields.items():
            for v in values:
                value_to_token.setdefault(v, []).append((host, field, "refresh_token"))

    for host, fields in exchange_map.items():
        for field, values in fields.items():
            for v in values:
                value_to_token.setdefault(v, []).append((host, field, "exchange_token"))

    # Build field-name-based index for ALL token types.
    # Key: (host, field_name_lower)  →  (host, field, token_type)
    field_to_token: dict[tuple[str, str], tuple[str, str, str]] = {}
    for host, fields in auth_map.items():
        for field in fields:
            field_to_token[(host, field.lower())] = (host, field, "auth_token")
    for host, fields in refresh_map.items():
        for field in fields:
            field_to_token[(host, field.lower())] = (host, field, "refresh_token")
    for host, fields in exchange_map.items():
        for field in fields:
            field_to_token[(host, field.lower())] = (host, field, "exchange_token")

    def _lookup_token(host: str, candi: str, field_name: str = "") -> tuple[str, str, str] | None:
        """Resolve a candidate value to a token identity.

        1. Exact value match — if multiple tokens share the value (e.g. same
           JWT across hosts), prefer the one whose host matches the request host.
        2. Field-name-based fallback for truncated values.
        """
        hits = value_to_token.get(candi, [])
        if hits:
            # Prefer token whose host matches the request host
            for hit in hits:
                if hit[0] == host:
                    return hit
            # Fallback: first match
            return hits[0]
        if field_name:
            return field_to_token.get((host, field_name.lower()))
        return None

    # ── Step 2: Declare nodes ────────────────────────────────────────────────
    # nodes: {node_id: {"type": ..., "label": ..., ...}}
    nodes: dict[str, dict] = {}

    def add_token_node(host, field, token_type):
        nid = make_token_id(host, field)
        if nid not in nodes:
            nodes[nid] = {
                "id":    nid,
                "type":  token_type,
                "host":  host,
                "field": field,
                "label": field,
            }
        return nid

    def add_api_node(method, url):
        nid = make_api_id(method, url)
        if nid not in nodes:
            nodes[nid] = {
                "id":     nid,
                "type":   "api",
                "method": method,
                "url":    url_key(url),
                "label":  f"{method} {url_key(url)}",
            }
        return nid

    for host, fields in auth_map.items():
        for field in fields:
            add_token_node(host, field, "auth_token")

    for host, fields in refresh_map.items():
        for field in fields:
            add_token_node(host, field, "refresh_token")

    for host, fields in exchange_map.items():
        for field in fields:
            add_token_node(host, field, "exchange_token")

    # ── Step 3: Scan traffic to build edges ──────────────────────────────────
    # edges: set of (src_id, edge_type, dst_id)
    edges: set[tuple[str, str, str]] = set()

    print(f"Scanning {len(entries)} traffic entries to build edges...")

    for entry in entries:
        method = entry.get("request", {}).get("method", "GET").upper()
        url    = entry.get("request", {}).get("url", "")
        host   = get_host(entry)
        api_id = add_api_node(method, url)

        # Collect which token fields appear in this request
        req_token_ids: set[str] = set()
        for fname, candi in extract_request_fields(entry):
            if alnum_len(candi) < MIN_ALNUM_LENGTH:
                continue
            hit = _lookup_token(host, candi, fname)
            if hit is None:
                continue
            req_host, req_field, req_type = hit
            tid = make_token_id(req_host, req_field)

            # UsedIn edge: Token --> API
            edges.add((tid, "UsedIn", api_id))
            req_token_ids.add(tid)

        # Collect which token fields appear in this response
        resp_token_ids: set[str] = set()
        for resp_fname, resp_val in _extract_response_kv(entry):
            if alnum_len(resp_val) < MIN_ALNUM_LENGTH:
                continue
            hit = _lookup_token(host, resp_val, resp_fname)
            if hit is None:
                continue
            resp_host, resp_field, resp_type = hit
            tid = make_token_id(resp_host, resp_field)

            # Issue edge: API --> Token
            edges.add((api_id, "Issue", tid))
            resp_token_ids.add(tid)

            for t1 in req_token_ids:
                for t2 in resp_token_ids:
                    if t1 != t2:
                        edges.add((t1, "Generate", t2))

    print("Validating UsedIn edges (token host must appear in API URL)...")
    validated_edges: set[tuple[str, str, str]] = set()
    fixed_count = 0
    removed_count = 0

    for src, etype, dst in edges:
        if etype != "UsedIn":
            validated_edges.add((src, etype, dst))
            continue

        token_host = src.split("::")[0]
        if token_host in dst:
            # Valid: token host appears in API URL
            validated_edges.add((src, etype, dst))
            continue

        # Cross-host edge — try to find a matching token for the correct host
        token_field = src.split("::")[-1]
        reassigned = False
        for nid, node in nodes.items():
            if node.get("field") == token_field and node["host"] in dst:
                validated_edges.add((nid, "UsedIn", dst))
                fixed_count += 1
                reassigned = True
                break
        if not reassigned:
            # No better token found — remove the edge
            removed_count += 1

    print(f"  Fixed:   {fixed_count} cross-host UsedIn edges reassigned")
    print(f"  Removed: {removed_count} unresolvable cross-host edges")
    edges = validated_edges

    csv_gen_edges = load_generate_edges_from_csv()
    edges |= csv_gen_edges
    print(f"  CSV-derived Generate edges added: {len(csv_gen_edges)}")

    print(f"Graph summary:")
    print(f"  Nodes: {len(nodes)}  ({sum(1 for n in nodes.values() if n['type']=='api')} API, "
          f"{sum(1 for n in nodes.values() if n['type']!='api')} token)")
    print(f"  Edges: {len(edges)}  "
          f"(UsedIn={sum(1 for e in edges if e[1]=='UsedIn')}, "
          f"Issue={sum(1 for e in edges if e[1]=='Issue')}, "
          f"Generate={sum(1 for e in edges if e[1]=='Generate')})")

    # ── Step 4: Assemble TDG dict ────────────────────────────────────────────
    tdg = {
        "nodes": list(nodes.values()),
        "edges": [
            {"src": src, "type": etype, "dst": dst}
            for src, etype, dst in sorted(edges)
        ],
    }

    return tdg


# ═════════════════════════════════════════════════════════
# Writers
# ═════════════════════════════════════════════════════════

def write_tdg(tdg: dict):
    """Write TDG to CSV (nodes + edges) and JSON."""

    # nodes CSV
    node_fields = ["id", "type", "host", "field", "method", "url", "label"]
    with open(TDG_NODES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=node_fields,
                                extrasaction="ignore", quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(sorted(tdg["nodes"], key=lambda n: (n["type"], n["id"])))

    # edges CSV
    with open(TDG_EDGES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["src", "type", "dst"],
                                quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(tdg["edges"])

    # JSON
    with open(TDG_JSON, "w", encoding="utf-8") as f:
        json.dump(tdg, f, ensure_ascii=False, indent=2)

    print(f"\nTDG written:")
    print(f"  {TDG_NODES_CSV}")
    print(f"  {TDG_EDGES_CSV}")
    print(f"  {TDG_JSON}")


def print_tdg_summary(tdg: dict):
    """Print a human-readable summary of the TDG."""
    nodes_by_type: dict[str, list] = defaultdict(list)
    for n in tdg["nodes"]:
        nodes_by_type[n["type"]].append(n)

    edges_by_type: dict[str, list] = defaultdict(list)
    for e in tdg["edges"]:
        edges_by_type[e["type"]].append(e)

    print("\n" + "=" * 70)
    print("TDG Summary")
    print("=" * 70)

    for token_type in ("auth_token", "refresh_token", "exchange_token"):
        label = token_type.replace("_", " ").title() + "s"
        items = nodes_by_type.get(token_type, [])
        if items:
            print(f"\n{label} ({len(items)}):")
            for n in sorted(items, key=lambda x: x["id"]):
                print(f"  [{n['host']}]  {n['field']}")

    print(f"\nAPI nodes: {len(nodes_by_type.get('api', []))}")

    print(f"\nEdges:")
    print(f"  UsedIn   (Token -> API):     {len(edges_by_type.get('UsedIn', []))}")
    print(f"  Issue    (API -> Token):      {len(edges_by_type.get('Issue', []))}")
    print(f"  Generate (Token -> Token):    {len(edges_by_type.get('Generate', []))}")

    gen_edges = edges_by_type.get("Generate", [])
    if gen_edges:
        print("\nGenerate chains (token derivation):")
        for e in sorted(gen_edges, key=lambda x: x["src"]):
            print(f"  {e['src']}  -->  {e['dst']}")
