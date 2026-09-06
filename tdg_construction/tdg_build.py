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
    alnum_len, bearer_strip, domain_key, get_host,
    extract_response_values, extract_request_fields,
)

# ── Output paths ─────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HAR_FILE = os.path.join(BASE_DIR, "input", "traffic", "demo.har")

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

TokenRef = tuple[str, str, str]


def _load_token_catalog(
    path: str,
    token_type: str,
) -> tuple[
    dict[str, dict[str, set[str]]],
    set[str],
    dict[tuple[str, str], list[TokenRef]],
    dict[TokenRef, dict[str, set[str]]],
]:
    """
    Load one token CSV and resolve consumer aliases to canonical identities.

    Auth tokens are canonicalised to the host and field that issued them.
    Thus the same value consumed by several domains remains one TDG node.

    Returns:
        token_map: canonical_host -> canonical_field -> values
        token_ids: canonical node IDs
        aliases: (consumer_host, request_field_lower) -> token references
        consumers: token reference -> host -> request fields
    """
    token_map: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    token_ids: set[str] = set()
    aliases: dict[tuple[str, str], list[TokenRef]] = defaultdict(list)
    consumers: dict[TokenRef, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )

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
                consumer_host = domain_key(row.get("Host", ""))
                consumer_field = row.get(field_col, "").strip()
                if consumer_host == "unknown" or not consumer_field:
                    continue

                if token_type == "auth":
                    issuer_source = (
                        row.get("Issuer Host")
                        or row.get("Source Response URL")
                        or row.get("Host", "")
                    )
                    canonical_host = domain_key(issuer_source)
                    source_field = row.get("Source Response Key", "").strip()
                    canonical_field = (
                        consumer_field
                        if not source_field or source_field == "__raw__"
                        else source_field
                    )
                else:
                    canonical_host = consumer_host
                    canonical_field = consumer_field

                ref: TokenRef = (
                    canonical_host,
                    canonical_field,
                    f"{token_type}_token",
                )
                tid = make_token_id(canonical_host, canonical_field)
                token_ids.add(tid)
                consumers[ref][consumer_host].add(consumer_field)

                for alias_key in (
                    (consumer_host, consumer_field.lower()),
                    (canonical_host, canonical_field.lower()),
                ):
                    if ref not in aliases[alias_key]:
                        aliases[alias_key].append(ref)

                # Load values: prefer "All Values (JSON)" if present; fall back to "Sample Value"
                all_json = row.get("All Values (JSON)", "")
                if all_json:
                    try:
                        loaded_values = json.loads(all_json)
                    except (json.JSONDecodeError, TypeError):
                        loaded_values = []
                    if not isinstance(loaded_values, list):
                        loaded_values = []
                    for v in loaded_values:
                        for c in bearer_strip(v):
                            if alnum_len(c) >= MIN_ALNUM_LENGTH:
                                token_map[canonical_host][canonical_field].add(c)
                else:
                    for c in bearer_strip(row.get("Sample Value", "")):
                        if alnum_len(c) >= MIN_ALNUM_LENGTH:
                            token_map[canonical_host][canonical_field].add(c)

    except FileNotFoundError:
        print(f"  Warning: {path} not found, skipping")

    return token_map, token_ids, aliases, consumers


def load_token_csv(path: str, token_type: str) -> tuple[dict, set]:
    """Backward-compatible public loader returning the map and IDs only."""
    token_map, token_ids, _, _ = _load_token_catalog(path, token_type)
    return token_map, token_ids


def load_generate_edges_from_csv(
    aliases: dict[tuple[str, str], list[TokenRef]] | None = None,
) -> set[tuple[str, str, str]]:
    gen_edges: set[tuple[str, str, str]] = set()
    aliases = aliases or {}

    def resolve(host: str, field: str, expected_type: str) -> str:
        key = (domain_key(host), field.lower())
        for ref in aliases.get(key, []):
            if ref[2] == expected_type:
                return make_token_id(ref[0], ref[1])
        return make_token_id(domain_key(host), field)

    # refresh token --> auth token
    try:
        with open(REFRESH_TOKEN_CSV, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                host    = row["Host"]
                src_tid = resolve(host, row["Refresh Token Field"], "refresh_token")
                dst_tid = resolve(host, row["Auth Token Field"], "auth_token")
                gen_edges.add((src_tid, "Generate", dst_tid))
    except FileNotFoundError:
        print(f"  Warning: {REFRESH_TOKEN_CSV} not found")

    # exchange token --> auth token
    try:
        with open(EXCHANGE_TOKEN_CSV, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                host    = row["Host"]
                src_tid = resolve(host, row["Exchange Token Field"], "exchange_token")
                dst_tid = resolve(host, row["Auth Token Field"], "auth_token")
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
    auth_catalog = _load_token_catalog(AUTH_TOKEN_CSV, "auth")
    refresh_catalog = _load_token_catalog(REFRESH_TOKEN_CSV, "refresh")
    exchange_catalog = _load_token_catalog(EXCHANGE_TOKEN_CSV, "exchange")

    auth_map, auth_ids, _, _ = auth_catalog
    refresh_map, refresh_ids, _, _ = refresh_catalog
    exchange_map, exchange_ids, _, _ = exchange_catalog

    print(f"  Auth tokens:     {len(auth_ids)}")
    print(f"  Refresh tokens:  {len(refresh_ids)}")
    print(f"  Exchange tokens: {len(exchange_ids)}")

    catalogs = [auth_catalog, refresh_catalog, exchange_catalog]

    alias_index: dict[tuple[str, str], list[TokenRef]] = defaultdict(list)
    consumer_index: dict[TokenRef, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for _, _, aliases, consumers in catalogs:
        for alias_key, refs in aliases.items():
            for ref in refs:
                if ref not in alias_index[alias_key]:
                    alias_index[alias_key].append(ref)
        for ref, hosts in consumers.items():
            for consumer_host, fields in hosts.items():
                consumer_index[ref][consumer_host].update(fields)

    # Bare value -> canonical token references. Values may overlap, so the
    # request/response field alias is used to disambiguate first.
    value_to_token: dict[str, list[TokenRef]] = defaultdict(list)
    for token_map, _, _, consumers in catalogs:
        token_type_by_identity = {
            (ref[0], ref[1]): ref[2] for ref in consumers
        }
        for host, fields in token_map.items():
            for field, values in fields.items():
                token_type = token_type_by_identity.get((host, field))
                if token_type is None:
                    continue
                ref = (host, field, token_type)
                for value in values:
                    if ref not in value_to_token[value]:
                        value_to_token[value].append(ref)

    def _lookup_token(host: str, candi: str, field_name: str = "") -> TokenRef | None:
        """Resolve a candidate value to a token identity.

        Consumer aliases take precedence, which preserves one issuer-owned
        identity even when the same auth token is sent to another domain.
        """
        alias_hits = (
            alias_index.get((host, field_name.lower()), []) if field_name else []
        )
        hits = value_to_token.get(candi, [])
        if hits:
            for alias_hit in alias_hits:
                if alias_hit in hits:
                    return alias_hit
            for hit in hits:
                if hit[0] == host:
                    return hit
            return sorted(hits)[0]
        if alias_hits:
            return sorted(alias_hits)[0]
        return None

    # ── Step 2: Declare nodes ────────────────────────────────────────────────
    # nodes: {node_id: {"type": ..., "label": ..., ...}}
    nodes: dict[str, dict] = {}

    def add_token_node(host, field, token_type):
        nid = make_token_id(host, field)
        if nid not in nodes:
            ref: TokenRef = (host, field, token_type)
            consumers = consumer_index.get(ref, {})
            all_consumer_fields = sorted(
                {name for names in consumers.values() for name in names}
            )
            display_field = all_consumer_fields[0] if all_consumer_fields else field
            nodes[nid] = {
                "id":              nid,
                "type":            token_type,
                "host":            host,
                "field":           display_field,
                "issuer_host":     host,
                "issuer_field":    field,
                "consumer_hosts":  sorted(consumers),
                "consumer_fields": {
                    consumer_host: sorted(fields)
                    for consumer_host, fields in sorted(consumers.items())
                },
                "label":           display_field,
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
    usedin_fields: dict[tuple[str, str], set[str]] = defaultdict(set)
    issue_fields: dict[tuple[str, str], set[str]] = defaultdict(set)

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
            usedin_fields[(tid, api_id)].add(fname)
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
            issue_fields[(api_id, tid)].add(resp_fname)
            resp_token_ids.add(tid)

            for t1 in req_token_ids:
                for t2 in resp_token_ids:
                    if t1 != t2:
                        edges.add((t1, "Generate", t2))

    print("Preserving cross-domain UsedIn edges via issuer/consumer aliases...")

    raw_csv_gen_edges = load_generate_edges_from_csv(alias_index)
    csv_gen_edges = {
        edge for edge in raw_csv_gen_edges
        if edge[0] in nodes and edge[2] in nodes
    }
    edges |= csv_gen_edges
    print(f"  CSV-derived Generate edges added: {len(csv_gen_edges)}")
    skipped_gen_edges = len(raw_csv_gen_edges) - len(csv_gen_edges)
    if skipped_gen_edges:
        print(f"  Skipped Generate edges with missing nodes: {skipped_gen_edges}")

    print(f"Graph summary:")
    print(f"  Nodes: {len(nodes)}  ({sum(1 for n in nodes.values() if n['type']=='api')} API, "
          f"{sum(1 for n in nodes.values() if n['type']!='api')} token)")
    print(f"  Edges: {len(edges)}  "
          f"(UsedIn={sum(1 for e in edges if e[1]=='UsedIn')}, "
          f"Issue={sum(1 for e in edges if e[1]=='Issue')}, "
          f"Generate={sum(1 for e in edges if e[1]=='Generate')})")

    # ── Step 4: Assemble TDG dict ────────────────────────────────────────────
    edge_records = []
    for src, etype, dst in sorted(edges):
        record = {"src": src, "type": etype, "dst": dst}
        if etype == "UsedIn":
            fields = sorted(usedin_fields.get((src, dst), set()))
        elif etype == "Issue":
            fields = sorted(issue_fields.get((src, dst), set()))
        else:
            fields = []
        if fields:
            record["field"] = fields[0]
            if len(fields) > 1:
                record["fields"] = fields
        edge_records.append(record)

    tdg = {"nodes": list(nodes.values()), "edges": edge_records}

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
        writer = csv.DictWriter(
            f,
            fieldnames=["src", "type", "dst", "field", "fields"],
            extrasaction="ignore",
            quoting=csv.QUOTE_ALL,
        )
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
