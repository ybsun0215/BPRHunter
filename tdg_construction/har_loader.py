import json
from urllib.parse import urlparse
from config import SKIP_METHODS


def load_har(har_file: str) -> list:

    print(f"Loading HAR file: {har_file}")
    with open(har_file, "r", encoding="utf-8") as f:
        har = json.load(f)

    entries = har.get("log", {}).get("entries", [])

    entries = [
        e for e in entries
        if e.get("request", {}).get("method", "").upper() not in SKIP_METHODS
        and 200 <= e.get("response", {}).get("status", 0) <= 299
        and "application/json" in e.get("response", {}).get("content", {}).get("mimeType", "")
    ]

    entries.sort(key=lambda e: e.get("startedDateTime", ""))

    # Deduplicate by path only — ignore query string after '?'
    seen_paths: set[str] = set()
    deduped = []
    for e in entries:
        url = e.get("request", {}).get("url", "")
        path = urlparse(url).scheme + "://" + urlparse(url).netloc + urlparse(url).path
        if path not in seen_paths:
            seen_paths.add(path)
            deduped.append(e)

    print(f"Loaded {len(deduped)} entries after filtering and deduplication")
    print("URLs loaded:")

    return deduped