from __future__ import annotations

import json
import os
from dataclasses import dataclass

import config
from .case_gen import TestCase, HARTraffic


SIMILARITY_THRESHOLD = getattr(config, "SIMILARITY_THRESHOLD", 0.90)

# Lazy imports for heavy ML dependencies (only needed in production mode)
_np = None
_SentenceTransformer = None


def _get_np():
    global _np
    if _np is None:
        import numpy as _numpy
        _np = _numpy
    return _np


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ComparisonResult:
    base_api_id:       str
    token_id:          str
    chain:             list[str]
    new_token_value:   str
    new_status:        int
    original_response: str
    new_response:      str
    similarity:        float
    is_vulnerable:     bool
    error:             str


# ---------------------------------------------------------------------------
# Sentence-BERT model (loaded once)
# ---------------------------------------------------------------------------

def load_model() -> "SentenceTransformer | None":
    """Load the Sentence-BERT model, or return None in demo / missing deps.

    Returns None when ``config.DEMO_MODE`` is True, or when
    ``sentence-transformers`` is not installed.  In that case
    ``calculate_similarity`` falls back to exact-text comparison.
    """
    if config.DEMO_MODE:
        print("[INFO] DEMO_MODE — using exact-text comparison")
        return None

    global _SentenceTransformer
    if _SentenceTransformer is None:
        try:
            from sentence_transformers import SentenceTransformer as ST
            _SentenceTransformer = ST
        except ImportError:
            print("[WARN] sentence-transformers not installed; using exact-text comparison")
            return None

    model_path = config.MODEL_PATH
    if not os.path.exists(model_path):
        print(f"[INFO] Downloading model to {model_path} ...")
        model = _SentenceTransformer("all-MiniLM-L6-v2")
        model.save(model_path)
        print(f"[INFO] Model saved.")
    else:
        print(f"[INFO] Loading model from {model_path} ...")
        model = _SentenceTransformer(model_path)
    return model


# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------

def calculate_similarity(model: "SentenceTransformer | None", text1: str, text2: str) -> float:

    if model is None:
        # Demo mode: exact-text comparison
        return 1.0 if text1 == text2 else 0.0

    np = _get_np()
    emb1 = model.encode(text1)
    emb2 = model.encode(text2)
    cosine_sim = np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2))
    return float(cosine_sim)


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_response(
    tc: TestCase,
    response: dict,
    error: str,
    har: HARTraffic,
    model: "SentenceTransformer | None",
    index: int,
) -> ComparisonResult:

    new_status = response.get("status", 0)
    new_body = response.get("body", "")

    if error:
        print(f"[ERROR #{index}] Request failed for {tc.base_api_id}: {error}")
        return _make_result(
            tc, new_status=new_status,
            original_response="", new_response="",
            similarity=0.0, is_vulnerable=False, error=error,
        )

    original_resp = har.find_response_text(tc.base_api_id)
    if original_resp is None:
        msg = "No original response found in HAR"
        print(f"[SKIP #{index}] {msg}: {tc.base_api_id}")
        return _make_result(
            tc, new_status=new_status,
            original_response="", new_response=new_body,
            similarity=0.0, is_vulnerable=False, error=msg,
        )

    similarity = calculate_similarity(model, original_resp, new_body)
    is_vulnerable = similarity >= SIMILARITY_THRESHOLD

    chain_str = " -> ".join(tc.chain) if tc.chain else "(base)"
    tag = "*** BRP VULNERABILITY ***" if is_vulnerable else "safe"
    print(f"[{tag}] #{index}  api={tc.base_api_id}  status={new_status}")
    print(f"  chain={chain_str}")
    print(f"  similarity={similarity:.4f}  threshold={SIMILARITY_THRESHOLD}")

    return _make_result(
        tc, new_status=new_status,
        original_response=original_resp,
        new_response=new_body,
        similarity=similarity,
        is_vulnerable=is_vulnerable,
        error="",
    )


# ---------------------------------------------------------------------------
# Persist results
# ---------------------------------------------------------------------------

def save_results(results: list[ComparisonResult]) -> None:

    results_dir = config.RESULTS_DIR
    os.makedirs(results_dir, exist_ok=True)

    by_token: dict[str, list[ComparisonResult]] = {}
    for r in results:
        by_token.setdefault(r.token_id, []).append(r)

    # ── Count vulnerabilities by derivation chain ──
    # A (token_id, chain_key) pair = one potential vulnerability.
    # It is vulnerable if ANY test case for that pair is vulnerable.
    vuln_chains: set[tuple[str, str]] = set()
    total_chains: set[tuple[str, str]] = set()

    for r in results:
        chain_key = " -> ".join(r.chain) if r.chain else "(base)"
        pair = (r.token_id, chain_key)
        total_chains.add(pair)
        if r.is_vulnerable:
            vuln_chains.add(pair)

    total_vuln = len(vuln_chains)
    print(f"\n[INFO] Total: {total_vuln}/{len(total_chains)} vulnerable chains "
          f"({len(results)} test cases).")

    for token_id, token_results in by_token.items():
        safe_name = token_id.replace("/", "_").replace(":", "_").replace(" ", "_")
        out_path = os.path.join(results_dir, f"{safe_name}.json")

        output = [_result_to_dict(r) for r in token_results]

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        # Count vulns per token by chain
        token_vulns = set()
        token_total = set()
        for r in token_results:
            ck = " -> ".join(r.chain) if r.chain else "(base)"
            token_total.add(ck)
            if r.is_vulnerable:
                token_vulns.add(ck)

        vuln_count = len(token_vulns)
        print(f"  [INFO] {vuln_count}/{len(token_total)} vulnerable chains "
              f"-> {out_path}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    tc: TestCase,
    new_status: int,
    original_response: str,
    new_response: str,
    similarity: float,
    is_vulnerable: bool,
    error: str,
) -> ComparisonResult:
    return ComparisonResult(
        base_api_id=tc.base_api_id,
        token_id=tc.token_id,
        chain=tc.chain,
        new_token_value=tc.new_token_value,
        new_status=new_status,
        original_response=original_response,
        new_response=new_response,
        similarity=round(similarity, 4),
        is_vulnerable=is_vulnerable,
        error=error,
    )


def _result_to_dict(r: ComparisonResult) -> dict:
    return {
        "base_api_id":       r.base_api_id,
        "token_id":          r.token_id,
        "chain":             r.chain,
        "new_token_value":   r.new_token_value,
        "new_status":        r.new_status,
        "original_response": r.original_response,
        "new_response":      r.new_response,
        "similarity":        r.similarity,
        "is_vulnerable":     r.is_vulnerable,
        "error":             r.error,
    }
