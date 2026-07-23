from __future__ import annotations

import argparse
import json
import os
import sys


def _extract_code_from_chat_history(chat_history: list[dict]) -> str | None:
    """Extract generated Python code from the last assistant message in chat history."""
    for msg in reversed(chat_history):
        if msg.get("role") != "assistant":
            continue
        try:
            data = json.loads(msg.get("content", "{}"))
            code = data.get("_generated_code")
            if code and "def update_vf" in code:
                return code
        except (json.JSONDecodeError, TypeError):
            pass
    return None


def _is_simple_ephemeral(field_name: str) -> bool:
    """Return True for time/date fields that don't need complex inference."""
    lower = field_name.lower()
    return any(p in lower for p in ("timestamp", "date", "nonce"))


# ---------------------------------------------------------------------------
# Stage 1 — TDG Construction
# ---------------------------------------------------------------------------

def run_stage1() -> None:
    print("\n" + "=" * 60)
    print("Stage 1: TDG Construction")
    print("=" * 60)

    import config
    from tdg_construction.har_loader import load_har
    from tdg_construction.auth_identify import identify_auth_tokens
    from tdg_construction.refresh_identify import identify_refresh_tokens
    from tdg_construction.exchange_identify import identify_exchange_tokens
    from tdg_construction.tdg_build import build_tdg, write_tdg, print_tdg_summary


    os.makedirs(config.TDG_DIR, exist_ok=True)

    entries = load_har(config.HAR_FILE)

    print("\n[Stage 1.1] Auth token identification")
    print("-" * 40)
    identify_auth_tokens(entries, output_csv=config.AUTH_TOKEN_CSV)

    print("\n[Stage 1.2] Refresh token identification")
    print("-" * 40)
    identify_refresh_tokens(
        entries,
        auth_csv=config.AUTH_TOKEN_CSV,
        output_csv=config.REFRESH_TOKEN_CSV,
    )

    print("\n[Stage 1.3] Exchange token identification")
    print("-" * 40)
    identify_exchange_tokens(
        entries,
        auth_csv=config.AUTH_TOKEN_CSV,
        refresh_csv=config.REFRESH_TOKEN_CSV,
        output_csv=config.EXCHANGE_TOKEN_CSV,
    )

    print("\n[Stage 1.4] TDG construction")
    print("-" * 40)
    tdg = build_tdg(entries)
    write_tdg(tdg)
    print_tdg_summary(tdg)

    print(f"\n[Stage 1 complete]")
    print(f"  Auth tokens     -> {config.AUTH_TOKEN_CSV}")
    print(f"  Refresh tokens  -> {config.REFRESH_TOKEN_CSV}")
    print(f"  Exchange tokens -> {config.EXCHANGE_TOKEN_CSV}")
    print(f"  TDG             -> {config.TDG_PATH}")


# ---------------------------------------------------------------------------
# Stage 2 — VF Logic Inference
# ---------------------------------------------------------------------------

def run_stage2() -> None:
    print("\n" + "=" * 60)
    print("Stage 2: VF Logic Inference")
    print("=" * 60)

    import config
    from pathlib import Path
    from tdg_construction.har_loader import load_har
    from vf_inference.vf_identification import (
        identify_dynamic_fields,
        locate_code_context,
        parse_har_entries,
    )
    from vf_inference.logic_inference import run_iterative_inference
    from vf_inference.code_generation import refine_domain_script
    from vf_inference.verification import verify_domain_script

    raw_entries = load_har(config.HAR_FILE)
    traffic = parse_har_entries(raw_entries)

    # Step 2.1: VF Identification (per domain)
    if config.MANUAL_VFS:
        print("\n[Stage 2.1] Using manually specified VFs from config.MANUAL_VFS")
        vfs_by_domain = config.MANUAL_VFS
    else:
        print("\n[Stage 2.1] Identifying dynamic VFs from traffic")
        vfs_by_domain = identify_dynamic_fields(traffic)

    for domain, vf_set in vfs_by_domain.items():
        print(f"  {domain}: {vf_set}")

    # Group traffic by domain
    traffic_by_domain: dict[str, list[dict]] = {}
    for entry in traffic:
        d = entry.get("domain", "unknown")
        traffic_by_domain.setdefault(d, []).append(entry)

    # Step 2.2–2.3: Per-field inference → in-chat code generation
    import json as _json
    from vf_inference.code_generation import _extract_code_from_chat_history as _extract_code

    for domain, vf_list in vfs_by_domain.items():
        print(f"\n{'#' * 60}")
        print(f"Domain: {domain}  |  VFs: {vf_list}")
        print(f"{'#' * 60}")

        domain_traffic = traffic_by_domain.get(domain, [])
        out_dir = Path(config.VF_DIR) / domain
        out_dir.mkdir(parents=True, exist_ok=True)

        # Check for cached chat histories (resume support)
        cache_path = out_dir / "_chat_histories.json"
        if cache_path.exists():
            print("  [*] Loading cached chat histories from previous run.")
            chat_histories = _json.loads(cache_path.read_text(encoding="utf-8"))
            # Extract code from cached history
            primary = chat_histories.get("_primary_vf", "")
            primary_history = chat_histories.get(primary, [])
            code = _extract_code(primary_history) or ""
        else:
            ephemeral_vfs = [f for f in vf_list
                             if _is_simple_ephemeral(f)]
            signature_vfs = [f for f in vf_list
                             if f not in ephemeral_vfs]

            chat_histories: dict[str, list[dict]] = {}

            # ── Ephemeral VFs: quick inference only ──
            ephemeral_analyses_parts: list[str] = []
            for field in ephemeral_vfs:
                print(f"\n{'=' * 60}")
                print(f"Domain: {domain}  |  VF: {field}  (ephemeral)")
                print(f"{'=' * 60}")

                print("[Stage 2.2] Running iterative inference on Smali code")
                ctx = locate_code_context(field, config.SMALI_DIR)
                ctx, history = run_iterative_inference(ctx, config.SMALI_DIR, {})
                chat_histories[field] = history

                # Collect analysis for the code-gen prompt
                from vf_inference.code_generation import _extract_inference_conclusions
                analysis = _extract_inference_conclusions(history)
                ephemeral_analyses_parts.append(f"=== {field} ===\n{analysis}")

            # ── Signature VFs: inference + code-gen in ONE chat ──
            code = ""
            for field in signature_vfs:
                print(f"\n{'=' * 60}")
                print(f"Domain: {domain}  |  VF: {field}  (signature, with code-gen)")
                print(f"{'=' * 60}")

                print("[Stage 2.2] Running iterative inference on Smali code")
                ctx = locate_code_context(field, config.SMALI_DIR)
                from vf_inference.logic_inference import run_inference_with_codegen
                ctx, history, code = run_inference_with_codegen(
                    ctx=ctx,
                    smali_dir=config.SMALI_DIR,
                    credentials={},
                    vf_list=vf_list,
                    ephemeral_analyses="\n\n".join(ephemeral_analyses_parts),
                )
                chat_histories[field] = history
                chat_histories["_primary_vf"] = field

            # Save chat histories to disk
            cache_path.write_text(
                _json.dumps(chat_histories, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"  [*] Chat histories + code cached -> {cache_path}")

        if not code:
            print("  [!] Code generation failed — no code in chat history.")
            continue

        print(f"\n[Stage 2.3] Code extracted from chat ({len(code.splitlines())} lines)")

        # Step 2.4: Verify & refine (smali-based, no inference-model dependency)
        print(f"\n[Stage 2.4] Verifying domain script")

        from vf_inference.verification import _run_verification, _find_sample
        from vf_inference.code_generation import _extract_inference_conclusions

        _sample = _find_sample(vf_list, domain_traffic)
        final_code = code
        verified = False

        # Build smali context once — reused for every refine iteration
        _primary_vf = [f for f in vf_list if f not in ("x-ca-timestamp", "x-sdk-date")]
        _primary_vf = _primary_vf[0] if _primary_vf else vf_list[0]
        _primary_history = chat_histories.get(_primary_vf, [])
        _smali_context = _extract_inference_conclusions(_primary_history)

        for _v_iter in range(config.MAX_VERIFY_ITERATIONS):
            if _sample is None:
                print("  [!] No traffic sample, skipping verification.")
                verified = True
                break

            is_correct, feedback = _run_verification(vf_list, final_code, _sample)
            if is_correct:
                print(f"    [+] VERIFIED")
                verified = True
                break

            print(f"    [!] FAILED: {feedback[:120]}...")
            print(f"    [refine iter {_v_iter + 1}] Refining with smali context...")

            try:
                final_code = refine_domain_script(final_code, feedback, _smali_context)
                print(f"    Refined: {len(final_code.splitlines())} lines.")
            except Exception as exc:
                print(f"    [!] Refine error: {exc}")
                break

        status = "VERIFIED" if verified else "UNVERIFIED (max iterations reached)"
        print(f"  Status: {status}")

        # Save ONE script per domain
        out_file = out_dir / "update_vf.py"
        out_file.write_text(final_code, encoding="utf-8")
        print(f"  Saved: {out_file}")

    print(f"\n[Stage 2 complete]  VF scripts -> {config.VF_DIR}")


# ---------------------------------------------------------------------------
# Stage 3 — BPR Vulnerability Detection
# ---------------------------------------------------------------------------

def run_stage3() -> None:
    print("\n" + "=" * 60)
    print("Stage 3: BPR Vulnerability Detection")
    print("=" * 60)

    import config
    from testcase_construction.case_gen import (
        TDG,
        HARTraffic,
        generate_test_cases,
        save_test_cases,
        append_test_case_log,
        clear_test_case_log,
    )
    from testcase_construction.resp_collect import send_test_case
    from testcase_construction.resp_compare import (
        load_model,
        compare_response,
        save_results,
    )

    tdg = TDG(config.TDG_PATH)
    har = HARTraffic(config.HAR_FILE)

    # ═════════════════════════════════════════════════════════════════
    # Full pipeline:  generate → send (mock) → compare → save
    #
    # HTTP calls return the original HAR response, so similarity = 1.0
    # for every test case.  Set DEMO_MODE=False + uncomment
    # send_request() real-HTTP path for production use.
    # ═════════════════════════════════════════════════════════════════

    model = load_model()
    clear_test_case_log()

    # ── Generate + Send ──
    print("\n[Stage 3.1] Generating & sending test cases")
    print("-" * 40)
    collected_cases = []
    collected_responses = []

    for i, tc in enumerate(generate_test_cases(tdg, har, dry_run=False), start=1):
        response, error = send_test_case(tc)
        collected_cases.append(tc)
        collected_responses.append((response, error))
        append_test_case_log(tc, response, error)

        chain_label = " -> ".join(tc.chain) if tc.chain else "(base)"
        http_status = response.get("status", 0) if not error else f"ERR:{error}"
        print(f"  [{i}] api={tc.base_api_id}  chain={chain_label}  status={http_status}")

    base_count = sum(1 for tc in collected_cases if not tc.chain)
    chain_count = sum(1 for tc in collected_cases if tc.chain)
    print(f"\n  Generated & sent {len(collected_cases)} test case(s) "
          f"(base={base_count}, chain={chain_count}).")

    # ── Compare ──
    print("\n[Stage 3.2] Comparing responses")
    print("-" * 40)

    results = []
    for i, (tc, (response, error)) in enumerate(
        zip(collected_cases, collected_responses), start=1
    ):
        result = compare_response(tc, response, error, har, model, index=i)
        results.append(result)

    # ── Save ──
    print("\n[Stage 3.3] Saving results")
    print("-" * 40)
    save_test_cases(collected_cases)
    save_results(results)

    vuln_chains = set()
    total_chains = set()
    for r in results:
        ck = " -> ".join(r.chain) if r.chain else "(base)"
        total_chains.add((r.token_id, ck))
        if r.is_vulnerable:
            vuln_chains.add((r.token_id, ck))

    vuln_count = len(vuln_chains)
    print(f"\n[Stage 3 complete]")
    print(f"  Vulnerabilities : {vuln_count} / {len(total_chains)} chains "
          f"({len(results)} test cases)")
    print(f"  Test cases      -> {config.TESTCASES_DIR}")
    print(f"  Results         -> {config.RESULTS_DIR}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

STAGE_RUNNERS = {
    1: run_stage1,
    2: run_stage2,
    3: run_stage3,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BPRHunter — automated BPR vulnerability detection for ICV cloud platforms"
    )
    parser.add_argument(
        "--stages",
        nargs="+",
        type=int,
        choices=[1, 2, 3],
        default=[1, 2, 3],
        metavar="N",
        help="Stages to run (default: 1 2 3). Example: --stages 1 2",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        default=False,
        help="Run in demo mode: uses demo data with mock HTTP responses. "
             "The full Stage 3 pipeline (generate → send → compare → save) "
             "runs end-to-end, with every HTTP call returning the original "
             "HAR response so similarity is always 1.0. "
             "No target permissions needed.",
    )
    args = parser.parse_args()

    import config

    # ── Demo flag: no-op (mock HTTP is now the default) ──
    if args.demo:
        config.DEMO_MODE = True

    # Validate required inputs before starting
    if 1 in args.stages or 2 in args.stages or 3 in args.stages:
        if not os.path.isfile(config.HAR_FILE):
            print(f"[ERROR] HAR file not found: {config.HAR_FILE}", file=sys.stderr)
            sys.exit(1)

    if 3 in args.stages and 1 not in args.stages:
        if not os.path.isfile(config.TDG_PATH):
            print(
                f"[ERROR] TDG file not found: {config.TDG_PATH}\n"
                f" Run Stage 1 first, or include --stages 1 3",
                file=sys.stderr,
            )
            sys.exit(1)

    print("=" * 60)
    print("BPRHunter")
    print(f"Stages to run: {args.stages}")
    if args.demo:
        print("Mode: DEMO (mock HTTP)")
    print("=" * 60)

    for stage_num in sorted(args.stages):
        STAGE_RUNNERS[stage_num]()

    print("\n" + "=" * 60)
    print("All stages complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
