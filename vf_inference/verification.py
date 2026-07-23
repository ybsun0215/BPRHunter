from __future__ import annotations

import json
import subprocess
from pathlib import Path

import config


def verify_domain_script(
    vf_list: list[str],
    initial_code: str,
    traffic: list[dict],
    refine_fn,
    context: str = "",
) -> tuple[bool, str]:

    code = initial_code
    sample = _find_sample(vf_list, traffic)
    if sample is None:
        print("  [!] No suitable traffic sample found; skipping verification.")
        return True, code

    for iteration in range(config.MAX_VERIFY_ITERATIONS):
        print(f"\n  [verify iter {iteration + 1}] Executing domain script against traffic...")

        is_correct, feedback = _run_verification(vf_list, code, sample)
        if is_correct:
            for line in feedback.split("; "):
                line = line.strip()
                if "PASS" in line or "PRESENT" in line:
                    print(f"     {line}")
            print(f"  [+] VERIFIED")
            return True, code

        print(f"  [!] Verification FAILED:")
        for line in feedback.split("; "):
            line = line.strip()
            print(f"      {line}")

        code = refine_fn(code, feedback, context)

    print(f"  [!] Max verification iterations ({config.MAX_VERIFY_ITERATIONS}) reached.")
    return False, code


# ─── Verification Execution ───────────────────────────────────────────────────

def _run_verification(
    vf_list: list[str],
    code: str,
    sample: dict,
) -> tuple[bool, str]:
    """Execute the script and compare each VF against the ground truth."""
    script = _build_test_script(vf_list, code, sample)
    return _execute_script(script)


def _is_ephemeral_field(field_name: str) -> bool:
    """Return True if *field_name* is time- or random-based."""
    lower = field_name.lower()
    for pattern in ("time", "date", "nonce"):
        if pattern in lower:
            return True
    return False


def _find_sample(
    vf_list: list[str],
    traffic: list[dict],
) -> dict | None:
    """Find the first traffic entry that contains all VF fields."""
    for entry in traffic:
        req = entry.get("request", {})
        headers = req.get("headers", {})
        # Check that all VFs are present in the request headers
        if all(field in headers for field in vf_list):
            return entry
    # Relaxed: return the first entry that has at least one VF
    for entry in traffic:
        req = entry.get("request", {})
        headers = req.get("headers", {})
        if any(field in headers for field in vf_list):
            return entry
    return None


def _build_test_script(
    vf_list: list[str],
    code: str,
    sample: dict,
) -> str:

    request_json = json.dumps(sample.get("request", {}))

    # Which VFs are time/random-based and should skip exact comparison?
    skip_verify_json = json.dumps([
        vf for vf in vf_list
        if _is_ephemeral_field(vf)
    ])

    return f"""{code}

# Verification harness — auto-generated, do not edit
import json

request = json.loads({json.dumps(request_json)})
vf_names = {json.dumps(vf_list)}
_skip_verify = set({json.dumps(skip_verify_json)})

# Record expected values before update
expected = {{}}
for vf in vf_names:
    for loc in ("headers", "query", "body"):
        if vf in request.get(loc, {{}}):
            expected[vf] = request[loc][vf]
            break

try:
    updated = update_vf(request)
    all_ok = True
    messages = []
    for vf in vf_names:
        actual = None
        for loc in ("headers", "query", "body"):
            if vf in updated.get(loc, {{}}):
                actual = updated[loc][vf]
                break

        if vf in _skip_verify:
            # Time/random fields — only check presence, never compare values
            if actual is not None:
                messages.append(f"{{vf}}:PRESENT")
            else:
                messages.append(f"{{vf}}:MISSING")
                all_ok = False
        else:
            exp = expected.get(vf)
            if actual is not None and str(actual) == str(exp):
                messages.append(f"{{vf}}:PASS")
            else:
                # Show only the hex signature for readability
                import re as _re
                _em = _re.search(r'Signature=([a-f0-9]+)', str(exp) if exp else '')
                _am = _re.search(r'Signature=([a-f0-9]+)', str(actual) if actual else '')
                _es = _em.group(1) if _em else str(exp)[:40]
                _as = _am.group(1) if _am else str(actual)[:40]
                messages.append(
                    f"{{vf}}:MISMATCH\\n"
                    f"  expected=Sig({{_es}})\\n"
                    f"  computed=Sig({{_as}})"
                )
                all_ok = False
    if all_ok:
        print("PASS:" + "; ".join(messages))
    else:
        print("FAIL:" + "; ".join(messages))
except Exception as e:
    import traceback
    print("ERROR:" + traceback.format_exc())
"""


def _execute_script(script: str) -> tuple[bool, str]:
    tmp = Path("/tmp/vf_verify_domain.py")
    tmp.write_text(script, encoding="utf-8")

    try:
        out = (
            subprocess.check_output(
                ["python3", str(tmp)], timeout=15, stderr=subprocess.STDOUT
            )
            .decode()
            .strip()
        )
    except subprocess.CalledProcessError as e:
        return False, f"Execution error: {e.output.decode().strip()}"
    except subprocess.TimeoutExpired:
        return False, "Execution timed out."

    return out.startswith("PASS:"), out
