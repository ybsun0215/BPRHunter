from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import config


# ─── Verified-script artifact helpers ────────────────────────────────────────

SCRIPT_NAME = "update_vf.py"
MANIFEST_NAME = "_verification.json"
MANIFEST_VERSION = 2


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_verification_manifest(
    out_dir: str | Path,
    *,
    domain: str,
    vf_fields: list[str],
    verified: bool,
    reason: str = "",
    source_path: str | Path | None = None,
) -> Path:
    """Record whether the canonical script passed Stage 2 verification."""

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    script_path = directory / SCRIPT_NAME
    digest = _sha256_bytes(script_path.read_bytes()) if script_path.is_file() else ""
    source = Path(source_path) if source_path is not None else None
    source_digest = (
        _sha256_bytes(source.read_bytes()) if source is not None and source.is_file() else ""
    )
    manifest = {
        "version": MANIFEST_VERSION,
        "domain": domain,
        "vf_fields": list(vf_fields),
        "verified": bool(verified),
        "script": SCRIPT_NAME,
        "script_sha256": digest,
        "source_sha256": source_digest,
        "reason": reason,
    }
    path = directory / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def validate_verified_script(
    script_path: str | Path,
    *,
    expected_domain: str | None = None,
    expected_source_path: str | Path | None = None,
) -> tuple[bool, str]:
    """Validate the Stage 2 marker and bind it to the exact script bytes."""

    script = Path(script_path)
    if not script.is_file():
        return False, f"VF script is missing: {script}"

    manifest_path = script.parent / MANIFEST_NAME
    if not manifest_path.is_file():
        return False, f"verification manifest is missing: {manifest_path}"

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"verification manifest is unreadable: {exc}"

    if manifest.get("version") != MANIFEST_VERSION:
        return False, "verification manifest version is unsupported"
    if not manifest.get("verified"):
        reason = manifest.get("reason") or "Stage 2 did not verify this script"
        return False, str(reason)
    if manifest.get("script") != script.name:
        return False, "verification manifest points to a different script"
    if expected_domain is not None and manifest.get("domain") != expected_domain:
        return False, "verification manifest belongs to a different domain"

    expected_digest = manifest.get("script_sha256", "")
    actual_digest = _sha256_bytes(script.read_bytes())
    if not expected_digest or expected_digest != actual_digest:
        return False, "VF script changed after verification"

    if expected_source_path is not None:
        source = Path(expected_source_path)
        if not source.is_file():
            return False, f"verification source is missing: {source}"
        expected_source_digest = manifest.get("source_sha256", "")
        actual_source_digest = _sha256_bytes(source.read_bytes())
        if not expected_source_digest or expected_source_digest != actual_source_digest:
            return False, "HAR input changed after VF verification"

    return True, "verified"


def verify_domain_script(
    vf_list: list[str],
    initial_code: str,
    traffic: list[dict],
    refine_fn,
    context: str = "",
) -> tuple[bool, str]:

    code = initial_code
    samples = _find_samples(vf_list, traffic)
    if not samples:
        print("  [!] No traffic entry contains every VF; verification failed.")
        return False, code

    for iteration in range(config.MAX_VERIFY_ITERATIONS):
        print(f"\n  [verify iter {iteration + 1}] Executing domain script against traffic...")

        failures: list[str] = []
        pass_feedback: list[str] = []
        for sample_index, sample in enumerate(samples, start=1):
            is_correct, feedback = _run_verification(vf_list, code, sample)
            if is_correct:
                pass_feedback.append(feedback)
            else:
                failures.append(f"sample {sample_index}: {feedback}")

        if not failures:
            for line in pass_feedback[0].split("; "):
                line = line.strip()
                if "PASS" in line or "PRESENT" in line:
                    print(f"     {line}")
            print(f"  [+] VERIFIED against all {len(samples)} sample(s)")
            return True, code

        print(f"  [!] Verification FAILED:")
        feedback = "\n".join(failures)
        for line in feedback.splitlines():
            line = line.strip()
            print(f"      {line}")

        try:
            code = refine_fn(code, feedback, context)
        except Exception as exc:
            print(f"  [!] Refinement failed: {exc}")
            return False, code

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
    """Compatibility helper: return the first fully verifiable sample."""
    samples = _find_samples(vf_list, traffic)
    return samples[0] if samples else None


def _find_samples(
    vf_list: list[str],
    traffic: list[dict],
) -> list[dict]:
    """Return every traffic entry containing all VF request headers."""
    samples = []
    for entry in traffic:
        headers = entry.get("request", {}).get("headers", {})
        if isinstance(headers, dict) and all(field in headers for field in vf_list):
            samples.append(entry)
    return samples


def _build_test_script(
    vf_list: list[str],
    code: str,
    sample: dict,
) -> str:

    request_json = json.dumps(sample.get("request", {}))

    # Which VFs are time/random-based and should skip exact comparison?
    skip_verify = [
        vf for vf in vf_list
        if _is_ephemeral_field(vf)
    ]

    return f"""{code}

# Verification harness — auto-generated, do not edit
import json

request = json.loads({json.dumps(request_json)})
vf_names = {json.dumps(vf_list)}
_skip_verify = set({json.dumps(skip_verify)})

# Record expected values before update
expected = {{}}
for vf in vf_names:
    for loc in ("headers", "query", "body"):
        container = request.get(loc, {{}})
        if isinstance(container, dict) and vf in container:
            expected[vf] = container[vf]
            break

try:
    updated = update_vf(request)
    all_ok = True
    messages = []
    for vf in vf_names:
        actual = None
        for loc in ("headers", "query", "body"):
            container = updated.get(loc, {{}})
            if isinstance(container, dict) and vf in container:
                actual = container[vf]
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
    with tempfile.TemporaryDirectory(prefix="bprhunter_vf_verify_") as tmp_dir:
        tmp = Path(tmp_dir) / "vf_verify_domain.py"
        tmp.write_text(script, encoding="utf-8")

        try:
            out = (
                subprocess.check_output(
                    [sys.executable, str(tmp)], timeout=15, stderr=subprocess.STDOUT
                )
                .decode()
                .strip()
            )
        except subprocess.CalledProcessError as e:
            return False, f"Execution error: {e.output.decode().strip()}"
        except subprocess.TimeoutExpired:
            return False, "Execution timed out."

    return out.startswith("PASS:"), out
