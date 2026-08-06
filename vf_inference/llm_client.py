"""
llm_client.py
Generic LLM client supporting any OpenAI-compatible API endpoint
(e.g., DeepSeek, OpenAI, Moonshot, etc.).

Uses ``requests`` directly (not the OpenAI SDK) and consumes SSE streaming
responses so large generations are not lost to malformed chunk terminators.

Used by Stage 2 (VF Logic Inference) to call the LLM for:
  - Iterative inference (next-action selection)
  - Code generation (domain script)
  - Code refinement (verification feedback loop)
"""

from __future__ import annotations

import json
import random
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry as UR3Retry
from urllib3.exceptions import IncompleteRead, ProtocolError

import config

# ---------------------------------------------------------------------------
# Retry config
# ---------------------------------------------------------------------------

MAX_RETRIES = 8
RETRY_BASE_DELAY = 3.0   # seconds; doubles each attempt, plus jitter
RETRY_MAX_DELAY = 120.0  # cap backoff at 2 minutes

_UNSET = object()

_last_call_time: float = 0.0

_URLLIB3_RETRIES = UR3Retry(
    total=3,
    backoff_factor=1.0,
    status_forcelist=[429, 500, 502, 503, 504],
    method_whitelist=frozenset(["POST"]),
    raise_on_status=False,
)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _make_session() -> requests.Session:
    """Create a fresh session with connection pooling and low-level retries."""
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=4,
        pool_maxsize=4,
        max_retries=_URLLIB3_RETRIES,
        pool_block=False,
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def call_llm(
    system: str,
    messages: list[dict],
    reasoning_effort: str | None | object = _UNSET,
    enable_thinking: bool | None | object = _UNSET,
    model: str | None = None,
) -> str:

    if not config.API_KEY:
        raise RuntimeError(
            "BPRHUNTER_API_KEY is not set. Export it before running Stage 2."
        )

    # Resolve model
    mdl = model or config.MODEL

    # Build the full message list with system prompt
    full_messages = [{"role": "system", "content": system}] + messages

    # Build request body
    body: dict = {
        "model": mdl,
        "messages": full_messages,
        "stream": True,
    }

    eff = reasoning_effort
    if eff is _UNSET:
        eff = getattr(config, "REASONING_EFFORT", None)
    if eff:
        body["reasoning_effort"] = eff

    # Resolve thinking: same sentinel pattern
    think = enable_thinking
    if think is _UNSET:
        think = getattr(config, "ENABLE_THINKING", False)
    if think:
        body["thinking"] = {"type": "enabled"}


    _rate_limit_delay()

    # Determine API URL
    base = config.API_BASE_URL.rstrip("/")
    url = f"{base}/chat/completions"

    timeout = getattr(config, "LLM_TIMEOUT", 300)

    connect_timeout = min(30, timeout)
    read_timeout = timeout

    last_exc = None
    for attempt in range(MAX_RETRIES):
        session = _make_session()
        try:
            resp = session.post(
                url,
                json=body,
                headers={
                    "Authorization": f"Bearer {config.API_KEY}",
                    "Content-Type": "application/json; charset=utf-8",
                    "Accept": "text/event-stream",
                },
                timeout=(connect_timeout, read_timeout),
                stream=True,
            )
            resp.raise_for_status()
            return _read_streaming_response(resp)
        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.ContentDecodingError,
            IncompleteRead,
            ProtocolError,
        ) as exc:
            last_exc = exc
            if attempt < MAX_RETRIES - 1:
                delay = _backoff(attempt)
                print(f"  [LLM] Attempt {attempt + 1} {type(exc).__name__}, "
                      f"retrying in {delay:.1f}s...")
                time.sleep(delay)
        except requests.exceptions.RequestException as exc:
            # 4xx / 5xx etc.
            status = (
                getattr(exc.response, "status_code", None)
                if hasattr(exc, "response")
                else None
            )
            last_exc = exc
            if attempt < MAX_RETRIES - 1 and status in (429, 500, 502, 503, 504):
                delay = _backoff(attempt)
                print(f"  [LLM] Attempt {attempt + 1} HTTP {status}, "
                      f"retrying in {delay:.1f}s...")
                time.sleep(delay)
            else:
                raise
        finally:
            session.close()

    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_streaming_response(resp: requests.Response) -> str:
    """Reassemble one OpenAI-compatible SSE response.

    DeepSeek occasionally emits an invalid HTTP chunk terminator after the
    final SSE event. Stop as soon as ``finish_reason`` or ``[DONE]`` arrives,
    when the model response is already complete.
    """

    resp.encoding = "utf-8"
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    complete = False

    for raw_line in resp.iter_lines(decode_unicode=True):
        if not raw_line:
            continue
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue

        payload = line[5:].strip()
        if payload == "[DONE]":
            complete = True
            break

        try:
            event = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise requests.exceptions.ChunkedEncodingError(
                f"Malformed SSE event: {exc}"
            ) from exc

        if event.get("error"):
            raise requests.exceptions.RequestException(str(event["error"]))

        choices = event.get("choices") or []
        if not choices:
            continue

        choice = choices[0]
        delta = choice.get("delta") or choice.get("message") or {}
        content_parts.append(delta.get("content") or "")
        reasoning_parts.append(delta.get("reasoning_content") or "")

        if choice.get("finish_reason") is not None:
            complete = True
            break

    if not complete:
        raise requests.exceptions.ChunkedEncodingError(
            "SSE stream ended before finish_reason/[DONE]"
        )

    content = "".join(content_parts)
    if not content:
        reasoning = "".join(reasoning_parts)
        if reasoning:
            content = _extract_final_answer(reasoning)
    return content or ""

def _backoff(attempt: int) -> float:
    """Compute exponential backoff delay with jitter, capped."""
    raw = RETRY_BASE_DELAY * (2 ** attempt)
    capped = min(raw, RETRY_MAX_DELAY)
    jitter = random.uniform(0, capped * 0.5)
    return capped + jitter


def _rate_limit_delay() -> None:
    """Enforce a minimum delay between consecutive API calls, plus jitter."""
    global _last_call_time
    now = time.time()
    min_delay = getattr(config, "LLM_CALL_DELAY", 0.0)
    if min_delay > 0:
        # Add jitter so multiple processes don't synchronize
        effective_delay = min_delay + random.uniform(0, min_delay * 0.5)
        if _last_call_time > 0:
            elapsed = now - _last_call_time
            if elapsed < effective_delay:
                time.sleep(effective_delay - elapsed)
    _last_call_time = time.time()


def _extract_final_answer(reasoning: str) -> str:

    import re

    # Strip thinking / reasoning XML tags
    cleaned = re.sub(r"<thinking>.*?</thinking>", "", reasoning, flags=re.DOTALL)
    cleaned = re.sub(r"<reasoning>.*?</reasoning>", "", cleaned, flags=re.DOTALL)
    if cleaned.strip():
        return cleaned.strip()
    # If after removing tags there's nothing, return the last 2000 chars
    return reasoning[-2000:].strip() if len(reasoning) > 2000 else reasoning.strip()
