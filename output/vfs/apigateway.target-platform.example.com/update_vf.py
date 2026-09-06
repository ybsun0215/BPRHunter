import hashlib
import hmac
import json
import datetime
from urllib.parse import quote, unquote

ACCESS_KEY = "PLACEHOLDER_ACCESS"
SECRET_KEY = "PLACEHOLDER_SECRET"


def update_vf(request: dict) -> dict:
    headers = request.get("headers")
    if headers is None:
        headers = {}
        request["headers"] = headers

    now = datetime.datetime.now(datetime.timezone.utc)

    if headers.get("x-demo-date") is None:
        headers["x-demo-date"] = now.strftime("%Y%m%dT%H%M%SZ")

    if headers.get("x-demo-timestamp") is None:
        headers["x-demo-timestamp"] = str(int(now.timestamp() * 1000))

    date_value = headers.get("x-demo-date", "")

    body = request.get("body")
    if body is None or body == "":
        body_bytes = b""
    elif isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = json.dumps(body).encode("utf-8")

    payload_hash = headers.get("x-demo-content-sha256")
    if payload_hash is None:
        payload_hash = hashlib.sha256(body_bytes).hexdigest()
    else:
        payload_hash = str(payload_hash)

    header_names = sorted(headers.keys(), key=lambda n: str(n).lower())

    signed_parts = []
    canonical_lines = []

    for name in header_names:
        if str(name).lower() == "sign":
            continue

        lower_name = str(name).lower()
        signed_parts.append(lower_name)

        value = headers[name]
        if value is None:
            value = ""
        else:
            value = str(value).strip()

        canonical_lines.append(f"{lower_name}:{value}\n")

    signed_headers = ";".join(signed_parts)
    canonical_headers = "".join(canonical_lines)

    raw_path = request.get("path", "/")
    if raw_path is None or raw_path == "":
        raw_path = "/"

    decoded_path = unquote(str(raw_path))
    canonical_path = quote(decoded_path, safe="/")

    if not canonical_path.startswith("/"):
        canonical_path = "/" + canonical_path

    if not canonical_path.endswith("/"):
        canonical_path = canonical_path + "/"

    canonical_request = (
        f"{request.get('method', 'GET')}\n"
        f"{canonical_path}\n\n"
        f"{canonical_headers}"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    canonical_request_hash = hashlib.sha256(
        canonical_request.encode("utf-8")
    ).hexdigest()

    string_to_sign = f"DEMO-HMAC-SHA256\n{date_value}\n{canonical_request_hash}"

    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    sign_value = (
        f"DEMO-HMAC-SHA256 Access={ACCESS_KEY}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    for key in [k for k in headers if str(k).lower() == "sign"]:
        del headers[key]

    headers["sign"] = sign_value

    return request