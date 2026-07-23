import hashlib
import hmac
import json
import datetime
import uuid
import urllib.parse
import time

ACCESS_KEY = "PLACEHOLDER_ACCESS"
SECRET_KEY = "PLACEHOLDER_SECRET"

def url_encode(path, keep_slashes):
    """Mimics HttpUtils.urlEncode"""
    # URLEncoder.encode would produce '+' for spaces, so we mimic that behaviour
    encoded = urllib.parse.quote(path, safe='')
    # Java URLEncoder.encode turns space into '+', but Python quote uses %20.
    # We want to keep %20, so we replace any '+' (shouldn't occur) with %20 for safety
    encoded = encoded.replace('+', '%20')
    # Replace '*' with %2A
    encoded = encoded.replace('*', '%2A')
    # Replace %7E with ~
    encoded = encoded.replace('%7E', '~')
    if keep_slashes:
        encoded = encoded.replace('%2F', '/')
    return encoded

def compute_v587sign(headers, method, path, body, access_key, secret_key, x_sdk_date):
    """Implements SignUtils.computeV587sign exactly as per smali."""
    # Build sorted header keys (case-insensitive comparator)
    sorted_keys = sorted(headers.keys(), key=lambda k: k.lower())

    # Determine content hash
    content_hash = None
    if "x-sdk-content-sha256" in headers:
        content_hash = headers["x-sdk-content-sha256"]
    else:
        if body is None:
            body_bytes = b""
        elif isinstance(body, str):
            body_bytes = body.encode('utf-8')
        else:
            # Assume dict -> JSON
            body_bytes = json.dumps(body, separators=(',', ':')).encode('utf-8')
        sha256_hash = hashlib.sha256(body_bytes).hexdigest()
        content_hash = sha256_hash

    # Build canonical headers string and signed headers string
    canonical_headers = ""
    signed_headers = ""
    for key in sorted_keys:
        if key.lower() == "v587sign":
            continue
        # Add to signed headers (semicolon separated)
        if signed_headers:
            signed_headers += ";"
        lower_key = key.lower()
        signed_headers += lower_key

        # Append header line: "lowercase_key:value\n"
        value = headers[key].strip()
        canonical_headers += lower_key + ":" + value + "\n"

    # Build canonical request
    if path is None:
        # If path is None, skip building canonical request (v11 remains empty)
        canonical_request = ""
    else:
        if path == "":
            path = "/"
        else:
            # Parse URI to get path component, apply urlEncode
            # We don't have java.net.URI in Python, but we can use urllib.parse
            parsed = urllib.parse.urlparse(path)
            path_encoded = url_encode(parsed.path, keep_slashes=True)
            if not path_encoded.startswith("/"):
                path_encoded = "/" + path_encoded
            if not path_encoded.endswith("/"):
                path_encoded += "/"
            path = path_encoded

        # Build canonical request: method + \n + path + \n\n + canonical_headers + signed_headers + \n + content_hash
        canonical_request = method + "\n" + path + "\n\n" + canonical_headers + signed_headers + "\n" + content_hash

    # SHA256 of canonical request
    canonical_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    # Build string to sign
    string_to_sign = "SDK-HMAC-SHA256\n" + x_sdk_date + "\n" + canonical_hash

    # HMAC-SHA256 using secret key
    secret = secret_key.encode('utf-8')
    hmac_obj = hmac.new(secret, string_to_sign.encode('utf-8'), hashlib.sha256)
    signature = hmac_obj.hexdigest()

    # Build final authorization header value
    auth_value = "SDK-HMAC-SHA256 Access=" + access_key + ", SignedHeaders=" + signed_headers + ", Signature=" + signature
    return auth_value

def update_vf(request: dict) -> dict:
    """Generates VF fields for the request."""
    headers = request.get('headers', {}).copy()
    method = request.get('method', 'GET')
    path = request.get('path', '/')
    body = request.get('body', None)
    query = request.get('query', {})

    # Ephemeral VFs: generate only if missing
    if 'x-sdk-date' not in headers:
        now = datetime.datetime.utcnow()
        headers['x-sdk-date'] = now.strftime('%Y%m%dT%H%M%SZ')

    if 'x-ca-timestamp' not in headers:
        timestamp_ms = int(time.time() * 1000)
        headers['x-ca-timestamp'] = str(timestamp_ms)

    x_sdk_date = headers['x-sdk-date']

    # Compute v587sign (always recompute)
    v587sign_value = compute_v587sign(
        headers=headers,
        method=method,
        path=path,
        body=body,
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        x_sdk_date=x_sdk_date
    )
    headers['v587sign'] = v587sign_value

    # Return updated request dict
    request['headers'] = headers
    return request