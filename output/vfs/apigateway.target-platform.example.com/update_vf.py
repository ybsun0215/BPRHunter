import hashlib
import hmac
import json
import datetime
import uuid
import urllib.parse

ACCESS_KEY = 'PLACEHOLDER_ACCESS'
SECRET_KEY = 'PLACEHOLDER_SECRET'


def _find_header_key(headers, name):
    if name in headers:
        return name
    target = name.lower()
    for key in headers:
        try:
            if str(key).lower() == target:
                return key
        except Exception:
            continue
    return None


def _header_value(headers, name):
    key = _find_header_key(headers, name)
    if key is None:
        return None
    value = headers[key]
    if value is None:
        return None
    return str(value)


def _body_bytes(body):
    if body is None:
        return b''
    if isinstance(body, str):
        return body.encode('utf-8')
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return json.dumps(body).encode('utf-8')


def _canonical_uri(path):
    if path is None or path == '':
        return '/'
    raw_path = urllib.parse.urlsplit(str(path)).path or '/'
    decoded_path = urllib.parse.unquote(raw_path)
    segments = decoded_path.split('/')
    encoded_segments = [urllib.parse.quote(seg, safe='-_.~') for seg in segments]
    result = '/'.join(encoded_segments)
    if not result.startswith('/'):
        result = '/' + result
    if not result.endswith('/'):
        result += '/'
    return result


def _compute_sign(method, path, headers, body, date_value):
    content_hash = _header_value(headers, 'x-demo-content-sha256')
    if content_hash is None:
        content_hash = hashlib.sha256(_body_bytes(body)).hexdigest()

    header_items = []
    for key, value in headers.items():
        header_name = str(key)
        if header_name.lower() == 'sign':
            continue
        value_str = '' if value is None else str(value)
        header_items.append((header_name.lower(), header_name, value_str.strip()))

    header_items.sort(key=lambda item: (item[0], item[1]))

    canonical_headers = ''.join(f'{lower}:{value}\n' for lower, _, value in header_items)
    signed_headers = ';'.join(lower for lower, _, _ in header_items)

    if path is None or path == '':
        canonical_request = ''
    else:
        canonical_uri = _canonical_uri(path)
        canonical_request = (
            f'{method}\n'
            f'{canonical_uri}\n'
            f'\n'
            f'{canonical_headers}'
            f'{signed_headers}\n'
            f'{content_hash}'
        )

    hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    string_to_sign = f'DEMO-HMAC-SHA256\n{date_value}\n{hashed_canonical_request}'

    signature = hmac.new(
        SECRET_KEY.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return (
        f'DEMO-HMAC-SHA256 Access={ACCESS_KEY}, '
        f'SignedHeaders={signed_headers}, '
        f'Signature={signature}'
    )


def update_vf(request):
    if request is None:
        request = {}

    updated = dict(request)
    headers = request.get('headers')
    headers = dict(headers) if isinstance(headers, dict) else {}

    method = request.get('method', 'GET')
    if method is None:
        method = 'GET'
    path = request.get('path', '/')
    body = request.get('body')

    now = datetime.datetime.now(datetime.timezone.utc)

    timestamp_key = _find_header_key(headers, 'x-demo-timestamp')
    if timestamp_key is None:
        timestamp_ms = int(now.timestamp() * 1000)
        headers['x-demo-timestamp'] = str(timestamp_ms)

    date_key = _find_header_key(headers, 'x-demo-date')
    if date_key is None:
        date_value = now.strftime('%Y%m%dT%H%M%SZ')
        headers['x-demo-date'] = date_value
    else:
        date_value = str(headers[date_key])

    signature = _compute_sign(method, path, headers, body, date_value)

    new_headers = {}
    for key, value in headers.items():
        try:
            skip = str(key).lower() == 'sign'
        except Exception:
            skip = False
        if not skip:
            new_headers[key] = value
    new_headers['sign'] = signature

    updated['headers'] = new_headers
    return updated