"""Tiny stdlib HTTP helper so the core engine needs no third-party packages."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects but never leak the Authorization header to a different host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req.full_url).netloc:
            new.headers = {k: v for k, v in new.headers.items() if k.lower() != "authorization"}
            new.unredirected_hdrs = {k: v for k, v in new.unredirected_hdrs.items() if k.lower() != "authorization"}
        return new


_opener = urllib.request.build_opener(_SafeRedirect)


class HTTPError(Exception):
    def __init__(self, status: int, body: str = ""):
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status = status
        self.body = body


def request(
    method: str,
    url: str,
    *,
    params: dict | None = None,
    json_body: dict | None = None,
    form: dict | None = None,
    data: bytes | None = None,
    headers: dict | None = None,
    auth: tuple[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, bytes]:
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    hdrs = dict(headers or {})
    body = data
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif form is not None:
        body = urllib.parse.urlencode(form).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    if auth:
        import base64

        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        hdrs["Authorization"] = f"Basic {token}"
    req = urllib.request.Request(url, data=body, method=method.upper(), headers=hdrs)
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        raise HTTPError(e.code, e.read().decode("utf-8", "replace")) from e


def get_json(url: str, **kw) -> dict:
    _, body = request("GET", url, **kw)
    return json.loads(body)


def post_json(url: str, json_body: dict, **kw) -> dict:
    _, body = request("POST", url, json_body=json_body, **kw)
    return json.loads(body) if body else {}
