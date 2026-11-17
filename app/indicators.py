"""Scammer identifiers (phone numbers, UPI IDs, domains) pulled out of a reported message.

Only a keyed hash is stored for matching across reports, plus a masked hint for display. The salt is
read from INDICATOR_SALT; set a long random value in production because phone numbers are a small space.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from urllib.parse import urlparse

_PHONE = re.compile(r"(?<!\d)(?:\+?91[\-\s]?)?([6-9]\d{4}[\-\s]?\d{5})(?!\d)")
_UPI = re.compile(r"\b([\w.\-]{2,})@([a-z]{2,})\b", re.I)
_URL = re.compile(r"(?:https?://|www\.)[^\s]+|\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:xyz|top|click|site|online|icu|shop|cc|buzz|live|info|link)\b[^\s]*", re.I)


def _salt() -> bytes:
    return os.environ.get("INDICATOR_SALT", "surakshasathi-demo-salt").encode()


def digest(kind: str, value: str) -> str:
    return hmac.new(_salt(), f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:16]


def extract(text: str) -> list[dict[str, str]]:
    """Return [{kind, digest, hint}] for each distinct identifier in `text`."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, norm: str, hint: str) -> None:
        if (kind, norm) in seen:
            return
        seen.add((kind, norm))
        out.append({"kind": kind, "digest": digest(kind, norm), "hint": hint})

    for m in _PHONE.finditer(text or ""):
        d = re.sub(r"\D", "", m.group(1))
        add("phone", d, f"{d[:2]}xxxxxx{d[-2:]}")
    for m in _UPI.finditer(text or ""):
        user, handle = m.group(1).lower(), m.group(2).lower()
        if "." in handle or handle in {"gmail", "yahoo", "outlook", "hotmail"}:
            continue
        add("upi", f"{user}@{handle}", f"{user[:2]}***@{handle}")
    for m in _URL.finditer(text or ""):
        raw = m.group(0).rstrip(".,;)")
        host = (urlparse(raw if "://" in raw else "http://" + raw).hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        if host and "." in host:
            add("domain", host, host)
    return out
