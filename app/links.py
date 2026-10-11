"""Link safety: offline heuristics plus optional Google Safe Browsing and RDAP domain age."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import httpclient
from .config import settings

URL_RE = re.compile(
    r"(?:(?:https?://|www\.)[^\s<>\"'()]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|co|net|org|xyz|top|club|online|site|link|click|info|shop|vip|live|icu|cc|ly|gl|me|app|apk|help|support|work|buzz|cfd|sbs)(?:/[^\s<>\"'()]*)?)",
    re.IGNORECASE,
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
    "ow.ly", "tiny.cc", "s.id", "rebrand.ly", "bit.do", "t.ly", "wa.me",
}
RISKY_TLDS = {
    "xyz", "top", "club", "online", "site", "link", "click", "icu", "cc", "buzz", "cfd", "sbs",
    "vip", "live", "shop", "work", "help", "support", "info", "apk",
}
# Official domains of brands scammers like to imitate.
BRAND_DOMAINS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "onlinesbi.com", "sbicard.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfcbank.net"},
    "icici": {"icicibank.com", "icicidirect.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com", "paytm.in"},
    "phonepe": {"phonepe.com"},
    "npci": {"npci.org.in"},
    "pnb": {"pnbindia.in", "netpnb.com"},
    "kotak": {"kotak.com"},
    "uidai": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "irctc": {"irctc.co.in"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
}


@dataclass
class LinkFinding:
    url: str
    host: str
    score: int
    reasons: list[str] = field(default_factory=list)
    safe_browsing_flagged: bool = False
    domain_age_days: int | None = None


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?)")
        if u and u not in urls:
            urls.append(u)
    return urls


def _host_of(url: str) -> str:
    candidate = url if re.match(r"^https?://", url, re.I) else "http://" + url
    parsed = urlparse(candidate)
    return (parsed.hostname or "").lower()


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "gov", "org", "ac", "nic", "bank"} and parts[-1] == "in":
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def heuristic_score(url: str) -> LinkFinding:
    host = _host_of(url)
    finding = LinkFinding(url=url, host=host, score=0)
    if not host:
        return finding
    reg = _registrable(host)
    parsed = urlparse(url if re.match(r"^https?://", url, re.I) else "http://" + url)

    def add(points: int, reason: str) -> None:
        finding.score += points
        finding.reasons.append(reason)

    try:
        ipaddress.ip_address(host)
        add(40, "ip_address_host")
    except ValueError:
        pass

    if reg in SHORTENERS or host in SHORTENERS:
        add(25, "url_shortener")
    if host.startswith("xn--") or ".xn--" in host:
        add(35, "punycode_lookalike")
    if "@" in (parsed.netloc or ""):
        add(35, "userinfo_trick")
    if reg.rsplit(".", 1)[-1] in RISKY_TLDS:
        add(25, "risky_tld")
    if url.lower().endswith(".apk") or ".apk" in parsed.path.lower():
        add(45, "apk_download")
    if host.count(".") >= 4:
        add(15, "many_subdomains")
    if host.count("-") >= 2:
        add(15, "many_hyphens")
    if parsed.scheme == "http":
        add(5, "no_https")

    # Brand lookalikes: mentions a bank/wallet name but is not on its official domain.
    squashed = re.sub(r"[^a-z0-9]", "", host)
    for brand, official in BRAND_DOMAINS.items():
        if brand in squashed and reg not in official:
            add(45, "brand_lookalike")
            break
    # Scam-flavoured keywords inside the hostname
    if re.search(r"(?:kyc|verify|update|secure|login|reward|claim|prize|refund|helpdesk|offer)", host) and not finding.reasons:
        add(15, "keyword_in_host")
    elif re.search(r"(?:kyc|verify|update|reward|claim|prize|refund)", host):
        add(15, "keyword_in_host")

    finding.score = min(100, finding.score)
    return finding


def safe_browsing_flagged(urls: list[str]) -> set[str]:
    """Return URLs flagged by Google Safe Browsing (empty when no key or on failure)."""
    if not settings.safe_browsing_key or not urls:
        return set()
    body = {
        "client": {"clientId": "surakshasathi", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u if u.lower().startswith("http") else "http://" + u} for u in urls],
        },
    }
    try:
        data = httpclient.post_json(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            body,
            params={"key": settings.safe_browsing_key},
            timeout=4.0,
        )
        matches = data.get("matches", [])
    except Exception:
        return set()
    flagged = {m["threat"]["url"] for m in matches}
    return {u for u in urls if (u if u.lower().startswith("http") else "http://" + u) in flagged}


def domain_age_days(host: str) -> int | None:
    """Domain age via RDAP (the modern WHOIS). Returns None when unknown."""
    reg = _registrable(host)
    if not reg or reg in SHORTENERS:
        return None
    try:
        data = httpclient.get_json(f"https://rdap.org/domain/{reg}", timeout=3.0)
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return max(0, (datetime.now(timezone.utc) - created).days)
    except Exception:
        return None
    return None


def check_links(text: str, *, online: bool = True) -> list[LinkFinding]:
    urls = extract_urls(text)
    findings = [heuristic_score(u) for u in urls]
    if not online or not findings:
        return findings

    flagged = safe_browsing_flagged(urls)
    for f in findings:
        if f.url in flagged:
            f.safe_browsing_flagged = True
            f.score = 100
            f.reasons.append("safe_browsing")
            continue
        # Domain age is a slow network call; only worth it for links already looking odd.
        if f.score >= 15:
            age = domain_age_days(f.host)
            f.domain_age_days = age
            if age is not None and age < 90:
                f.score = min(100, f.score + 30)
                f.reasons.append("new_domain")
    return findings
