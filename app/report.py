"""Builds a ready-to-paste complaint for cybercrime.gov.in / the 1930 helpline.

The portal has no pre-fill API, so the realistic version of "one-tap reporting" is
a complete, structured text the user (or a family member) can paste into the form
or read out to the 1930 operator.
"""
from __future__ import annotations

import datetime as dt
import re

CATEGORY_LABELS = {
    "kyc": "Fake KYC / account-block phishing",
    "block_threat": "Fake account-block threat (phishing)",
    "otp": "OTP theft attempt",
    "pin": "UPI PIN / card details theft attempt",
    "upi_collect": "Fake UPI collect request / refund fraud",
    "lottery": "Lottery / prize fraud",
    "advance_fee": "Advance-fee fraud",
    "remote_access": "Remote-access app fraud (AnyDesk / TeamViewer)",
    "malware": "Malicious APK / malware link",
    "legal_threat": "Digital arrest / impersonation of police or agency",
    "electricity": "Fake electricity disconnection scam",
    "parcel": "Fake courier / customs scam",
    "job_scam": "Fake job / task scam",
    "investment": "Investment fraud",
    "extortion": "Blackmail / sextortion",
    "family_impersonation": "Impersonation of a relative asking for money",
    "wrong_transfer": "Fake 'money sent by mistake' refund scam",
    "credentials": "Credential phishing",
    "link_link": "Phishing link",
    "link_bait": "Phishing link",
    "urgency": "Social-engineering scam",
    "impersonation": "Impersonation of bank / government",
}

CATEGORY_PRIORITY = [
    "pin", "upi_collect", "remote_access", "malware", "otp", "legal_threat", "extortion", "kyc", "advance_fee",
    "lottery", "electricity", "parcel", "job_scam", "investment", "family_impersonation", "wrong_transfer", "credentials", "block_threat", "link_link",
    "link_bait", "urgency", "impersonation",
]

_PHONE = re.compile(r"(?<!\d)(?:\+?91[\-\s]?)?[6-9]\d{9}(?!\d)")
_UPI = re.compile(r"\b[\w.\-]{2,}@[a-z]{2,}\b", re.I)
_URL = re.compile(r"(?:https?://|www\.)[^\s]+", re.I)


def primary_category(categories: list[str]) -> str:
    for c in CATEGORY_PRIORITY:
        if c in categories:
            return c
    return categories[0] if categories else "urgency"


def build_complaint(text: str, categories: list[str], received_at: dt.datetime | None = None, district: str | None = None) -> str:
    received_at = received_at or dt.datetime.now()
    cat = primary_category(categories)
    phones = sorted(set(m.group(0) for m in _PHONE.finditer(text or "")))
    upis = sorted(set(m.group(0) for m in _UPI.finditer(text or "") if not m.group(0).lower().startswith(("http", "www"))))
    urls = sorted(set(m.group(0).rstrip(".,;)") for m in _URL.finditer(text or "")))

    lines = [
        "COMPLAINT SUMMARY (prepared by SurakshaSathi)",
        "",
        f"Type of fraud: {CATEGORY_LABELS.get(cat, 'Online financial fraud / phishing')}",
        f"Date and time received: {received_at.strftime('%d %b %Y, %I:%M %p')}",
        f"Location / district: {district or '[fill in]'}",
        "",
        "What happened:",
        "I received the message below. It tries to make me share confidential details or pay money. "
        "I want this reported so the sender can be traced.",
        "",
        "Suspect details found in the message:",
        f"- Phone number(s): {', '.join(phones) if phones else 'none found'}",
        f"- UPI ID(s): {', '.join(upis) if upis else 'none found'}",
        f"- Link(s): {', '.join(urls) if urls else 'none found'}",
        "",
        "Message text (copied exactly):",
        '"""',
        (text or "").strip()[:1500],
        '"""',
        "",
        "Fill in only if you lost money:",
        "- Amount lost: Rs. ________",
        "- Date and time of transaction: ________",
        "- Transaction ID / UTR number: ________",
        "- Your bank and last 4 digits of account: ________",
        "",
        "Keep screenshots of the message, the sender's number, and your bank SMS as evidence.",
    ]
    return "\n".join(lines)
