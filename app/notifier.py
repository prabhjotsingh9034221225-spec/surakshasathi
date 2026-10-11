"""Family-guardian alerts. The guardian is told THAT a scam arrived and what kind, never the message itself."""
from __future__ import annotations

import time

from . import storage
from .report import CATEGORY_LABELS, primary_category
from .whatsapp import Sender, mask_phone

ALERT_COOLDOWN_SECONDS = 10 * 60

_ALERT = {
    "en": "⚠️ SurakshaSathi alert: {who} just received a likely SCAM ({label}). They may need help. Please call them now and remind them: never share OTP or PIN. If money was lost, call 1930 immediately.",
    "hi": "⚠️ सुरक्षा साथी अलर्ट: {who} को अभी ठगी का संदिग्ध मैसेज मिला है ({label})। उन्हें मदद की ज़रूरत हो सकती है। कृपया अभी फोन करें और याद दिलाएं: OTP या PIN किसी को न बताएं। पैसे कटे हों तो तुरंत 1930 पर कॉल करें।",
}

_ADDED = {
    "en": "🙏 SurakshaSathi: {who} added you as their family guardian. You will be alerted if they get a serious scam message. Reply STOP to opt out.",
    "hi": "🙏 सुरक्षा साथी: {who} ने आपको अपना परिवार रक्षक बनाया है। उन्हें गंभीर ठगी का मैसेज आने पर आपको अलर्ट मिलेगा। बंद करने के लिए STOP भेजें।",
}


def notify_guardian_added(sender: Sender, guardian: str, user_phone: str) -> None:
    who = mask_phone(user_phone)
    try:
        sender.send_text(guardian, f"{_ADDED['en'].format(who=who)}\n\n{_ADDED['hi'].format(who=who)}")
    except Exception:
        pass


def alert_guardian(sender: Sender, user: dict, categories: list[str]) -> bool:
    """Send a high-risk alert to the user's guardian. Returns True if an alert went out."""
    guardian = user.get("guardian_phone")
    if not guardian:
        return False
    now = time.time()
    last = user.get("last_alert_at")
    if last and now - last < ALERT_COOLDOWN_SECONDS:
        return False
    label = CATEGORY_LABELS.get(primary_category(categories), "online fraud")
    who = mask_phone(user["phone"])
    try:
        sender.send_text(guardian, f"{_ALERT['en'].format(who=who, label=label)}\n\n{_ALERT['hi'].format(who=who, label=label)}")
    except Exception:
        return False
    storage.update_user(user["phone"], last_alert_at=now)
    return True
