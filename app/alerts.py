"""District early-warning alerts: when a scam category spikes in a district, tell the people who opted in there."""
from __future__ import annotations

import time
from typing import Any

from . import intel, storage
from .whatsapp import Sender

_TEXT = {
    "en": "🚨 Scam alert for {district}\n{label} scams are rising: {count} reports in the last {hours} hours.\n\n{tip}\n\nIf you lost money call 1930 at once. Reply ALERTS OFF to stop these alerts.",
    "hi": "🚨 {district} के लिए ठगी की चेतावनी\n{label} की ठगी बढ़ रही है: पिछले {hours} घंटों में {count} रिपोर्ट।\n\n{tip}\n\nपैसे कट गए हों तो तुरंत 1930 पर कॉल करें। ये चेतावनियाँ बंद करने के लिए ALERTS OFF भेजें।",
    "pa": "🚨 {district} ਲਈ ਠੱਗੀ ਦੀ ਚੇਤਾਵਨੀ\n{label} ਦੀ ਠੱਗੀ ਵਧ ਰਹੀ ਹੈ: ਪਿਛਲੇ {hours} ਘੰਟਿਆਂ ਵਿੱਚ {count} ਰਿਪੋਰਟਾਂ।\n\n{tip}\n\nਪੈਸੇ ਕੱਟੇ ਗਏ ਹੋਣ ਤਾਂ ਤੁਰੰਤ 1930 ਤੇ ਕਾਲ ਕਰੋ। ਇਹ ਚੇਤਾਵਨੀਆਂ ਬੰਦ ਕਰਨ ਲਈ ALERTS OFF ਭੇਜੋ।",
}
_TIPS = {
    "kyc": {"en": "Banks never ask you to update KYC through a link or share an OTP.", "hi": "बैंक कभी लिंक से KYC अपडेट करने या OTP बताने को नहीं कहता।", "pa": "ਬੈਂਕ ਕਦੇ ਲਿੰਕ ਰਾਹੀਂ KYC ਅੱਪਡੇਟ ਕਰਨ ਜਾਂ OTP ਦੱਸਣ ਨੂੰ ਨਹੀਂ ਕਹਿੰਦਾ।"},
    "electricity": {"en": "Electricity boards do not cut a connection over a phone call. Check your bill on the official app.", "hi": "बिजली विभाग फोन कॉल पर कनेक्शन नहीं काटता। बिल आधिकारिक ऐप पर देखें।", "pa": "ਬਿਜਲੀ ਵਿਭਾਗ ਫ਼ੋਨ ਕਾਲ ਤੇ ਕੁਨੈਕਸ਼ਨ ਨਹੀਂ ਕੱਟਦਾ। ਬਿੱਲ ਅਧਿਕਾਰਤ ਐਪ ਤੇ ਵੇਖੋ।"},
    "lottery": {"en": "A real prize never asks you to pay a fee first.", "hi": "असली इनाम के लिए कभी पहले पैसे नहीं माँगे जाते।", "pa": "ਅਸਲੀ ਇਨਾਮ ਲਈ ਕਦੇ ਪਹਿਲਾਂ ਪੈਸੇ ਨਹੀਂ ਮੰਗੇ ਜਾਂਦੇ।"},
    "legal_threat": {"en": "Police and courts never arrest people over a phone or video call. Hang up.", "hi": "पुलिस या अदालत फोन या वीडियो कॉल पर गिरफ्तारी नहीं करती। कॉल काट दें।", "pa": "ਪੁਲਿਸ ਜਾਂ ਅਦਾਲਤ ਫ਼ੋਨ ਜਾਂ ਵੀਡੀਓ ਕਾਲ ਤੇ ਗ੍ਰਿਫ਼ਤਾਰੀ ਨਹੀਂ ਕਰਦੀ। ਕਾਲ ਕੱਟ ਦਿਓ।"},
}
_DEFAULT_TIP = {"en": "Do not click links, pay, or share any OTP or PIN. Check with your bank directly.", "hi": "लिंक न खोलें, पैसे न भेजें और OTP या PIN न बताएँ। बैंक से सीधे पूछें।", "pa": "ਲਿੰਕ ਨਾ ਖੋਲ੍ਹੋ, ਪੈਸੇ ਨਾ ਭੇਜੋ ਅਤੇ OTP ਜਾਂ PIN ਨਾ ਦੱਸੋ। ਬੈਂਕ ਤੋਂ ਸਿੱਧਾ ਪੁੱਛੋ।"}


def build_alert(alert: dict[str, Any], lang: str = "en") -> str:
    lang = lang if lang in _TEXT else "en"
    tip = _TIPS.get(alert["category"], _DEFAULT_TIP).get(lang) or _DEFAULT_TIP["en"]
    return _TEXT[lang].format(district=alert["district"], label=alert["label"], count=alert["count"], hours=alert.get("hours", 6), tip=tip)


def active_alerts(now: float | None = None, min_level: str = "high") -> list[dict[str, Any]]:
    order = {"watch": 0, "high": 1, "critical": 2}
    data = intel.outbreaks(now)
    return [{**a, "hours": data["window_hours"]} for a in data["alerts"] if order.get(a["level"], 0) >= order[min_level]]


def preview(district: str, lang: str = "en", now: float | None = None) -> dict[str, Any]:
    """What a subscriber in `district` would receive right now (or a calm status when nothing is spiking)."""
    for a in active_alerts(now, min_level="watch"):
        if a["district"] == district:
            return {"active": True, "level": a["level"], "text": build_alert(a, lang)}
    return {"active": False, "level": None, "text": None}


def broadcast(sender: Sender, now: float | None = None) -> dict[str, int]:
    """Send each new high/critical outbreak to subscribers of that district, at most once per day per outbreak."""
    day = time.strftime("%Y-%m-%d", time.gmtime(now or time.time()))
    sent = skipped = 0
    for a in active_alerts(now):
        if storage.alert_already_sent(day, a["district"], a["category"]):
            skipped += 1
            continue
        for sub in storage.alert_subscribers(a["district"]):
            try:
                sender.send_text(sub["phone"], build_alert(a, sub["lang"]))
                sent += 1
            except Exception as exc:  # one bad number must not stop the rest
                print(f"[alert send failed]: {exc}")
        storage.mark_alert_sent(day, a["district"], a["category"])
    return {"sent": sent, "outbreaks_already_sent": skipped}
