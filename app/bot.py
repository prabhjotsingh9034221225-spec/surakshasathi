"""Conversation logic, independent of the transport (WhatsApp provider, simulator, tests)."""
from __future__ import annotations

import re
import time

from . import i18n, lessons, llm, notifier, speech, storage
from .analyzer import Analysis, analyze
from .report import build_complaint, primary_category
from .whatsapp import Inbound, Sender, fetch_media, mask_phone, normalise_phone

GREETINGS = {
    "hi", "hello", "hey", "hii", "namaste", "namaskar", "start", "help", "menu", "?", "hlo",
    "नमस्ते", "नमस्कार", "हेलो", "हैलो", "मदद", "ਸਤ ਸ੍ਰੀ ਅਕਾਲ", "ਸਤਿ ਸ੍ਰੀ ਅਕਾਲ", "ਹੈਲੋ", "ਮਦਦ", "sat sri akal", "sat shri akal",
}

LANG_COMMANDS = {
    "hindi": "hi", "हिंदी": "hi", "हिन्दी": "hi", "hindī": "hi",
    "punjabi": "pa", "ਪੰਜਾਬੀ": "pa", "पंजाबी": "pa",
    "english": "en", "अंग्रेज़ी": "en", "अंग्रेजी": "en", "ਅੰਗਰੇਜ਼ੀ": "en",
}


def parse_command(text: str) -> tuple[str | None, str]:
    t = (text or "").strip()
    if not t:
        return None, ""
    low = t.lower()
    if low in LANG_COMMANDS:
        return "lang", LANG_COMMANDS[low]
    m = re.match(r"^(family|guardian|परिवार|ਪਰਿਵਾਰ)\s+(.+)$", t, re.I)
    if m:
        return "family", m.group(2)
    m = re.match(r"^(district|zila|ज़िला|जिला|ਜ਼ਿਲ੍ਹਾ|ਜ਼ਿਲ੍ਹਾ)\s+(.+)$", t, re.I)
    if m:
        return "district", m.group(2)
    if low in {"report", "complaint", "शिकायत", "ਸ਼ਿਕਾਇਤ"}:
        return "report", ""
    if low in {"tip", "lesson", "सीख", "ਸਿੱਖਿਆ"}:
        return "tip", ""
    if low in {"stop", "delete", "unsubscribe", "बंद", "ਬੰਦ"}:
        return "stop", ""
    if low in GREETINGS:
        return "help", ""
    return None, ""


class Bot:
    def __init__(self, sender: Sender, channel: str = "whatsapp") -> None:
        self.sender = sender
        self.channel = channel

    # ------------------------------------------------------------ public entry points
    def handle(self, msg: Inbound) -> None:
        if msg.kind == "text":
            self.handle_text(msg.phone, msg.text)
        elif msg.kind == "audio":
            try:
                data, mime = fetch_media(msg)
            except Exception:
                data, mime = b"", msg.mime
            self.handle_audio(msg.phone, data, mime)
        elif msg.kind == "image":
            try:
                data, mime = fetch_media(msg)
            except Exception:
                data, mime = b"", msg.mime
            self.handle_image(msg.phone, data, mime, caption=msg.text)
        else:
            user, _ = storage.ensure_user(msg.phone)
            self._text(msg.phone, i18n.tr("send_something", user["lang"]))

    def handle_text(self, phone: str, text: str, *, via_voice: bool = False, heard: str | None = None) -> None:
        user, created = storage.ensure_user(phone, i18n.detect_language(text))
        lang = user["lang"]
        cmd, arg = parse_command(text)

        if cmd == "help" or (created and not cmd and len(text.split()) <= 2 and not re.search(r"\d", text)):
            self._text(phone, i18n.WELCOME[lang])
            return
        if cmd == "lang":
            storage.update_user(phone, lang=arg)
            self._text(phone, i18n.tr("lang_set", arg) + "\n\n" + i18n.WELCOME[arg])
            return
        if cmd == "family":
            self._cmd_family(user, arg)
            return
        if cmd == "district":
            self._cmd_district(user, arg)
            return
        if cmd == "report":
            self._cmd_report(user)
            return
        if cmd == "tip":
            body = f"{i18n.tr('lesson_title', lang)}\n\n{lessons.lesson_text(lang)}"
            self._text(phone, body)
            self._voice(phone, lessons.lesson_text(lang), lang)
            return
        if cmd == "stop":
            self._cmd_stop(user)
            return

        self._check_message(user, text, via_voice=via_voice, heard=heard)

    def handle_audio(self, phone: str, audio: bytes, mime: str = "audio/ogg") -> None:
        user, _ = storage.ensure_user(phone)
        lang = user["lang"]
        transcript = speech.transcribe(audio, mime, lang) if audio else None
        if not transcript:
            self._text(phone, i18n.tr("voice_failed", lang))
            return
        self.handle_text(phone, transcript, via_voice=True, heard=transcript)

    def handle_image(self, phone: str, image: bytes, mime: str = "image/jpeg", caption: str = "") -> None:
        user, _ = storage.ensure_user(phone)
        lang = user["lang"]
        extracted = llm.read_image_text(image, mime) if image else None
        text = "\n".join(x for x in (caption, extracted) if x).strip()
        if not text:
            self._text(phone, i18n.tr("image_failed", lang))
            return
        self._check_message(user, text, via_voice=False, heard=None)

    # ------------------------------------------------------------ core check
    def _check_message(self, user: dict, text: str, *, via_voice: bool, heard: str | None) -> None:
        phone, lang = user["phone"], user["lang"]
        result = analyze(text, lang)
        category = primary_category(result.categories) if result.verdict != "safe" and result.categories else "none"

        storage.add_report(
            district=user.get("district"),
            verdict=result.verdict,
            score=result.score,
            category=category,
            snippet=text,
            channel=self.channel,
        )

        first_scam = user.get("last_scam_at") is None
        alerted = False
        if result.verdict in {"scam", "suspicious"}:
            storage.update_user(phone, last_scam_text=text[:2000], last_scam_category=",".join(result.categories), last_scam_at=time.time())
        if result.verdict == "scam":
            alerted = notifier.alert_guardian(self.sender, user, result.categories)

        reply = self._compose(result, user, heard=heard, alerted=alerted, first_scam=first_scam)
        self._text(phone, reply)
        # Voice reply: always for voice-note senders, and for any scam/suspicious verdict.
        if via_voice or result.verdict != "safe":
            self._voice(phone, self._spoken(result), lang)

    def _compose(self, result: Analysis, user: dict, *, heard: str | None, alerted: bool, first_scam: bool) -> str:
        lang = user["lang"]
        parts: list[str] = []
        if heard:
            parts.append(i18n.tr("heard", lang, text=heard[:200]))
        parts.append(i18n.VERDICT_HEAD[result.verdict][lang])
        parts.append(result.reason)

        for link in result.links:
            if link.score >= 60 or link.safe_browsing_flagged:
                parts.append(i18n.tr("link_note", lang, host=link.host, state=i18n.tr("link_state_bad", lang)))
                break
            if link.score >= 30:
                parts.append(i18n.tr("link_note", lang, host=link.host, state=i18n.tr("link_state_warn", lang)))
                break

        advice = i18n.ADVICE[result.verdict][lang]
        if advice:
            parts.append(advice)
        if alerted:
            parts.append(i18n.tr("family_alerted", lang))
        elif result.verdict == "scam" and not user.get("guardian_phone") and first_scam:
            parts.append(i18n.tr("family_hint", lang))
        if result.verdict != "safe" and not user.get("district") and first_scam:
            parts.append(i18n.tr("district_ask", lang))
        return "\n\n".join(parts)

    def _spoken(self, result: Analysis) -> str:
        lang = result.lang
        head = i18n.VERDICT_HEAD[result.verdict][lang]
        return f"{head} {result.reason}"

    # ------------------------------------------------------------ commands
    def _cmd_family(self, user: dict, arg: str) -> None:
        phone, lang = user["phone"], user["lang"]
        guardian = normalise_phone(arg)
        if not guardian or guardian == phone:
            self._text(phone, i18n.tr("family_bad", lang))
            return
        storage.update_user(phone, guardian_phone=guardian)
        notifier.notify_guardian_added(self.sender, guardian, phone)
        self._text(phone, i18n.tr("family_added", lang, number=mask_phone(guardian)))

    def _cmd_district(self, user: dict, arg: str) -> None:
        from .geo import resolve_district

        phone, lang = user["phone"], user["lang"]
        district = resolve_district(arg)
        if not district:
            self._text(phone, i18n.tr("district_unknown", lang))
            return
        storage.update_user(phone, district=district)
        self._text(phone, i18n.tr("district_set", lang, district=district))

    def _cmd_report(self, user: dict) -> None:
        phone, lang = user["phone"], user["lang"]
        text = user.get("last_scam_text")
        if not text:
            self._text(phone, i18n.tr("no_report", lang))
            return
        cats = [c for c in (user.get("last_scam_category") or "").split(",") if c]
        complaint = build_complaint(text, cats, district=user.get("district"))
        self._text(phone, i18n.tr("report_intro", lang))
        self._text(phone, complaint)

    def _cmd_stop(self, user: dict) -> None:
        phone, lang = user["phone"], user["lang"]
        cleared = storage.clear_guardian(phone)
        storage.delete_user(phone)
        msg = {
            "en": "✅ Done. Your data is deleted" + (" and you are no longer a family guardian." if cleared else "."),
            "hi": "✅ हो गया। आपका डेटा मिटा दिया गया" + (" और आप अब परिवार रक्षक नहीं हैं।" if cleared else "।"),
            "pa": "✅ ਹੋ ਗਿਆ। ਤੁਹਾਡਾ ਡੇਟਾ ਮਿਟਾ ਦਿੱਤਾ ਗਿਆ" + (" ਅਤੇ ਤੁਸੀਂ ਹੁਣ ਪਰਿਵਾਰਕ ਰੱਖਿਅਕ ਨਹੀਂ ਹੋ।" if cleared else "।"),
        }
        self._text(phone, msg.get(lang, msg["en"]))

    # ------------------------------------------------------------ sending helpers
    def _text(self, to: str, body: str) -> None:
        try:
            self.sender.send_text(to, body)
        except Exception as exc:  # never let a send failure crash the webhook
            print(f"[send_text failed to {mask_phone(to)}]: {exc}")

    def _voice(self, to: str, text: str, lang: str) -> None:
        path = speech.synthesize(text, lang)
        if not path:
            return
        try:
            self.sender.send_audio(to, path)
        except Exception as exc:
            print(f"[send_audio failed to {mask_phone(to)}]: {exc}")


def broadcast_daily_lesson(sender: Sender) -> int:
    """Send today's 'Scam of the Day' (text + voice) to every user. Run from a daily cron."""
    bot = Bot(sender)
    count = 0
    for user in storage.all_users():
        lang = user["lang"]
        bot._text(user["phone"], f"{i18n.tr('lesson_title', lang)}\n\n{lessons.lesson_text(lang)}")
        bot._voice(user["phone"], lessons.lesson_text(lang), lang)
        count += 1
    return count
