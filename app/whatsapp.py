"""WhatsApp transport: Meta Cloud API, Twilio, or a console/outbox stub for demos and tests."""
from __future__ import annotations

import hashlib
import hmac
import base64
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import httpclient
from .config import settings
from .speech import audio_url

GRAPH = "https://graph.facebook.com/v20.0"


def normalise_phone(raw: str) -> str | None:
    """Return digits with country code (default India), e.g. '919876543210', or None if invalid."""
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 10 and digits[0] in "6789":
        return "91" + digits
    if len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
        return "91" + digits[1:]
    if 11 <= len(digits) <= 15:
        return digits
    return None


def mask_phone(phone: str) -> str:
    return f"+{phone[:2]}******{phone[-4:]}" if len(phone) > 6 else "******"


@dataclass
class Inbound:
    phone: str
    message_id: str
    kind: str  # text | audio | image | other
    text: str = ""
    media: dict = field(default_factory=dict)  # provider-specific reference
    mime: str = ""


# ---------------------------------------------------------------- senders
class Sender:
    def send_text(self, to: str, body: str) -> None: ...
    def send_audio(self, to: str, path: Path) -> None: ...


class ConsoleSender(Sender):
    """Keeps an in-memory outbox (used by tests and the dashboard simulator) and prints."""

    def __init__(self) -> None:
        self.outbox: list[dict] = []

    def send_text(self, to: str, body: str) -> None:
        self.outbox.append({"to": to, "type": "text", "body": body})
        print(f"\n[WhatsApp -> +{to}]\n{body}\n")

    def send_audio(self, to: str, path: Path) -> None:
        self.outbox.append({"to": to, "type": "audio", "url": audio_url(path)})
        print(f"[WhatsApp -> +{to}] 🔊 voice reply: {audio_url(path)}")

    def drain(self) -> list[dict]:
        items, self.outbox = self.outbox, []
        return items


class MetaSender(Sender):
    def _post(self, payload: dict) -> None:
        httpclient.post_json(
            f"{GRAPH}/{settings.meta_phone_number_id}/messages",
            {"messaging_product": "whatsapp", **payload},
            headers={"Authorization": f"Bearer {settings.meta_access_token}"},
            timeout=10.0,
        )

    def send_text(self, to: str, body: str) -> None:
        self._post({"to": to, "type": "text", "text": {"body": body[:4000], "preview_url": False}})

    def send_audio(self, to: str, path: Path) -> None:
        self._post({"to": to, "type": "audio", "audio": {"link": audio_url(path)}})


class TwilioSender(Sender):
    def _post(self, to: str, **fields: str) -> None:
        httpclient.request(
            "POST",
            f"https://api.twilio.com/2010-04-01/Accounts/{settings.twilio_account_sid}/Messages.json",
            form={"From": settings.twilio_whatsapp_from, "To": f"whatsapp:+{to}", **fields},
            auth=(settings.twilio_account_sid, settings.twilio_auth_token),
            timeout=10.0,
        )

    def send_text(self, to: str, body: str) -> None:
        self._post(to, Body=body[:1500])

    def send_audio(self, to: str, path: Path) -> None:
        self._post(to, MediaUrl=audio_url(path))


_sender: Sender | None = None


def get_sender() -> Sender:
    global _sender
    if _sender is None:
        provider = settings.whatsapp_provider
        if provider == "meta" and settings.meta_access_token and settings.meta_phone_number_id:
            _sender = MetaSender()
        elif provider == "twilio" and settings.twilio_account_sid and settings.twilio_auth_token:
            _sender = TwilioSender()
        else:
            _sender = ConsoleSender()
    return _sender


def set_sender(sender: Sender | None) -> None:
    global _sender
    _sender = sender


# ---------------------------------------------------------------- inbound parsing
def parse_meta(payload: dict) -> list[Inbound]:
    out: list[Inbound] = []
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            for msg in value.get("messages", []) or []:
                phone = normalise_phone(msg.get("from", ""))
                if not phone:
                    continue
                mtype = msg.get("type")
                mid = msg.get("id", "")
                if mtype == "text":
                    out.append(Inbound(phone, mid, "text", text=msg["text"].get("body", "")))
                elif mtype == "audio":
                    a = msg["audio"]
                    out.append(Inbound(phone, mid, "audio", media={"id": a.get("id")}, mime=a.get("mime_type", "audio/ogg")))
                elif mtype == "image":
                    i = msg["image"]
                    out.append(Inbound(phone, mid, "image", text=i.get("caption", ""), media={"id": i.get("id")}, mime=i.get("mime_type", "image/jpeg")))
                elif mtype == "button":
                    out.append(Inbound(phone, mid, "text", text=msg["button"].get("text", "")))
                elif mtype == "interactive":
                    inter = msg["interactive"]
                    reply = inter.get("button_reply") or inter.get("list_reply") or {}
                    out.append(Inbound(phone, mid, "text", text=reply.get("title", "")))
                else:
                    out.append(Inbound(phone, mid, "other"))
    return out


def parse_twilio(form: dict) -> Inbound | None:
    phone = normalise_phone((form.get("From") or "").replace("whatsapp:", ""))
    if not phone:
        return None
    mid = form.get("MessageSid") or form.get("SmsMessageSid") or ""
    body = form.get("Body", "") or ""
    num_media = int(form.get("NumMedia", "0") or 0)
    if num_media > 0:
        mime = form.get("MediaContentType0", "")
        url = form.get("MediaUrl0", "")
        if mime.startswith("audio/"):
            return Inbound(phone, mid, "audio", media={"url": url}, mime=mime)
        if mime.startswith("image/"):
            return Inbound(phone, mid, "image", text=body, media={"url": url}, mime=mime)
        return Inbound(phone, mid, "other")
    return Inbound(phone, mid, "text", text=body)


def fetch_media(inbound: Inbound) -> tuple[bytes, str]:
    """Download the audio/image behind an inbound message."""
    if "id" in inbound.media:  # Meta
        headers = {"Authorization": f"Bearer {settings.meta_access_token}"}
        info = httpclient.get_json(f"{GRAPH}/{inbound.media['id']}", headers=headers, timeout=10.0)
        _, data = httpclient.request("GET", info["url"], headers=headers, timeout=20.0)
        return data, info.get("mime_type", inbound.mime)
    # Twilio media URLs need basic auth
    _, data = httpclient.request(
        "GET", inbound.media["url"], auth=(settings.twilio_account_sid, settings.twilio_auth_token), timeout=20.0
    )
    return data, inbound.mime


# ---------------------------------------------------------------- webhook signatures
def verify_meta_signature(raw_body: bytes, header: str | None) -> bool:
    """With META_APP_SECRET set, require a valid X-Hub-Signature-256; otherwise skip (local dev)."""
    if not settings.meta_app_secret:
        return True
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(settings.meta_app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.split("=", 1)[1])


def verify_twilio_signature(url: str, params: dict, header: str | None) -> bool:
    if not settings.twilio_auth_token or settings.whatsapp_provider != "twilio":
        return True
    if not header:
        return False
    data = url + "".join(f"{k}{params[k]}" for k in sorted(params))
    digest = hmac.new(settings.twilio_auth_token.encode(), data.encode(), hashlib.sha1).digest()
    return hmac.compare_digest(base64.b64encode(digest).decode(), header)
