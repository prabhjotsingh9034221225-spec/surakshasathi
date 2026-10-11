"""Speech: text-to-speech (gTTS) and speech-to-text (faster-whisper locally, or OpenAI Whisper API).

Both directions degrade gracefully: if nothing is configured, the bot still works in text.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import uuid
from pathlib import Path

from . import httpclient
from .config import settings

GTTS_LANG = {"en": "en", "hi": "hi", "pa": "pa"}
WHISPER_LANG = {"en": "en", "hi": "hi", "pa": "pa"}


def _speakable(text: str) -> str:
    """Strip emoji, markdown and bullets so the voice does not read symbols aloud."""
    text = re.sub(r"[*_`~]", "", text)
    text = re.sub(r"[\U0001F000-\U0001FAFF☀-➿️‍]", "", text)
    text = text.replace("❌", "").replace("📞", "")
    text = re.sub(r"https?://\S+", "", text)
    text = re.sub(r"\n+", ". ", text)
    return re.sub(r"\s+", " ", text).strip()


def synthesize(text: str, lang: str) -> Path | None:
    """Create an mp3 for `text`. Returns the file path, or None if TTS is unavailable."""
    speakable = _speakable(text)[:900]
    if not speakable:
        return None
    key = hashlib.sha256(f"{lang}:{speakable}".encode()).hexdigest()[:24]
    path = settings.audio_dir / f"{key}.mp3"
    if path.exists():
        return path
    try:
        from gtts import gTTS

        gTTS(text=speakable, lang=GTTS_LANG.get(lang, "en")).save(str(path))
        return path
    except Exception:
        path.unlink(missing_ok=True)
        return None


def audio_url(path: Path) -> str:
    return f"{settings.public_base_url}/audio/{path.name}"


_whisper_model = None


def _local_whisper(audio: bytes, suffix: str, lang: str | None) -> str | None:
    global _whisper_model
    try:
        from faster_whisper import WhisperModel
    except Exception:
        return None
    try:
        if _whisper_model is None:
            _whisper_model = WhisperModel("small", compute_type="int8")
        with tempfile.NamedTemporaryFile(suffix=suffix) as f:
            f.write(audio)
            f.flush()
            segments, _ = _whisper_model.transcribe(f.name, language=WHISPER_LANG.get(lang or ""), vad_filter=True)
            return " ".join(s.text.strip() for s in segments).strip() or None
    except Exception:
        return None


def _openai_whisper(audio: bytes, suffix: str, lang: str | None) -> str | None:
    if not settings.openai_api_key:
        return None
    boundary = uuid.uuid4().hex
    parts: list[bytes] = []

    def field(name: str, value: str) -> None:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())

    field("model", "whisper-1")
    if lang in WHISPER_LANG:
        field("language", WHISPER_LANG[lang])
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="voice{suffix}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode() + audio + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    try:
        _, body = httpclient.request(
            "POST",
            "https://api.openai.com/v1/audio/transcriptions",
            data=b"".join(parts),
            headers={
                "Authorization": f"Bearer {settings.openai_api_key}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            timeout=30.0,
        )
        return (json.loads(body).get("text") or "").strip() or None
    except Exception:
        return None


def transcribe(audio: bytes, mime: str = "audio/ogg", lang: str | None = None) -> str | None:
    suffix = ".ogg" if "ogg" in mime else ".mp3" if "mpeg" in mime or "mp3" in mime else ".m4a" if "mp4" in mime or "m4a" in mime else ".ogg"
    return _local_whisper(audio, suffix, lang) or _openai_whisper(audio, suffix, lang)
