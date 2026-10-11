"""Central settings, read from environment variables (and an optional .env file).

Every key in .env.example maps to a field here. Nothing is required: with no keys
the app runs in offline demo mode (rule engine only, replies printed to the console).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Tiny .env reader (KEY=VALUE lines). Real environment variables win."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


_load_dotenv(ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _flag(name: str, default: bool) -> bool:
    return _env(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _path(name: str, default: str) -> Path:
    p = Path(_env(name, default))
    return p if p.is_absolute() else ROOT / p


@dataclass
class Settings:
    # --- LLM (optional) ---
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY"))
    anthropic_model: str = field(default_factory=lambda: _env("ANTHROPIC_MODEL", "claude-sonnet-5-5"))

    # --- WhatsApp: console | meta | twilio ---
    whatsapp_provider: str = field(default_factory=lambda: _env("WHATSAPP_PROVIDER", "console").lower())
    meta_verify_token: str = field(default_factory=lambda: _env("META_VERIFY_TOKEN", "surakshasathi-verify"))
    meta_access_token: str = field(default_factory=lambda: _env("META_ACCESS_TOKEN"))
    meta_app_secret: str = field(default_factory=lambda: _env("META_APP_SECRET"))
    meta_phone_number_id: str = field(default_factory=lambda: _env("META_PHONE_NUMBER_ID"))
    twilio_account_sid: str = field(default_factory=lambda: _env("TWILIO_ACCOUNT_SID"))
    twilio_auth_token: str = field(default_factory=lambda: _env("TWILIO_AUTH_TOKEN"))
    twilio_whatsapp_from: str = field(default_factory=lambda: _env("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886"))

    # --- Link safety / speech ---
    safe_browsing_key: str = field(default_factory=lambda: _env("GOOGLE_SAFE_BROWSING_KEY"))
    openai_api_key: str = field(default_factory=lambda: _env("OPENAI_API_KEY"))

    # --- Admin / demo ---
    admin_token: str = field(default_factory=lambda: _env("ADMIN_TOKEN", "change-me"))
    demo_mode: bool = field(default_factory=lambda: _flag("DEMO_MODE", True))
    public_base_url: str = field(default_factory=lambda: _env("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/"))

    # --- Storage ---
    database_path: Path = field(default_factory=lambda: _path("DATABASE_PATH", "data/surakshasathi.db"))
    audio_dir: Path = field(default_factory=lambda: _path("AUDIO_DIR", "data/audio"))

    # --- Verdict bands: score >= scam_threshold -> scam; >= suspicious_threshold -> suspicious ---
    scam_threshold: int = field(default_factory=lambda: _int("SCAM_THRESHOLD", 55))
    suspicious_threshold: int = field(default_factory=lambda: _int("SUSPICIOUS_THRESHOLD", 25))

    def __post_init__(self) -> None:
        self.audio_dir.mkdir(parents=True, exist_ok=True)  # main.py mounts it at import time


settings = Settings()
