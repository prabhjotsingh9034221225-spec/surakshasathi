"""FastAPI app: WhatsApp webhooks, analysis API, dashboard API, and the static dashboard."""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import demo, geo, storage, whatsapp
from .analyzer import analyze
from .bot import Bot, broadcast_daily_lesson
from .config import ROOT, settings
from .i18n import detect_language


@asynccontextmanager
async def lifespan(_: FastAPI):
    storage.init()
    yield


app = FastAPI(title="SurakshaSathi", version="1.0.0", lifespan=lifespan)
app.mount("/audio", StaticFiles(directory=str(settings.audio_dir)), name="audio")
STATIC = ROOT / "app" / "static"


# ---------------------------------------------------------------- tiny rate limiter
_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(request: Request, limit: int = 30, per: int = 60) -> None:
    ip = request.client.host if request.client else "unknown"
    q = _hits[ip]
    now = time.time()
    while q and now - q[0] > per:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many requests, slow down.")
    q.append(now)


def require_admin(token: str | None) -> None:
    if not settings.admin_token or settings.admin_token == "change-me" or token != settings.admin_token:
        raise HTTPException(403, "Admin token missing or invalid. Set ADMIN_TOKEN in .env and send it as X-Admin-Token.")


def require_demo() -> None:
    if not settings.demo_mode:
        raise HTTPException(404, "Demo endpoints are disabled (DEMO_MODE=0).")


# ---------------------------------------------------------------- pages
@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "dashboard.html")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "whatsapp_provider": type(whatsapp.get_sender()).__name__,
        "llm_enabled": bool(settings.anthropic_api_key),
        "link_checker": "google-safe-browsing" if settings.safe_browsing_key else "heuristics-only",
        "demo_mode": settings.demo_mode,
    }


# ---------------------------------------------------------------- WhatsApp webhooks
def _process(msg: whatsapp.Inbound) -> None:
    try:
        Bot(whatsapp.get_sender()).handle(msg)
    except Exception as exc:  # a bad message must never take the worker down
        print(f"[bot error for {whatsapp.mask_phone(msg.phone)}]: {exc!r}")


@app.get("/webhook/meta")
def meta_verify(
    mode: str | None = Query(None, alias="hub.mode"),
    token: str | None = Query(None, alias="hub.verify_token"),
    challenge: str | None = Query(None, alias="hub.challenge"),
) -> PlainTextResponse:
    if mode == "subscribe" and token == settings.meta_verify_token and challenge:
        return PlainTextResponse(challenge)
    raise HTTPException(403, "Verification failed")


@app.post("/webhook/meta")
async def meta_inbound(request: Request, background: BackgroundTasks, x_hub_signature_256: str | None = Header(None)) -> dict:
    raw = await request.body()
    if not whatsapp.verify_meta_signature(raw, x_hub_signature_256):
        raise HTTPException(403, "Bad signature")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")
    for msg in whatsapp.parse_meta(payload):
        if msg.message_id and not storage.first_time_seen(msg.message_id):
            continue  # provider retry
        background.add_task(_process, msg)
    return {"status": "received"}


@app.post("/webhook/twilio")
async def twilio_inbound(request: Request, background: BackgroundTasks, x_twilio_signature: str | None = Header(None)) -> Response:
    form = dict(await request.form())
    url = f"{settings.public_base_url}{request.url.path}"
    if not whatsapp.verify_twilio_signature(url, form, x_twilio_signature):
        raise HTTPException(403, "Bad signature")
    msg = whatsapp.parse_twilio(form)
    if msg and (not msg.message_id or storage.first_time_seen(msg.message_id)):
        background.add_task(_process, msg)
    return Response(content="<Response></Response>", media_type="application/xml")


# ---------------------------------------------------------------- analysis API
class AnalyzeIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    lang: str | None = Field(default=None, pattern="^(en|hi|pa)$")


@app.post("/api/analyze")
def api_analyze(body: AnalyzeIn, request: Request) -> dict:
    rate_limit(request)
    lang = body.lang or detect_language(body.text)
    return analyze(body.text, lang).to_dict()


# ---------------------------------------------------------------- dashboard API
@app.get("/api/stats")
def api_stats(days: int = Query(30, ge=1, le=365)) -> dict:
    data = storage.stats(days)
    data["sample_data"] = _has_sample_data()
    return data


def _has_sample_data() -> bool:
    with storage.connect() as c:
        return c.execute("SELECT 1 FROM reports WHERE channel='seed' LIMIT 1").fetchone() is not None


@app.get("/api/heatmap")
def api_heatmap(days: int = Query(30, ge=1, le=365)) -> list[dict]:
    out = []
    for row in storage.heatmap(days):
        pos = geo.coords(row["district"])
        if pos:
            out.append({**row, "lat": pos[0], "lng": pos[1], "state": geo.state_of(row["district"])})
    return out


@app.get("/api/reports/recent")
def api_recent(limit: int = Query(15, ge=1, le=50)) -> list[dict]:
    return storage.recent_reports(limit)


# ---------------------------------------------------------------- demo (DEMO_MODE=1 only)
class SimulateIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    phone: str = "919999900001"
    guardian: str | None = "919999900002"
    district: str | None = None
    lang: str | None = Field(default=None, pattern="^(en|hi|pa)$")


@app.post("/api/demo/simulate")
def demo_simulate(body: SimulateIn, request: Request) -> dict:
    """Run a message through the real bot, but capture replies instead of sending real WhatsApp messages."""
    require_demo()
    rate_limit(request, limit=20)
    phone = whatsapp.normalise_phone(body.phone)
    if not phone:
        raise HTTPException(422, "Invalid phone")
    sender = whatsapp.ConsoleSender()
    bot = Bot(sender, channel="simulator")
    user, _ = storage.ensure_user(phone, body.lang or detect_language(body.text))
    updates: dict = {}
    if body.lang:
        updates["lang"] = body.lang
    if body.district and geo.resolve_district(body.district):
        updates["district"] = geo.resolve_district(body.district)
    guardian = whatsapp.normalise_phone(body.guardian) if body.guardian else None
    if guardian and guardian != phone and not user.get("guardian_phone"):
        updates["guardian_phone"] = guardian
    if updates:
        storage.update_user(phone, **updates)
    bot.handle_text(phone, body.text)
    guardian_phone = (storage.get_user(phone) or {}).get("guardian_phone")
    return {
        "user_phone": phone,
        "guardian_phone": guardian_phone,
        "messages": [
            {**m, "recipient": "guardian" if m["to"] == guardian_phone else "user"} for m in sender.drain()
        ],
    }


@app.post("/api/demo/seed")
def demo_seed(request: Request, n: int = Query(150, ge=1, le=1000)) -> dict:
    require_demo()
    rate_limit(request, limit=5)
    return {"seeded": demo.seed_reports(n)}


# ---------------------------------------------------------------- admin
@app.post("/admin/broadcast-lesson")
def admin_broadcast(x_admin_token: str | None = Header(None)) -> JSONResponse:
    """Send today's 'Scam of the Day' to every user. Call from a daily cron job."""
    require_admin(x_admin_token)
    sent = broadcast_daily_lesson(whatsapp.get_sender())
    return JSONResponse({"sent": sent})
