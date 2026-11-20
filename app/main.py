"""FastAPI app: WhatsApp webhooks, analysis API, dashboard API, and the static dashboard."""
from __future__ import annotations

import csv
import io
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import alerts, benchmark, channel, calls, demo, explain, geo, indicators, intel, llm, paycheck, speech, stall, storage, whatsapp
from .analyzer import analyze
from .bot import Bot, broadcast_daily_lesson
from .config import ROOT, settings
from .i18n import detect_language


@asynccontextmanager
async def lifespan(_: FastAPI):
    storage.init()
    if settings.demo_mode:  # free-tier disks are ephemeral: never show an empty dashboard on stage
        with storage.connect() as c:
            empty = c.execute("SELECT 1 FROM reports LIMIT 1").fetchone() is None
        if empty:
            demo.seed_reports()
    yield


app = FastAPI(title="SurakshaSathi", version="1.1.0", lifespan=lifespan)
log = logging.getLogger("surakshasathi")
STARTED = time.time()
_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "microphone=(self), camera=(), geolocation=(self)",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


@app.middleware("http")
async def harden_and_trace(request: Request, call_next):
    """Security headers on every response, plus a request id and timing line for the logs (no bodies, no phone numbers)."""
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    t0 = time.perf_counter()
    response = await call_next(request)
    for k, v in _SEC_HEADERS.items():
        response.headers.setdefault(k, v)
    response.headers["X-Request-ID"] = rid
    if request.url.path.startswith("/api/"):
        log.info("%s %s %s %.0fms rid=%s", request.method, request.url.path, response.status_code, (time.perf_counter() - t0) * 1000, rid)
    return response
app.mount("/audio", StaticFiles(directory=str(settings.audio_dir)), name="audio")
STATIC = ROOT / "app" / "static"
app.mount("/samples", StaticFiles(directory=str(STATIC / "samples")), name="samples")
app.mount("/assets", StaticFiles(directory=str(STATIC / "assets")), name="assets")


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
    return FileResponse(STATIC / "dashboard.html", headers={"Cache-Control": "no-cache"})


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "whatsapp_provider": type(whatsapp.get_sender()).__name__,
        "llm_enabled": bool(settings.anthropic_api_key),
        "link_checker": "google-safe-browsing" if settings.safe_browsing_key else "heuristics-only",
        "demo_mode": settings.demo_mode,
        "whatsapp_number": settings.whatsapp_public_number,
        "channel_url": settings.whatsapp_channel_url,
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
    fast: bool = False  # rules only, no AI call: used by the live call shield, which checks every few seconds


@app.post("/api/analyze")
def api_analyze(body: AnalyzeIn, request: Request) -> dict:
    rate_limit(request)
    lang = body.lang or detect_language(body.text)
    a = analyze(body.text, lang, use_llm=not body.fast)
    return {**a.to_dict(), "explanation": explain.build(a)}


@app.get("/api/status")
def api_status() -> dict:
    """Public health summary for monitors and the footer link."""
    try:
        with storage.connect() as c:
            c.execute("SELECT 1").fetchone()
        db = "ok"
    except Exception:
        db = "error"
    return {
        "status": "ok" if db == "ok" else "degraded",
        "version": app.version,
        "uptime_seconds": int(time.time() - STARTED),
        "database": db,
        "ai_explanations": bool(settings.anthropic_api_key),
        "link_checker": "google-safe-browsing" if settings.safe_browsing_key else "heuristics-only",
        "demo_mode": settings.demo_mode,
    }


@app.get("/api/feedback/summary")
def api_feedback_summary() -> dict:
    f = storage.feedback_summary()
    f["helpful_pct"] = round(100 * f["helpful"] / f["total"]) if f["total"] else None
    return f


@app.get("/api/export/reports")
def api_export_reports(
    days: int = Query(30, ge=1, le=365),
    format: str = Query("csv", pattern="^(csv|json)$"),
    x_admin_token: str | None = Header(None),
) -> Response:
    """Anonymous report data for police, banks and CERT-In. Needs the admin token in the X-Admin-Token header."""
    require_admin(x_admin_token)
    rows = storage.export_reports(days)
    if format == "json":
        return JSONResponse({"days": days, "count": len(rows), "reports": rows})
    buf = io.StringIO()
    cols = ["id", "time_utc", "district", "verdict", "score", "category", "channel", "snippet"]
    w = csv.DictWriter(buf, fieldnames=cols)
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k) for k in cols})
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="surakshasathi-reports-{days}d.csv"'})


class FeedbackIn(BaseModel):
    helpful: bool
    verdict: str | None = Field(default=None, pattern="^(scam|suspicious|safe)$")


@app.post("/api/feedback")
def api_feedback(body: FeedbackIn, request: Request) -> dict:
    rate_limit(request, limit=20)
    storage.add_feedback(body.verdict, body.helpful)
    return {"ok": True}


class TtsIn(BaseModel):
    text: str = Field(min_length=1, max_length=900)
    lang: str = Field(default="en", pattern="^(en|hi|pa)$")


@app.post("/api/tts")
def api_tts(body: TtsIn, request: Request) -> dict:
    """Read a verdict aloud. Returns an mp3 URL, or 503 so the browser can fall back to its own voice."""
    rate_limit(request, limit=15)
    path = speech.synthesize(body.text, body.lang)
    if not path:
        raise HTTPException(503, "Voice is not available right now.")
    return {"url": f"/audio/{path.name}"}


class LinkIn(BaseModel):
    url: str = Field(min_length=3, max_length=2000)
    lang: str | None = Field(default=None, pattern="^(en|hi|pa)$")


@app.post("/api/check/link")
def api_check_link(body: LinkIn, request: Request) -> dict:
    """Check a single link without needing a whole message."""
    rate_limit(request)
    url = body.url.strip()
    a = analyze(f"Click {url}", body.lang or "en")
    if not a.links:
        raise HTTPException(422, "That does not look like a web link.")
    worst = max(a.links, key=lambda x: x.score)
    # A link on its own is judged by the link evidence only.
    verdict = "scam" if worst.score >= 60 else "suspicious" if worst.score >= 30 else "safe"
    a.verdict = verdict
    a.score = worst.score
    a.categories = ["link_link"] if verdict != "safe" else []
    ex = explain.build(a)
    ex["why"] = [] if verdict == "safe" else ex["why"]
    return {**a.to_dict(), "explanation": ex}


class IdentifierIn(BaseModel):
    value: str = Field(min_length=3, max_length=200)


@app.post("/api/check/identifier")
def api_check_identifier(body: IdentifierIn, request: Request) -> dict:
    """Has this phone number, UPI ID or website been reported before? Looks up a salted hash, never raw values."""
    rate_limit(request)
    found = indicators.extract(body.value.strip())
    if not found:
        raise HTTPException(422, "Please enter a 10-digit mobile number, a UPI ID like name@bank, or a website.")
    ind = found[0]
    stats = storage.lookup_indicator(ind["digest"])
    n = stats["reports"]
    level = "high" if n >= 3 else "reported" if n >= 1 else "unknown"
    return {"kind": ind["kind"], "hint": ind["hint"], "level": level, **stats}


class PayIn(BaseModel):
    payee: str | None = Field(default=None, max_length=200)
    amount: float | None = Field(default=None, ge=0, le=1e9)
    lang: str = Field(default="en", pattern="^(en|hi|pa)$")
    stranger: bool = False
    rushed: bool = False
    to_receive: bool = False
    secret: bool = False
    new_payee: bool = False
    name_mismatch: bool = False
    authority: bool = False


@app.post("/api/check/payment")
def api_check_payment(body: PayIn, request: Request) -> dict:
    """'Before I pay': reports about the payee plus a few plain questions give a stop, wait or go answer."""
    rate_limit(request)
    payee = None
    reports = 0
    if body.payee and body.payee.strip():
        found = indicators.extract(body.payee.strip())
        if found:
            stats = storage.lookup_indicator(found[0]["digest"])
            reports = stats["reports"]
            payee = {"kind": found[0]["kind"], "hint": found[0]["hint"], "reports": reports}
    flags = body.model_dump(include={"stranger", "rushed", "to_receive", "secret", "new_payee", "name_mismatch", "authority"})
    return {**paycheck.check(flags, body.amount, reports, body.lang), "payee": payee}


class StallIn(BaseModel):
    text: str = Field(min_length=3, max_length=3000)
    lang: str = Field(default="en", pattern="^(en|hi|pa)$")


@app.post("/api/stall-reply")
def api_stall_reply(body: StallIn, request: Request) -> dict:
    """A safe reply the person can send themselves to stall a scammer. We never contact the scammer."""
    rate_limit(request)
    a = analyze(body.text, body.lang, online=False)
    if a.verdict == "safe":
        raise HTTPException(422, "That message does not look like a scam, so there is no need to stall anyone.")
    return stall.suggest(a.categories, body.lang)


@app.get("/api/alerts/preview")
def api_alerts_preview(district: str = Query(..., min_length=2, max_length=60), lang: str = Query("en", pattern="^(en|hi|pa)$")) -> dict:
    """What a subscriber in this district would get right now, plus how many people have opted in."""
    d = geo.resolve_district(district)
    if not d:
        raise HTTPException(422, "We do not know that district yet.")
    return {"district": d, **alerts.preview(d, lang), "subscribers": storage.alert_subscriber_count()}


@app.get("/api/channel/digest")
def api_channel_digest(request: Request, lang: str = Query("en", pattern="^(en|hi|pa)$"), x_admin_token: str | None = Header(None)) -> dict:
    """Ready-to-post Channel report. Owner only: needs the admin token."""
    require_admin(x_admin_token)
    return {**channel.build(lang, url=str(request.base_url).rstrip("/")), "channel_url": settings.whatsapp_channel_url}


MAX_IMAGE_BYTES = 5 * 1024 * 1024


@app.post("/api/check/screenshot")
async def api_check_screenshot(request: Request, file: UploadFile = File(...), lang: str | None = Form(None)) -> dict:
    """Read the text out of a screenshot of a message and analyze it."""
    rate_limit(request)
    mime = (file.content_type or "").lower()
    if not mime.startswith("image/"):
        raise HTTPException(415, "Please upload an image (PNG or JPG).")
    data = await file.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(413, "Image is too large. Please upload one under 5 MB.")
    text = llm.read_image_text(data, mime)
    if not text or text.strip().upper() == "NONE":
        raise HTTPException(
            422,
            "We could not read any text from this image. Try a clearer screenshot, or paste the message instead.",
        )
    text = text.strip()[:4000]
    lg = lang if lang in ("en", "hi", "pa") else detect_language(text)
    a = analyze(text, lg)
    return {**a.to_dict(), "extracted_text": text, "explanation": explain.build(a)}


MAX_AUDIO_BYTES = 8 * 1024 * 1024


@app.post("/api/check/call")
async def api_check_call(
    request: Request,
    file: UploadFile | None = File(None),
    transcript: str | None = Form(None),
    lang: str | None = Form(None),
) -> dict:
    """Score a phone call for scam-script patterns, from a recording (speech-to-text) or a pasted transcript."""
    rate_limit(request)
    text = (transcript or "").strip()
    source = "transcript"
    if not text:
        if file is None:
            raise HTTPException(422, "Upload a call recording or paste what was said on the call.")
        mime = (file.content_type or "").lower()
        if not (mime.startswith("audio/") or mime.startswith("video/")):
            raise HTTPException(415, "Please upload an audio file (MP3, M4A or OGG).")
        data = await file.read(MAX_AUDIO_BYTES + 1)
        if len(data) > MAX_AUDIO_BYTES:
            raise HTTPException(413, "Recording is too large. Please upload one under 8 MB.")
        text = (await run_in_threadpool(speech.transcribe, data, mime, lang if lang in ("en", "hi", "pa") else None)) or ""
        source = "recording"
        if not text.strip():
            raise HTTPException(
                422,
                "We could not turn this recording into text on this server. Please paste what the caller said instead.",
            )
    text = text.strip()[:6000]
    lg = lang if lang in ("en", "hi", "pa") else detect_language(text)
    a, sig = calls.analyze_call(text, lg)
    ex = explain.build(a)
    return {**a.to_dict(), "explanation": ex, "transcript": text, "source": source, "call_signals": [s["id"] for s in sig]}


# ---------------------------------------------------------------- early-warning intelligence
@app.get("/api/intel/outbreaks")
def api_outbreaks() -> dict:
    return intel.outbreaks()


@app.get("/api/intel/trends")
def api_trends() -> dict:
    return intel.trends()


@app.get("/api/intel/rings")
def api_rings() -> dict:
    return intel.rings()


@app.get("/api/intel/awareness")
def api_awareness(district: str | None = Query(None, max_length=60)) -> dict:
    return intel.awareness(geo.resolve_district(district) if district else None)


@app.get("/api/intel/feed")
def api_feed(days: int = Query(30, ge=1, le=90)) -> dict:
    return intel.feed(days)


@app.get("/api/intel/benchmark")
def api_benchmark() -> dict:
    return benchmark.run()


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
@app.post("/admin/broadcast-alerts")
def admin_broadcast_alerts(x_admin_token: str | None = Header(None)) -> JSONResponse:
    """Send new district outbreak alerts to opted-in subscribers. Call hourly from a cron job."""
    require_admin(x_admin_token)
    return JSONResponse(alerts.broadcast(whatsapp.get_sender()))


@app.post("/admin/broadcast-digest")
def admin_broadcast_digest(request: Request, x_admin_token: str | None = Header(None)) -> JSONResponse:
    """Send the daily scam report to every opted-in subscriber. Call once a day from a cron job."""
    require_admin(x_admin_token)
    return JSONResponse(channel.broadcast_digest(whatsapp.get_sender(), url=str(request.base_url).rstrip("/")))


@app.post("/admin/broadcast-lesson")
def admin_broadcast(x_admin_token: str | None = Header(None)) -> JSONResponse:
    """Send today's 'Scam of the Day' to every user. Call from a daily cron job."""
    require_admin(x_admin_token)
    sent = broadcast_daily_lesson(whatsapp.get_sender())
    return JSONResponse({"sent": sent})
