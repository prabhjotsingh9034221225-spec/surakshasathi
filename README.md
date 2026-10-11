# SurakshaSathi

A WhatsApp-based, voice-enabled AI guardian that helps elderly and first-time internet users spot and report scams in Hindi, Punjabi and English.

Forward a suspicious message, link, screenshot or voice note. The bot answers **Safe / Suspicious / Scam** with a one-line reason, as text and voice. On a serious scam it alerts a family guardian, and the report appears on a district heatmap.

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # everything is optional
uvicorn app.main:app --reload
```

Open http://localhost:8000. With no API keys it runs in offline demo mode: the rule engine decides, and WhatsApp replies are printed to the console and shown in the dashboard's simulator.

```bash
python scripts/seed_demo.py              # fill the heatmap with sample reports
python -m unittest discover -s tests -t . # offline tests, no network needed
```

## Demo flow for judges

1. In the dashboard simulator, send: `आपका SBI खाता आज बंद हो जाएगा। तुरंत KYC अपडेट करें: http://sbi-kyc-update.xyz`
2. The bot replies in Hindi with the verdict, the reason and what to do, plus a voice reply when gTTS is installed.
3. The guardian's phone gets an alert (shown in the simulator).
4. The district appears on the heatmap.

## WhatsApp commands

`HINDI` / `PUNJABI` / `ENGLISH` · `FAMILY <number>` · `DISTRICT <name>` · `REPORT` (cybercrime.gov.in / 1930 complaint draft) · `TIP` (scam of the day) · `STOP` · `HELP`

## How it decides

1. **Rules** (`app/rules.py`): weighted patterns for KYC, OTP/PIN, UPI collect, lottery, advance fee, digital arrest, remote-access apps, job and courier scams, in English, Hindi, Hinglish and Punjabi. Genuine "do not share your OTP" notices are recognised as protective.
2. **Links** (`app/links.py`): look-alike bank domains, shorteners, IP hosts, risky endings, APK downloads, plus Google Safe Browsing if a key is set.
3. **LLM** (`app/llm.py`, optional): a Claude second opinion for borderline messages, and screenshot text reading.
4. Score is mapped to a verdict by `SCAM_THRESHOLD` (default 55) and `SUSPICIOUS_THRESHOLD` (default 25).

## Configuration

All keys are in `.env.example`. Main ones: `ANTHROPIC_API_KEY`, `WHATSAPP_PROVIDER` (`console` | `meta` | `twilio`) with that provider's credentials, `GOOGLE_SAFE_BROWSING_KEY`, `OPENAI_API_KEY` (voice-note transcription), `PUBLIC_BASE_URL` (so WhatsApp can fetch voice replies), `ADMIN_TOKEN`.

Set `DEMO_MODE=0` and a real `ADMIN_TOKEN` before exposing the server publicly.

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze` | `{text, lang?}` returns the verdict, reason, signals and link findings |
| `GET /api/stats`, `/api/heatmap`, `/api/reports/recent` | Dashboard data |
| `POST /api/demo/simulate`, `/api/demo/seed` | Demo only (`DEMO_MODE=1`) |
| `GET/POST /webhook/meta`, `POST /webhook/twilio` | WhatsApp providers |
| `POST /admin/broadcast-lesson` | Send the daily lesson (header `X-Admin-Token`); call from cron |

## Known limits

- In production, WhatsApp only allows free-form business messages within 24 hours of a user's last message, so alerts to a guardian who hasn't messaged the bot need an approved message template.
- The district list in `app/geo.py` is a starter set; extend it or swap in a full district GeoJSON.
- Speech-to-text uses Whisper; accuracy for Punjabi is weaker than for Hindi. Bhashini is the natural upgrade.
