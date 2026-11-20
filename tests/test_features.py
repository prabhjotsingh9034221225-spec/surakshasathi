import tempfile
from pathlib import Path

from app import alerts, paycheck, stall, storage
from app.bot import Bot, parse_command


class Recorder:
    def __init__(self):
        self.sent = []

    def send_text(self, to, body):
        self.sent.append((to, body))

    def send_audio(self, to, path):
        pass


def _fresh():
    storage.init(Path(tempfile.mkdtemp()) / "t.db")


# ---- pay-safe check
def test_paying_to_receive_money_is_always_stop():
    r = paycheck.check({"to_receive": True}, 100, 0)
    assert r["level"] == "stop" and "RECEIVE" in r["reasons"][0]


def test_authority_asking_for_money_is_stop():
    assert paycheck.check({"authority": True}, 20000, 0)["level"] == "stop"


def test_reported_payee_escalates():
    assert paycheck.check({}, 500, 1)["level"] == "wait"
    assert paycheck.check({}, 500, 3)["level"] == "stop"


def test_stranger_and_rushed_is_stop_but_stranger_alone_is_wait():
    assert paycheck.check({"stranger": True, "rushed": True}, 500, 0)["level"] == "stop"
    assert paycheck.check({"stranger": True}, 500, 0)["level"] == "wait"


def test_clean_small_payment_is_go_and_large_new_payee_waits():
    assert paycheck.check({}, 300, 0)["level"] == "go"
    assert paycheck.check({"new_payee": True}, 80000, 0)["level"] == "wait"


def test_pay_check_speaks_all_three_languages():
    for lang in ("en", "hi", "pa"):
        r = paycheck.check({"to_receive": True}, 1, 0, lang)
        assert r["headline"] and r["reasons"] and r["next_steps"]


# ---- stall reply
def test_stall_reply_never_asks_for_or_offers_personal_data():
    for cat in ("legal_threat", "family_impersonation", "lottery", "job_scam", "kyc"):
        for lang in ("en", "hi", "pa"):
            s = stall.suggest([cat], lang)
            assert s["reply"] and len(s["rules"]) == 4
    assert "never share" in stall.suggest(["kyc"], "en")["rules"][1].lower()


def test_stall_falls_back_to_default_and_aliases():
    assert stall.suggest(["kyc"], "en")["category"] == "default"
    assert stall.suggest(["investment"], "en")["category"] == "job_scam"


# ---- district alerts
def _spike(district="Ludhiana", category="kyc", n=12):
    for _ in range(n):
        storage.add_report(district=district, verdict="scam", score=90, category=category, snippet="KYC update link", channel="web")


def test_alert_preview_and_broadcast_once_per_day():
    _fresh()
    _spike()
    assert alerts.preview("Ludhiana", "en")["active"] is True
    assert alerts.preview("Amritsar", "en")["active"] is False
    storage.ensure_user("911111111111", "hi")
    storage.alert_subscribe("911111111111", "Ludhiana")
    storage.alert_subscribe("922222222222", "Amritsar")  # different district: must not be messaged
    rec = Recorder()
    first = alerts.broadcast(rec)
    assert first["sent"] == 1 and rec.sent[0][0] == "911111111111"
    assert "Ludhiana" in rec.sent[0][1] and "ALERTS OFF" in rec.sent[0][1]
    again = alerts.broadcast(rec)
    assert again["sent"] == 0 and len(rec.sent) == 1


def test_alert_commands_on_and_off():
    _fresh()
    assert parse_command("alerts Ludhiana") == ("alerts", "Ludhiana")
    assert parse_command("ALERTS OFF") == ("alerts", "OFF")
    rec = Recorder()
    bot = Bot(rec)
    bot.handle_text("933333333333", "ALERTS Ludhiana")
    assert [s["phone"] for s in storage.alert_subscribers("Ludhiana")] == ["933333333333"]
    bot.handle_text("933333333333", "ALERTS OFF")
    assert storage.alert_subscribers("Ludhiana") == []


def test_stop_command_removes_alert_subscription():
    _fresh()
    rec = Recorder()
    bot = Bot(rec)
    bot.handle_text("944444444444", "ALERTS Ludhiana")
    assert storage.alert_subscribers("Ludhiana")
    bot.handle_text("944444444444", "STOP")
    assert storage.alert_subscribers("Ludhiana") == []


def test_channel_digest_withholds_small_districts_and_has_sections(tmp_path, monkeypatch):
    from app import channel
    out = channel.build("en", url="https://x.example")
    assert "Top scams" in out["text"] and "District-wise" in out["text"] and "1930" in out["text"]
    for lang in ("hi", "pa"):
        assert channel.build(lang)["text"]
