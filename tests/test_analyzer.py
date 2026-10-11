import unittest

from app.analyzer import analyze
from app.i18n import detect_language
from app.links import check_links, extract_urls

from .samples import SAFE, SCAMS, SUSPICIOUS_OK


def run(text: str):
    # Offline and no LLM: tests must be deterministic and need no network.
    return analyze(text, online=False, use_llm=False)


class TestVerdicts(unittest.TestCase):
    def test_scams_are_caught(self):
        missed = [(t, run(t).verdict, run(t).score) for t in SCAMS if run(t).verdict != "scam"]
        self.assertEqual(missed, [], f"{len(missed)} scams not flagged as scam")

    def test_safe_messages_are_not_flagged(self):
        wrong = [(t, run(t).verdict, run(t).score) for t in SAFE if run(t).verdict == "scam"]
        self.assertEqual(wrong, [], "genuine messages wrongly flagged as scam")

    def test_safe_messages_are_not_even_suspicious(self):
        wrong = [(t, run(t).verdict) for t in SAFE if run(t).verdict != "safe"]
        self.assertEqual(wrong, [])

    def test_borderline_is_not_called_safe(self):
        for t in SUSPICIOUS_OK:
            self.assertIn(run(t).verdict, {"suspicious", "scam"}, t)

    def test_empty_text(self):
        self.assertEqual(run("").verdict, "safe")
        self.assertEqual(run("   ").score, 0)

    def test_bank_name_alone_is_not_suspicious(self):
        self.assertEqual(run("SBI branch is closed on Sunday").verdict, "safe")


class TestReasons(unittest.TestCase):
    def test_reason_is_in_user_language(self):
        hi = analyze("Share your OTP now", "hi", online=False, use_llm=False)
        pa = analyze("Share your OTP now", "pa", online=False, use_llm=False)
        self.assertTrue(any("ऀ" <= ch <= "ॿ" for ch in hi.reason))
        self.assertTrue(any("਀" <= ch <= "੿" for ch in pa.reason))

    def test_otp_notice_gets_protective_reason(self):
        a = run("Your OTP is 482913. Do not share it with anyone. -HDFC Bank")
        self.assertEqual(a.verdict, "safe")
        self.assertIn("not to share", a.reason)


class TestLinks(unittest.TestCase):
    def test_extract(self):
        self.assertEqual(extract_urls("go to http://a.xyz/x, now"), ["http://a.xyz/x"])
        self.assertIn("bit.ly/abc", extract_urls("click bit.ly/abc today"))

    def test_lookalike_bank_domain(self):
        f = check_links("http://sbi-kyc-update.xyz/login", online=False)[0]
        self.assertGreaterEqual(f.score, 60)
        self.assertIn("brand_lookalike", f.reasons)

    def test_official_domain_is_clean(self):
        f = check_links("https://www.amazon.in/orders", online=False)[0]
        self.assertEqual(f.score, 0)
        f = check_links("https://onlinesbi.sbi", online=False)[0]
        self.assertEqual(f.score, 0)

    def test_ip_and_apk(self):
        self.assertIn("ip_address_host", check_links("http://192.168.4.5/login", online=False)[0].reasons)
        self.assertIn("apk_download", check_links("http://x-files.site/app.apk", online=False)[0].reasons)

    def test_shortener(self):
        self.assertIn("url_shortener", check_links("https://bit.ly/3abcd", online=False)[0].reasons)


class TestLanguage(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(detect_language("आपका खाता बंद हो जाएगा"), "hi")
        self.assertEqual(detect_language("ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ"), "pa")
        self.assertEqual(detect_language("Your account is blocked"), "en")
        self.assertEqual(detect_language("aapka khata band ho jayega turant batao"), "hi")


if __name__ == "__main__":
    unittest.main()
