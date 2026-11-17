"""Demo helpers: realistic sample scam data so the heatmap is not empty on stage.

Seeded rows are tagged channel='seed' and the dashboard labels them as sample data.
"""
from __future__ import annotations

import random
import time

from . import storage
from .geo import DISTRICTS

# (category, snippet, weight)
SAMPLES = [
    ("kyc", "Your SBI account is blocked. Update KYC now [link]", 30),
    ("otp", "Share the OTP sent to your phone to avoid account closure", 18),
    ("upi_collect", "Approve the collect request to receive your refund", 16),
    ("lottery", "You won Rs 25 lakh in KBC lottery. Pay processing fee", 10),
    ("electricity", "Electricity will be disconnected tonight 9:30pm. Call now", 10),
    ("legal_threat", "CBI notice: you are under digital arrest, stay on the video call", 6),
    ("remote_access", "Install AnyDesk so we can process your refund", 5),
    ("job_scam", "Earn Rs 5000 daily from home, like and subscribe tasks", 5),
]

# Rough weighting: northern districts are the focus of the demo.
HOT = {"Ludhiana": 9, "Amritsar": 7, "Jalandhar": 7, "Ambala": 6, "Patiala": 6, "Mohali": 6, "Gurugram": 8,
       "Hisar": 5, "Karnal": 4, "Bathinda": 4, "Delhi": 9, "Chandigarh": 5, "Faridabad": 5, "Rohtak": 4,
       "Panipat": 3, "Sirsa": 3, "Moga": 3, "Sangrur": 3, "Yamunanagar": 2, "Kurukshetra": 2}


def seed_reports(n: int = 150, seed: int = 7) -> int:
    rng = random.Random(seed)
    districts = [d for d in HOT if d in DISTRICTS]
    d_weights = [HOT[d] for d in districts]
    cats = [(c, s) for c, s, _ in SAMPLES]
    c_weights = [w for _, _, w in SAMPLES]
    now = time.time()
    for _ in range(n):
        district = rng.choices(districts, d_weights)[0]
        cat, snippet = rng.choices(cats, c_weights)[0]
        storage.add_report(
            district=district,
            verdict="scam" if rng.random() < 0.85 else "suspicious",
            score=rng.randint(62, 100),
            category=cat,
            snippet=snippet,
            channel="seed",
            ts=now - rng.uniform(0, 14 * 86400),
        )
    seed_intel(seed=seed)
    return n


# Fake, obviously sequential identifiers: three "rings" that reuse numbers / UPI IDs / domains across districts.
_RINGS = [
    ("electricity", ["Ludhiana", "Amritsar", "Patiala"], [
        "Dear consumer, electricity will be disconnected tonight 9:30 pm, bill not updated. Call 9000011111 now",
        "Your power connection will be cut tonight. Update bill at http://pspcl-bill-pay.top or call 9000011112",
        "Electricity bill pending, supply disconnect tonight. Contact 9000011111 or 9000011112 immediately",
        "Power cut tonight due to unpaid bill. Pay here pspcl-bill-pay.top and call 9000011112",
    ]),
    ("kyc", ["Jalandhar", "Delhi", "Gurugram"], [
        "Your SBI account is blocked. Update KYC at http://sbi-kyc-update.xyz or pay Rs 10 to kyc.update@okaxis",
        "SBI KYC expired, account will be suspended. Click sbi-kyc-update.xyz and call 9000022222",
        "Update KYC now to avoid block, send OTP, call 9000022222 or UPI kyc.update@okaxis",
    ]),
    ("lottery", ["Hisar", "Karnal", "Rohtak"], [
        "You won Rs 25 lakh in KBC lottery. Pay processing fee to kbc.prize@ybl",
        "KBC lottery winner! Pay fee to kbc.prize@ybl and call 9000033333 to claim",
        "Congratulations lottery prize, processing fee on 9000033333 or UPI kbc.prize@ybl",
    ]),
]

_BURST = [
    ("electricity", "Ludhiana", 14, [
        "Dear consumer, electricity will be disconnected tonight 9:30 pm, bill not updated. Call 9000011111 now",
        "Your power connection will be cut tonight, bill not updated. Update at http://pspcl-bill-pay.top or call 9000011112",
        "Electricity will be disconnected tonight because your bill is not updated. Call now 9000011111",
    ]),
    ("kyc", "Jalandhar", 9, [
        "Your SBI account is blocked. Update KYC now at http://sbi-kyc-update.xyz",
        "SBI KYC expired, account will be suspended. Click sbi-kyc-update.xyz to update KYC now",
    ]),
]


def seed_intel(seed: int = 7) -> None:
    """Add a fresh outbreak burst and scammer-ring identifiers so the intelligence panels have something to show."""
    rng = random.Random(seed + 1)
    now = time.time()
    for cat, districts, texts in _RINGS:
        for i, text in enumerate(texts):
            storage.add_report(district=districts[i % len(districts)], verdict="scam", score=rng.randint(70, 98), category=cat,
                               snippet=text, channel="seed", ts=now - rng.uniform(1 * 86400, 12 * 86400))
    for cat, district, n, texts in _BURST:
        for i in range(n):
            storage.add_report(district=district, verdict="scam", score=rng.randint(70, 98), category=cat,
                               snippet=texts[i % len(texts)], channel="seed", ts=now - rng.uniform(60, 3.5 * 3600))
