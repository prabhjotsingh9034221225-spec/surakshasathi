"""Fill the database with sample reports so the heatmap looks alive.

    python scripts/seed_demo.py            # add 150 sample reports
    python scripts/seed_demo.py --reset    # wipe everything first
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import demo, storage  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("-n", type=int, default=150)
parser.add_argument("--reset", action="store_true")
args = parser.parse_args()

storage.init()
if args.reset:
    storage.clear_all()
print(f"Seeded {demo.seed_reports(args.n)} sample reports into {storage.settings.database_path}")
