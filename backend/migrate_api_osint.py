"""
Migration: add api_results and osint_results columns to scans table.
Run from repo root:  python backend/migrate_api_osint.py
  OR from backend/:  python migrate_api_osint.py
"""
import os
import sys

# Ensure imports work whether called from repo root or backend/
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Change working directory to backend/ so relative SQLite paths resolve
os.chdir(BACKEND_DIR)

try:
    from sqlalchemy import create_engine, text
    from app.config import settings
    db_url = settings.DATABASE_URL
except Exception:
    db_url = os.environ.get("DATABASE_URL", "sqlite:///./suturasec.db")

print(f"[migrate] Connecting to: {db_url}")

connect_args = {"check_same_thread": False} if "sqlite" in db_url else {}
engine = create_engine(db_url, connect_args=connect_args)

MIGRATIONS = [
    "ALTER TABLE scans ADD COLUMN api_results JSON",
    "ALTER TABLE scans ADD COLUMN osint_results JSON",
]

with engine.connect() as conn:
    for sql in MIGRATIONS:
        col = sql.split("ADD COLUMN ")[1].split()[0]
        try:
            conn.execute(text(sql))
            conn.commit()
            print(f"[migrate] Added column: {col}")
        except Exception as e:
            if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                print(f"[migrate] Column {col} already exists — skipped")
            else:
                print(f"[migrate] ERROR for {col}: {e}")
                sys.exit(1)

print("[migrate] Done.")
