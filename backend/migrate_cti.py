"""Migration : ajoute la colonne threat_intel à la table scans."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import text
from app.database import engine

with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE scans ADD COLUMN threat_intel TEXT"))
        conn.commit()
        print("OK: Colonne threat_intel ajoutee a scans.")
    except Exception as e:
        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
            print("INFO: Colonne threat_intel deja presente - rien a faire.")
        else:
            print(f"ERREUR: {e}")
