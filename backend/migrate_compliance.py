"""Migration : ajoute la colonne compliance_reports a la table scans."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sqlalchemy import text
from app.database import engine

with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE scans ADD COLUMN compliance_reports TEXT"))
        conn.commit()
        print("OK: Colonne compliance_reports ajoutee.")
    except Exception as e:
        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
            print("INFO: Colonne deja presente.")
        else:
            print(f"ERREUR: {e}")
