"""
Migration : ajout de la colonne subdomain_results sur la table scans.
Lancer depuis le dossier backend/ : python migrate_subdomain.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.config import settings
from sqlalchemy import create_engine, text

connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)

SQL = "ALTER TABLE scans ADD COLUMN subdomain_results JSON"

with engine.connect() as conn:
    try:
        conn.execute(text(SQL))
        conn.commit()
        print("OK: colonne subdomain_results ajoutee")
    except Exception as e:
        msg = str(e).lower()
        if "duplicate" in msg or "already exists" in msg:
            print("INFO: colonne subdomain_results deja presente")
        else:
            print("ERREUR:", e)
            sys.exit(1)

print("Migration terminee.")
