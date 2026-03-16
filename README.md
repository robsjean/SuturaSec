# 🛡️ SuturaSec — Security as a Service Platform

> Plateforme d'analyse de sécurité automatisée propulsée par l'IA, construite avec FastAPI et Claude AI.

![Python](https://img.shields.io/badge/Python-3.14-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?style=flat-square&logo=sqlite&logoColor=white)

---

## ✨ Fonctionnalités

### Scanners de sécurité
- **Scanner Web** — Analyse automatisée OWASP Top 10 : injections, XSS, mauvaises configurations, headers HTTP, SSL/TLS, cookies, redirections
- **Scanner Réseau** — Découverte d'hôtes, scan de ports ouverts, détection de services et bannières

### Moteur IA (Claude AI)
- **Résumé exécutif** auto-généré pour chaque analyse
- **Modélisation des chemins d'attaque** (MITRE ATT&CK-style)
- **Priorités de remédiation** classées par effort / impact
- **Quick Wins** : actions correctives rapides identifiées automatiquement

### Rapports PDF
- Génération en un clic depuis le tableau de bord
- Format professionnel optimisé pour l'impression
- 4 sections : synthèse, vulnérabilités, chemins d'attaque, plan de remédiation

### Interface moderne
- **Mode sombre / mode clair** avec persistance localStorage
- Sidebar de navigation avec roadmap des fonctionnalités à venir
- Design responsive (mobile & desktop)
- Mise à jour automatique en temps réel pendant les scans

### Authentification & Sécurité
- JWT (JSON Web Tokens) avec expiration configurable
- Hashage bcrypt des mots de passe
- Isolation des données par utilisateur

---

## Architecture

```
SuturaSec/
└── backend/
    ├── app/
    │   ├── main.py              # FastAPI app + routes HTML
    │   ├── config.py            # Configuration (Settings)
    │   ├── database.py          # SQLAlchemy + SQLite
    │   ├── core/
    │   │   └── security.py      # JWT + bcrypt
    │   ├── models/
    │   │   ├── user.py          # Modèle User
    │   │   └── scan.py          # Modèle Scan + Vulnerability
    │   ├── routers/
    │   │   ├── auth.py          # /api/auth/*
    │   │   └── scans.py         # /api/scans/*
    │   ├── schemas/             # Pydantic schemas
    │   ├── services/
    │   │   ├── auth.py          # get_current_user
    │   │   └── ai_engine.py     # Intégration Claude API
    │   └── scanners/
    │       ├── web_scanner.py   # Scanner HTTP/SSL/OWASP
    │       └── network_scanner.py # Scanner réseau/ports
    ├── templates/               # Jinja2 + Alpine.js + Tailwind CSS
    │   ├── base.html            # Layout public
    │   ├── base_app.html        # Layout app
    │   ├── login.html
    │   ├── register.html
    │   ├── dashboard.html
    │   ├── scan_detail.html
    │   └── report.html          # Template rapport PDF
    └── requirements.txt
```

### Stack technique

| Couche | Technologie |
|--------|------------|
| Backend | Python 3.14, FastAPI, Uvicorn |
| Base de données | SQLite + SQLAlchemy ORM |
| Auth | JWT (python-jose) + bcrypt |
| IA | Anthropic Claude API (httpx direct) |
| Frontend | Jinja2, Alpine.js (CDN), Tailwind CSS (CDN) |
| HTTP client | httpx (scans web + appels API) |


---

## Installation & Lancement

### Prérequis
- Python 3.10+
- Une clé API Anthropic → [console.anthropic.com](https://console.anthropic.com)

### 1. Cloner le dépôt

```bash
git clone https://github.com/TON_USERNAME/SuturaSec.git
cd SuturaSec/backend
```

### 2. Créer l'environnement virtuel

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Configurer les variables d'environnement

```bash
cp .env.example .env
```

Éditer `.env` :

```env
SECRET_KEY=une_cle_secrete_longue_et_aleatoire_ici
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440
DATABASE_URL=sqlite:///./suturasec.db
ANTHROPIC_API_KEY=sk-ant-api03-...
```

### 5. Lancer le serveur

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Ouvrir [http://localhost:8000](http://localhost:8000) 

---

## API REST

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/auth/register` | Créer un compte |
| `POST` | `/api/auth/login` | Connexion (retourne JWT) |
| `GET` | `/api/auth/me` | Profil utilisateur courant |
| `GET` | `/api/scans` | Liste des scans de l'utilisateur |
| `POST` | `/api/scans` | Lancer un nouveau scan |
| `GET` | `/api/scans/{id}` | Détail d'un scan + vulnérabilités |
| `DELETE` | `/api/scans/{id}` | Supprimer un scan |

Documentation Swagger interactive : [http://localhost:8000/docs](http://localhost:8000/docs)

---

## ⚠️ Avertissement légal

SuturaSec est conçu pour analyser **uniquement des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite explicite**. Toute utilisation non autorisée est illégale et contraire à l'éthique. Les auteurs déclinent toute responsabilité en cas d'utilisation abusive.

---

## Auteur

**Jean Robert Waly Sarr** — Ingénieur Cybersécurité
