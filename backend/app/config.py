from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SECRET_KEY: str = "changeme"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 heures
    DATABASE_URL: str = "sqlite:///./suturasec.db"
    ANTHROPIC_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    # Nombre de proxys de confiance devant l'app (Railway = 1). Sert à lire la vraie IP
    # client dans X-Forwarded-For pour le rate limiting. -1 = auto (1 si Railway, sinon 0).
    TRUSTED_PROXY_HOPS: int = -1
    # Autorise les cibles privées/locales (127.0.0.1, 10.x, 192.168.x…). À n'activer
    # qu'en développement local : en production, cela exposerait le réseau interne (SSRF).
    ALLOW_PRIVATE_TARGETS: bool = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.TRUSTED_PROXY_HOPS < 0:
            import os
            on_railway = any(k.startswith("RAILWAY_") for k in os.environ)
            object.__setattr__(self, "TRUSTED_PROXY_HOPS", 1 if on_railway else 0)
        # Railway fournit postgresql:// — SQLAlchemy 2.0 requiert postgresql+psycopg2://
        if self.DATABASE_URL.startswith("postgresql://"):
            object.__setattr__(self, "DATABASE_URL", self.DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1))

    class Config:
        env_file = ".env"


settings = Settings()
