from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SECRET_KEY: str = "changeme"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 heures
    DATABASE_URL: str = "sqlite:///./suturasec.db"
    ANTHROPIC_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Railway fournit postgresql:// — SQLAlchemy 2.0 requiert postgresql+psycopg2://
        if self.DATABASE_URL.startswith("postgresql://"):
            object.__setattr__(self, "DATABASE_URL", self.DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1))

    class Config:
        env_file = ".env"


settings = Settings()
