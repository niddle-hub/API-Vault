import os
import secrets
from datetime import timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def _load_or_create_secret(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text(encoding="ascii").strip()

    secret = secrets.token_hex(32)
    path.write_text(secret, encoding="ascii")
    return secret


class Config:
    SECRET_KEY = os.environ.get(
        "API_VAULT_SECRET_KEY",
        _load_or_create_secret(BASE_DIR / ".app_secret"),
    )
    DATABASE = os.environ.get("API_VAULT_DATABASE", str(BASE_DIR / "keys.db"))
    SESSION_PERMANENT = True
    SESSION_COOKIE_NAME = "api_vault_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = False
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get("API_VAULT_SESSION_MINUTES", "30"))
    )
    MAX_CONTENT_LENGTH = 64 * 1024
    PORT = int(os.environ.get("API_VAULT_PORT", "5000"))
