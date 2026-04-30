from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


class Settings(BaseSettings):
    database_url: str = "sqlite:///./data/agent_memory.db"
    agent_interval_hours: int = 4

    max_linkedin_connections_per_day: int = 20
    max_linkedin_comments_per_day: int = 50
    max_linkedin_posts_per_day: int = 10
    max_linkedin_follows_per_day: int = 30

    api_host: str = "127.0.0.1"
    api_port: int = 8000
    dashboard_api_url: str = "http://127.0.0.1:8000"

    playwright_headless: bool = True
    agent_dry_run: bool = False
    agent_log_level: str = "info"

    content_provider: str = "template"
    llm_api_url: str = ""
    llm_api_key: str = ""
    # Comma-separated list of Gemini API keys for quota rotation.
    # Falls back to llm_api_key when empty.
    llm_api_keys: str = ""
    llm_model: str = ""

    agent_post_topic: str = "How EduBuild helps professionals upskill faster"
    agent_post_audience: str = "working professionals"
    agent_post_tone: str = "professional"

    agent_comment_targets: str = ""
    agent_connection_targets: str = ""
    agent_max_comments_per_run: int = 4
    agent_max_connections_per_run: int = 5
    agent_max_follows_per_run: int = 5
    agent_max_discover_posts: int = 6
    agent_max_discover_people: int = 5
    agent_max_discover_companies: int = 5

    # ── CAPTCHA solving ───────────────────────────────────────────────────────
    # API key for 2captcha.com (supports reCAPTCHA v2/v3, FunCaptcha, hCaptcha).
    # Leave blank to use the timed-wait fallback (agent pauses 45 s then retries).
    captcha_api_key: str = ""

    # ── Security settings ──────────────────────────────────────────────────────
    # JWT signing secret — generate: python -c "import secrets; print(secrets.token_hex(32))"
    dashboard_secret_key: str = ""
    dashboard_username: str = "admin"
    dashboard_password: str = ""  # MUST be set in .env — server refuses to start without it
    jwt_expire_minutes: int = 480
    csrf_secret: str = ""
    # Fernet encryption key for activity logs at rest (optional but recommended)
    # Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    log_encryption_key: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
