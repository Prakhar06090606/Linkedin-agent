from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, func, select, text
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from backend.config import DATA_DIR, settings


DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = settings.database_url
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ActionLog(Base):
    __tablename__ = "action_logs"

    id = Column(Integer, primary_key=True, index=True)
    platform = Column(String, index=True)
    action_type = Column(String, index=True)
    target_url = Column(String, nullable=True)
    status = Column(String, index=True)
    details = Column(String, nullable=True)
    # NEW: stores the actual text of a post/comment/note for the Live Feed
    content_body = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class Draft(Base):
    __tablename__ = "drafts"

    id = Column(Integer, primary_key=True, index=True)
    platform = Column(String, index=True)
    draft_type = Column(String, index=True)  # e.g. blog, post
    topic = Column(String, nullable=True)
    audience = Column(String, nullable=True)
    tone = Column(String, nullable=True)
    title = Column(String, nullable=True)
    content = Column(String, nullable=False)
    status = Column(String, index=True, default="generated")
    source_provider = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    published_at = Column(DateTime(timezone=True), nullable=True)


# ── Heartbeat table ───────────────────────────────────────────────────────────
class AgentHeartbeat(Base):
    __tablename__ = "agent_heartbeats"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    action_type = Column(String, nullable=True)   # what the agent is currently doing
    detail = Column(String, nullable=True)


@contextmanager
def get_db_session() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _run_migrations(db_engine) -> None:
    """
    Safe additive migrations — adds new columns to existing tables without
    dropping data. SQLite does not support ALTER COLUMN, only ADD COLUMN.
    """
    with db_engine.connect() as conn:
        # 1. Add content_body to action_logs if missing
        try:
            cols = [row[1] for row in conn.execute(text("PRAGMA table_info(action_logs)"))]
            if "content_body" not in cols:
                conn.execute(text("ALTER TABLE action_logs ADD COLUMN content_body TEXT"))
                conn.commit()
        except Exception:
            pass

        # 2. Create agent_heartbeats table if missing (handled by create_all too)
        try:
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS agent_heartbeats "
                "(id INTEGER PRIMARY KEY, timestamp DATETIME, action_type TEXT, detail TEXT)"
            ))
            conn.commit()
        except Exception:
            pass


def init_database() -> None:
    Base.metadata.create_all(bind=engine)
    _run_migrations(engine)


# ── action logging ────────────────────────────────────────────────────────────
def log_action(
    db: Session,
    platform: str,
    action_type: str,
    status: str,
    target_url: Optional[str] = None,
    details: Optional[str] = None,
    content_body: Optional[str] = None,
) -> ActionLog:
    row = ActionLog(
        platform=platform,
        action_type=action_type,
        status=status,
        target_url=target_url,
        details=details,
        content_body=content_body,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def log_heartbeat(db: Session, action_type: Optional[str] = None, detail: Optional[str] = None) -> AgentHeartbeat:
    row = AgentHeartbeat(action_type=action_type, detail=detail)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_last_heartbeat(db: Session) -> Optional[AgentHeartbeat]:
    stmt = select(AgentHeartbeat).order_by(AgentHeartbeat.timestamp.desc()).limit(1)
    return db.scalar(stmt)


def check_action_limit(db: Session, platform: str, action_type: str, daily_limit: int) -> bool:
    today = datetime.now(timezone.utc).date()
    count_stmt = (
        select(func.count(ActionLog.id))
        .where(ActionLog.platform == platform)
        .where(ActionLog.action_type == action_type)
        .where(ActionLog.status == "success")
        .where(func.date(ActionLog.timestamp) == today.isoformat())
    )
    current_count = db.scalar(count_stmt) or 0
    return current_count < daily_limit


def get_today_metrics(db: Session) -> Dict[str, int]:
    today = datetime.now(timezone.utc).date().isoformat()

    def count(action_type: str, status: Optional[str] = None) -> int:
        stmt = (
            select(func.count(ActionLog.id))
            .where(ActionLog.action_type == action_type)
            .where(func.date(ActionLog.timestamp) == today)
        )
        if status:
            stmt = stmt.where(ActionLog.status == status)
        return db.scalar(stmt) or 0

    return {
        "linkedin_connections": count("connection", "success"),
        "linkedin_comments": count("comment", "success"),
        "linkedin_posts": count("post", "success"),
        "linkedin_likes": count("like", "success"),
        "linkedin_follows": count("follow", "success"),
        "blocked_by_limit": (
            count("connection", "blocked_limit")
            + count("comment", "blocked_limit")
            + count("post", "blocked_limit")
        ),
        "errors_or_captcha": (
            count("connection", "failed") + count("comment", "failed")
            + count("post", "failed") + count("like", "failed")
            + count("follow", "failed")
            + count("connection", "captcha_hit") + count("comment", "captcha_hit")
            + count("post", "captcha_hit")
        ),
    }


def get_all_time_metrics(db: Session) -> Dict[str, int]:
    """All-time cumulative counts per action type (success only)."""
    def count_all(action_type: str) -> int:
        stmt = (
            select(func.count(ActionLog.id))
            .where(ActionLog.action_type == action_type)
            .where(ActionLog.status == "success")
        )
        return db.scalar(stmt) or 0

    return {
        "total_posts": count_all("post"),
        "total_comments": count_all("comment"),
        "total_connections": count_all("connection"),
        "total_likes": count_all("like"),
        "total_follows": count_all("follow"),
    }


def get_recent_actions(db: Session, limit: int = 100) -> List[ActionLog]:
    stmt = select(ActionLog).order_by(ActionLog.timestamp.desc()).limit(limit)
    return list(db.scalars(stmt).all())


def get_actions_last_n_days(db: Session, days: int = 7) -> List[ActionLog]:
    """Return actions for the last N days — used for analytics graphs."""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = (
        select(ActionLog)
        .where(ActionLog.timestamp >= cutoff)
        .where(ActionLog.status == "success")
        .order_by(ActionLog.timestamp.asc())
    )
    return list(db.scalars(stmt).all())


def was_recently_acted_on(
    db: Session,
    url: str,
    action_type: str,
    days: int = 30,
) -> bool:
    """Return True if this URL was successfully acted on within the last N days.
    Used for deduplication — prevents re-commenting or re-connecting with the same target."""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = (
        select(func.count(ActionLog.id))
        .where(ActionLog.target_url == url)
        .where(ActionLog.action_type == action_type)
        .where(ActionLog.status == "success")
        .where(ActionLog.timestamp >= cutoff)
    )
    return (db.scalar(stmt) or 0) > 0


def create_draft(
    db: Session,
    platform: str,
    draft_type: str,
    content: str,
    title: Optional[str] = None,
    topic: Optional[str] = None,
    audience: Optional[str] = None,
    tone: Optional[str] = None,
    source_provider: Optional[str] = None,
) -> Draft:
    row = Draft(
        platform=platform,
        draft_type=draft_type,
        topic=topic,
        audience=audience,
        tone=tone,
        title=title,
        content=content,
        status="generated",
        source_provider=source_provider,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_draft(db: Session, draft_id: int) -> Optional[Draft]:
    stmt = select(Draft).where(Draft.id == draft_id)
    return db.scalar(stmt)


def list_drafts(db: Session, limit: int = 50) -> List[Draft]:
    stmt = select(Draft).order_by(Draft.created_at.desc()).limit(limit)
    return list(db.scalars(stmt).all())


def update_draft_content(
    db: Session,
    draft_id: int,
    title: Optional[str] = None,
    content: Optional[str] = None,
) -> Optional[Draft]:
    row = get_draft(db, draft_id)
    if row is None:
        return None
    if title is not None:
        row.title = title
    if content is not None:
        row.content = content
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def mark_draft_published(db: Session, draft_id: int) -> Optional[Draft]:
    row = get_draft(db, draft_id)
    if row is None:
        return None
    row.status = "published"
    row.published_at = datetime.now(timezone.utc)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def mark_draft_approved(db: Session, draft_id: int) -> Optional[Draft]:
    row = get_draft(db, draft_id)
    if row is None:
        return None
    row.status = "approved"
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
