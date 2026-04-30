from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from backend.agent.content import generate_blog_content
from backend.agent.execution import (
    CaptchaDetectedError,
    SafetyBlockedError,
    SessionExpiredError,
    bootstrap_linkedin_session,
    execute_linkedin_action,
    get_linkedin_session_status,
)
from backend.agent.graph import run_daily_agent_workflow
from backend.config import settings
from backend.database import (
    create_draft,
    get_actions_last_n_days,
    get_all_time_metrics,
    get_db_session,
    get_draft,
    get_last_heartbeat,
    get_recent_actions,
    get_today_metrics,
    init_database,
    list_drafts,
    log_heartbeat,
    mark_draft_approved,
    mark_draft_published,
    update_draft_content,
)
from backend.logging_utils import read_error_logs, read_recent_logs, setup_logging
from backend.scheduler import now_iso, runtime_state, scheduler
from backend.security import (
    RateLimiter,
    create_access_token,
    generate_csrf_token,
    scrub_secrets,
    verify_csrf_token,
    verify_token,
)

app = FastAPI(title="EduBild 24/7 Social Agent API", version="2.0.0")
logger = setup_logging()

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Rate limiter ──────────────────────────────────────────────────────────────
# General API: 120 req/min per IP
# Sensitive endpoints (trigger, runagent): 10 req/min
_rate_limiter = RateLimiter(max_requests=120, window_seconds=60)
_sensitive_limiter = RateLimiter(max_requests=10, window_seconds=60)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    path = request.url.path

    # Tighter limit on action-triggering endpoints
    if any(path.startswith(p) for p in ("/api/trigger", "/api/runagent", "/api/manual")):
        if not _sensitive_limiter.allow(ip):
            return JSONResponse(
                {"detail": "Rate limit exceeded — too many requests. Try again in a minute."},
                status_code=429,
                headers={"Retry-After": "60"},
            )
    elif not _rate_limiter.allow(ip):
        return JSONResponse(
            {"detail": "Rate limit exceeded"},
            status_code=429,
            headers={"Retry-After": "60"},
        )

    response = await call_next(request)
    return response


# ── JWT authentication helpers ────────────────────────────────────────────────
_DASHBOARD_USERNAME = settings.dashboard_username or "admin"
_DASHBOARD_PASSWORD = settings.dashboard_password
if not _DASHBOARD_PASSWORD:
    raise RuntimeError(
        "DASHBOARD_PASSWORD is not set in .env — refusing to start with no password. "
        "Add DASHBOARD_PASSWORD=<your-password> to .env and restart."
    )


class LoginRequest(BaseModel):
    username: str
    password: str


def _require_auth(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    """
    FastAPI dependency — verifies Bearer JWT in Authorization header.
    Raises 401 if missing/invalid.  Returns payload dict on success.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header required")
    token = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


# ── request models ────────────────────────────────────────────────────────────
class ManualActionRequest(BaseModel):
    action_type: str = Field(pattern="^(connection|comment|post|follow)$")
    target_url: str | None = None
    text: str | None = None


class DraftGenerateRequest(BaseModel):
    topic: str
    audience: str = "professionals"
    tone: str = "professional"
    length_words: int = 180


class DraftUpdateRequest(BaseModel):
    title: str | None = None
    content: str | None = None


class PublishDraftRequest(BaseModel):
    target_url: str | None = "https://www.linkedin.com/feed/"
    override_title: str | None = None
    override_content: str | None = None
    force_publish: bool = False


class RuntimeConfigRequest(BaseModel):
    automation_paused: bool | None = None


class LinkedInSessionBootstrapRequest(BaseModel):
    timeout_minutes: int = 5


class RunAgentRequest(BaseModel):
    require_linkedin_session: bool = True


class HeartbeatRequest(BaseModel):
    action_type: str | None = None
    detail: str | None = None


# ── agent job ─────────────────────────────────────────────────────────────────
async def agent_job() -> Dict[str, Any]:
    logger.info("agent_job requested")
    if runtime_state.automation_paused:
        logger.info("agent_job skipped: automation paused")
        return {"status": "skipped", "reason": "automation_paused"}

    if not runtime_state.acquire():
        logger.info("agent_job skipped: already running")
        return {"status": "skipped", "reason": "job_already_running"}

    runtime_state.is_running = True
    runtime_state.last_run_started_at = now_iso()
    runtime_state.last_error = None
    logger.info("agent_job started")

    try:
        with get_db_session() as db:
            log_heartbeat(db, "agent_start", "Agent job started")
            result = await run_daily_agent_workflow(db)
            log_heartbeat(db, "agent_done", "Agent job completed")
        runtime_state.last_result = result
        runtime_state.last_run_status = "success"
        logger.info("agent_job finished successfully")
        return {"status": "success", "result": result}
    except Exception as exc:
        runtime_state.last_run_status = "failed"
        runtime_state.last_error = scrub_secrets(str(exc))
        logger.exception("agent_job failed: %s", exc)
        return {"status": "failed", "error": scrub_secrets(str(exc))}
    finally:
        runtime_state.is_running = False
        runtime_state.last_run_finished_at = now_iso()
        runtime_state.release()


# ── lifecycle ─────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event() -> None:
    logger.info("backend startup — dry_run=%s headless=%s",
                settings.agent_dry_run, settings.playwright_headless)
    init_database()
    if not scheduler.running:
        scheduler.add_job(
            agent_job, "interval",
            hours=settings.agent_interval_hours,
            id="main_agent_loop",
            replace_existing=True,
        )
        scheduler.start()
        logger.info("scheduler started with interval=%sh", settings.agent_interval_hours)


@app.on_event("shutdown")
async def shutdown_event() -> None:
    logger.info("backend shutdown")
    if scheduler.running:
        scheduler.shutdown(wait=False)


# ── auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(req: LoginRequest) -> Dict[str, Any]:
    """Issue a JWT for dashboard access.  Configure username/password in .env."""
    # Use constant-time comparison to prevent timing attacks
    import hmac as _hmac
    user_ok = _hmac.compare_digest(req.username, _DASHBOARD_USERNAME)
    pass_ok = _hmac.compare_digest(req.password, _DASHBOARD_PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": req.username})
    logger.info("dashboard login: user=%s", req.username)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/auth/csrf")
async def get_csrf_token(request: Request) -> Dict[str, str]:
    """Return a short-lived CSRF token for the requesting session."""
    session_id = request.client.host if request.client else "default"
    token = generate_csrf_token(session_id)
    return {"csrf_token": token}


# ── core endpoints ────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "time_utc": datetime.now(timezone.utc).isoformat()}


@app.get("/api/status")
async def status() -> Dict[str, Any]:
    job = scheduler.get_job("main_agent_loop") if scheduler.running else None
    next_run = job.next_run_time.isoformat() if job and job.next_run_time else None
    return {
        "agent_running": runtime_state.is_running,
        "last_run_started_at": runtime_state.last_run_started_at,
        "last_run_finished_at": runtime_state.last_run_finished_at,
        "last_run_status": runtime_state.last_run_status,
        "last_error": runtime_state.last_error,
        "automation_paused": runtime_state.automation_paused,
        "next_scheduled_run": next_run,
        "scheduler_running": scheduler.running,
        "interval_hours": settings.agent_interval_hours,
        "last_result": runtime_state.last_result,
    }


# ── heartbeat ─────────────────────────────────────────────────────────────────
@app.post("/api/heartbeat")
async def post_heartbeat(req: HeartbeatRequest) -> Dict[str, Any]:
    """
    Agent calls this endpoint each time it completes a sub-action.
    The dashboard reads /api/heartbeat/last to drive the Pulse indicator.
    """
    with get_db_session() as db:
        hb = log_heartbeat(db, req.action_type, req.detail)
    return {
        "status": "ok",
        "timestamp": hb.timestamp.isoformat(),
        "action_type": hb.action_type,
    }


@app.get("/api/heartbeat/last")
async def get_heartbeat() -> Dict[str, Any]:
    """Return the most recent heartbeat row for the dashboard Pulse widget."""
    with get_db_session() as db:
        hb = get_last_heartbeat(db)
    if hb is None:
        return {"timestamp": None, "action_type": None, "detail": None, "seconds_ago": None}
    now = datetime.now(timezone.utc)
    ts = hb.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    seconds_ago = int((now - ts).total_seconds())
    return {
        "timestamp": ts.isoformat(),
        "action_type": hb.action_type,
        "detail": hb.detail,
        "seconds_ago": seconds_ago,
        "stuck": seconds_ago > 300,   # > 5 min = stuck alert
    }


@app.post("/api/trigger")
async def trigger(background_tasks: BackgroundTasks, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, str]:
    if runtime_state.automation_paused:
        raise HTTPException(status_code=409, detail="Automation is paused")
    if runtime_state.is_running:
        raise HTTPException(status_code=409, detail="Agent already running")
    background_tasks.add_task(agent_job)
    logger.info("manual trigger queued")
    return {"message": "Agent manually triggered"}


@app.post("/api/runagent")
async def runagent(req: RunAgentRequest, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, Any]:
    if runtime_state.automation_paused:
        raise HTTPException(status_code=409, detail="Automation is paused")
    if runtime_state.is_running:
        raise HTTPException(status_code=409, detail="Agent already running")

    session_status = get_linkedin_session_status()
    if (
        req.require_linkedin_session
        and not settings.agent_dry_run
        and not session_status.get("session_exists", False)
    ):
        raise HTTPException(
            status_code=409,
            detail="LinkedIn session missing. Bootstrap from dashboard first.",
        )

    result = await agent_job()
    logger.info("runagent completed status=%s", result.get("status"))
    return {
        "message": "Agent run completed",
        "dry_run": settings.agent_dry_run,
        "session_exists": session_status.get("session_exists", False),
        "result": result,
    }


# ── automation control ────────────────────────────────────────────────────────
@app.post("/api/automation/pause")
async def pause_automation(_: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, str]:
    runtime_state.automation_paused = True
    logger.info("automation paused")
    return {"message": "Automation paused"}


@app.post("/api/automation/resume")
async def resume_automation(_: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, str]:
    runtime_state.automation_paused = False
    logger.info("automation resumed")
    return {"message": "Automation resumed"}


# ── manual actions ────────────────────────────────────────────────────────────
@app.post("/api/manual/action")
async def manual_action(req: ManualActionRequest, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, Any]:
    if runtime_state.is_running:
        raise HTTPException(status_code=409, detail="Agent currently running. Try again shortly.")

    payload = {"text": req.text} if req.text else {}
    with get_db_session() as db:
        try:
            result = await execute_linkedin_action(
                db=db,
                action_type=req.action_type,
                target_url=req.target_url,
                payload=payload,
            )
        except SafetyBlockedError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except SessionExpiredError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except CaptchaDetectedError as exc:
            logger.warning("CAPTCHA encountered during manual action: %s", exc)
            raise HTTPException(status_code=503, detail=f"LinkedIn CAPTCHA detected: {exc}")

    logger.info("manual action %s status=%s", req.action_type, result.get("status"))
    return result


# ── LinkedIn session ──────────────────────────────────────────────────────────
@app.get("/api/linkedin/session/status")
async def linkedin_session_status() -> Dict[str, Any]:
    return get_linkedin_session_status()


@app.post("/api/linkedin/session/bootstrap")
async def linkedin_session_bootstrap(req: LinkedInSessionBootstrapRequest, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, Any]:
    if runtime_state.is_running:
        raise HTTPException(status_code=409, detail="Agent currently running. Try again shortly.")
    logger.info("linkedin session bootstrap requested timeout=%s", req.timeout_minutes)
    result = await bootstrap_linkedin_session(timeout_minutes=req.timeout_minutes)
    logger.info("linkedin session bootstrap result=%s", result.get("status"))
    return result


@app.get("/api/linkedin/session/check")
async def linkedin_session_check() -> Dict[str, Any]:
    from backend.agent.execution import (
        LINKEDIN_SESSION_FILE,
        CaptchaDetectedError,
        _check_session_alive,
        _open_browser,
    )

    if not LINKEDIN_SESSION_FILE.exists():
        return {"alive": False, "detail": "Session file does not exist"}

    pw = browser = context = page = None
    try:
        pw, browser, context, page = await _open_browser()
        alive = await _check_session_alive(page)
        return {"alive": alive, "detail": "Session valid" if alive else "Session expired or invalid"}
    except CaptchaDetectedError as exc:
        return {"alive": False, "detail": f"CAPTCHA detected: {exc}"}
    except Exception as exc:
        logger.error("session health check failed: %s", exc)
        return {"alive": False, "detail": str(exc)}
    finally:
        for res in [context, browser, pw]:
            if res:
                try:
                    await res.close()
                except Exception:
                    pass


# ── scheduler ─────────────────────────────────────────────────────────────────
@app.post("/api/scheduler/start")
async def scheduler_start(_: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, str]:
    if not scheduler.running:
        scheduler.start()
    scheduler.resume()
    return {"message": "Scheduler started"}


@app.post("/api/scheduler/stop")
async def scheduler_stop(_: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, str]:
    if not scheduler.running:
        return {"message": "Scheduler already stopped"}
    scheduler.pause()
    return {"message": "Scheduler paused"}


@app.get("/api/scheduler/jobs")
async def scheduler_jobs() -> Dict[str, Any]:
    if not scheduler.running:
        return {"jobs": [], "scheduler_running": False}
    jobs = scheduler.get_jobs()
    return {
        "scheduler_running": True,
        "jobs": [
            {
                "id": job.id,
                "name": job.name,
                "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
            }
            for job in jobs
        ],
    }


# ── config ────────────────────────────────────────────────────────────────────
@app.get("/api/config")
async def get_runtime_config() -> Dict[str, Any]:
    return {
        "automation_paused": runtime_state.automation_paused,
        "agent_interval_hours": settings.agent_interval_hours,
        "agent_dry_run": settings.agent_dry_run,
        "playwright_headless": settings.playwright_headless,
        "content_provider": settings.content_provider,
    }


@app.post("/api/config")
async def update_runtime_config(req: RuntimeConfigRequest, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, Any]:
    if req.automation_paused is not None:
        runtime_state.automation_paused = req.automation_paused
    return await get_runtime_config()


# ── logs ──────────────────────────────────────────────────────────────────────
@app.get("/api/logs")
async def logs(limit: int = 300) -> Dict[str, Any]:
    lines = read_recent_logs(limit=limit)
    return {"items": lines, "count": len(lines)}


@app.get("/api/logs/errors")
async def error_logs(limit: int = 100) -> Dict[str, Any]:
    lines = read_error_logs(limit=limit)
    return {"items": lines, "count": len(lines)}


# ── metrics ───────────────────────────────────────────────────────────────────
@app.get("/api/metrics")
async def metrics() -> Dict[str, Any]:
    with get_db_session() as db:
        today = get_today_metrics(db)
        all_time = get_all_time_metrics(db)
        recent = get_recent_actions(db, limit=50)
        drafts = list_drafts(db, limit=50)

    return {
        "today": today,
        "all_time": all_time,
        "recent_actions": [
            {
                "id": row.id,
                "platform": row.platform,
                "action_type": row.action_type,
                "target_url": row.target_url,
                "status": row.status,
                "details": row.details,
                "content_body": row.content_body,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            }
            for row in recent
        ],
        "drafts": [
            {
                "id": d.id,
                "platform": d.platform,
                "draft_type": d.draft_type,
                "topic": d.topic,
                "audience": d.audience,
                "tone": d.tone,
                "title": d.title,
                "content": d.content,
                "status": d.status,
                "source_provider": d.source_provider,
                "created_at": d.created_at.isoformat() if d.created_at else None,
                "published_at": d.published_at.isoformat() if d.published_at else None,
            }
            for d in drafts
        ],
    }


@app.get("/api/metrics/analytics")
async def metrics_analytics(days: int = 7) -> Dict[str, Any]:
    """
    Returns per-day action counts for the last N days.
    Used by the dashboard analytics graphs.
    """
    with get_db_session() as db:
        rows = get_actions_last_n_days(db, days=days)

    # Bucket by date and action_type
    buckets: Dict[str, Dict[str, int]] = {}
    for row in rows:
        ts = row.timestamp
        if ts is None:
            continue
        day = ts.strftime("%Y-%m-%d")
        if day not in buckets:
            buckets[day] = {"post": 0, "comment": 0, "connection": 0, "like": 0, "follow": 0}
        atype = row.action_type
        if atype in buckets[day]:
            buckets[day][atype] += 1

    # Sort chronologically and return as a list for charting
    sorted_days = sorted(buckets.keys())
    return {
        "days": sorted_days,
        "series": {
            atype: [buckets[d].get(atype, 0) for d in sorted_days]
            for atype in ("post", "comment", "connection", "like", "follow")
        },
    }


# ── drafts ────────────────────────────────────────────────────────────────────
@app.post("/api/drafts/generate")
async def generate_draft(req: DraftGenerateRequest, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, Any]:
    generated = generate_blog_content(
        topic=req.topic,
        audience=req.audience,
        tone=req.tone,
        length_words=req.length_words,
    )
    with get_db_session() as db:
        draft = create_draft(
            db=db,
            platform="linkedin",
            draft_type="blog",
            topic=req.topic,
            audience=req.audience,
            tone=req.tone,
            title=generated.get("title"),
            content=generated["content"],
            source_provider=generated.get("provider"),
        )
    return {
        "id": draft.id,
        "title": draft.title,
        "content": draft.content,
        "status": draft.status,
        "provider": draft.source_provider,
    }


@app.get("/api/drafts")
async def get_drafts(limit: int = 50) -> Dict[str, Any]:
    with get_db_session() as db:
        rows = list_drafts(db, limit=limit)
    return {
        "items": [
            {
                "id": d.id,
                "platform": d.platform,
                "draft_type": d.draft_type,
                "topic": d.topic,
                "title": d.title,
                "content": d.content,
                "status": d.status,
                "source_provider": d.source_provider,
                "created_at": d.created_at.isoformat() if d.created_at else None,
                "published_at": d.published_at.isoformat() if d.published_at else None,
            }
            for d in rows
        ]
    }


@app.put("/api/drafts/{draft_id}")
async def update_draft(draft_id: int, req: DraftUpdateRequest, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, Any]:
    with get_db_session() as db:
        row = update_draft_content(db, draft_id=draft_id, title=req.title, content=req.content)
        if row is None:
            raise HTTPException(status_code=404, detail="Draft not found")
    return {"id": row.id, "title": row.title, "content": row.content, "status": row.status}


@app.post("/api/drafts/{draft_id}/approve")
async def approve_draft(draft_id: int, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, Any]:
    with get_db_session() as db:
        row = mark_draft_approved(db, draft_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Draft not found")
    return {"id": row.id, "status": row.status, "title": row.title}


@app.post("/api/drafts/{draft_id}/publish")
async def publish_draft(draft_id: int, req: PublishDraftRequest, _: Dict[str, Any] = Depends(_require_auth)) -> Dict[str, Any]:
    if runtime_state.is_running:
        raise HTTPException(status_code=409, detail="Agent currently running. Try again shortly.")

    with get_db_session() as db:
        row = get_draft(db, draft_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Draft not found")
        if row.status != "approved" and not req.force_publish:
            raise HTTPException(
                status_code=409,
                detail="Draft must be approved before publishing. Use force_publish=true to override.",
            )

        content = req.override_content if req.override_content is not None else row.content
        title = req.override_title if req.override_title is not None else row.title
        payload_text = f"{title}\n\n{content}" if title else content

        try:
            result = await execute_linkedin_action(
                db=db,
                action_type="post",
                target_url=req.target_url,
                payload={"text": payload_text},
            )
        except SafetyBlockedError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except SessionExpiredError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        except CaptchaDetectedError as exc:
            raise HTTPException(status_code=503, detail=str(exc))

        if result.get("status") == "success":
            updated = update_draft_content(db, draft_id=row.id, title=title, content=content)
            mark_draft_published(db, draft_id=row.id)
            return {
                "message": "Draft published to LinkedIn",
                "draft_id": row.id,
                "publish_result": result,
                "title": updated.title if updated else title,
            }

        return {
            "message": "Draft publish failed — check /api/logs/errors for details",
            "draft_id": row.id,
            "publish_result": result,
        }


# ── screenshots ────────────────────────────────────────────────────────────────
@app.get("/api/screenshots")
async def list_screenshots() -> Dict[str, Any]:
    """Return a list of screenshot filenames available for the dashboard viewer."""
    from backend.config import DATA_DIR
    screenshots_dir = DATA_DIR / "screenshots"
    if not screenshots_dir.exists():
        return {"items": []}
    files = sorted(screenshots_dir.glob("*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {
        "items": [
            {"name": f.name, "size_kb": round(f.stat().st_size / 1024, 1)}
            for f in files[:30]
        ]
    }


@app.get("/api/screenshots/{filename}")
async def get_screenshot(filename: str):
    """Serve a screenshot PNG from the data/screenshots directory."""
    from fastapi.responses import FileResponse
    from backend.config import DATA_DIR
    # Sanitise filename — no path traversal
    safe_name = filename.replace("..", "").replace("/", "").replace("\\", "")
    path = DATA_DIR / "screenshots" / safe_name
    if not path.exists() or not path.suffix == ".png":
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(str(path), media_type="image/png")
