from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler


class AgentRuntimeState:
    def __init__(self) -> None:
        self.is_running = False
        self.automation_paused = False
        self.last_run_started_at: Optional[str] = None
        self.last_run_finished_at: Optional[str] = None
        self.last_run_status: str = "never"
        self.last_error: Optional[str] = None
        self.last_result: Dict[str, Any] = {}
        self._lock = Lock()

    def acquire(self) -> bool:
        return self._lock.acquire(blocking=False)

    def release(self) -> None:
        self._lock.release()


runtime_state = AgentRuntimeState()
scheduler = AsyncIOScheduler(timezone="UTC")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
