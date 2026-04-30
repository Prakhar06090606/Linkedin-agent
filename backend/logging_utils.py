from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import List

from backend.config import DATA_DIR

LOG_FILE = DATA_DIR / "agent.log"
LOGGER_NAME = "edubild_agent"

# ── custom formatter ───────────────────────────────────────────────────────────
class _Formatter(logging.Formatter):
    """Adds level icons so log lines are scannable at a glance."""
    _ICONS = {
        "DEBUG":    "·",
        "INFO":     "»",
        "WARNING":  "⚠",
        "ERROR":    "✖",
        "CRITICAL": "☠",
    }

    def format(self, record: logging.LogRecord) -> str:
        icon = self._ICONS.get(record.levelname, " ")
        record.icon = icon
        return super().format(record)


def setup_logging() -> logging.Logger:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)   # capture DEBUG so step traces are stored
    logger.propagate = False

    if logger.handlers:
        return logger

    fmt = _Formatter(
        "%(asctime)s | %(levelname)-8s | %(icon)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── rotating file — keeps last 3 × 5 MB = 15 MB of history ──
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    # ── console — only INFO+ so terminal isn't spammy ──
    # Reconfigure stdout to UTF-8 on Windows so Unicode log icons (✓, ⚠, →) don't
    # crash when stdout is redirected to a file (default cp1252 can't encode them).
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    stream_handler.setLevel(logging.INFO)
    logger.addHandler(stream_handler)

    return logger


def read_recent_logs(limit: int = 300) -> List[str]:
    """Return the last `limit` lines from the log file."""
    if not LOG_FILE.exists():
        return ["[no log file yet]"]
    lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max(1, limit):]


def read_error_logs(limit: int = 100) -> List[str]:
    """Return only WARNING / ERROR / CRITICAL lines — useful for the dashboard."""
    if not LOG_FILE.exists():
        return []
    result = []
    for line in LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        if any(lvl in line for lvl in ("WARNING", "ERROR", "CRITICAL")):
            result.append(line)
    return result[-max(1, limit):]
