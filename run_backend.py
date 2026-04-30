"""
Backend startup script.
Sets WindowsProactorEventLoopPolicy BEFORE uvicorn creates the event loop,
which is required for Playwright to launch browser subprocesses on Python 3.13+.
"""
import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
    )
