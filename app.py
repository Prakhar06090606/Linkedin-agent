"""
EduBuild Social Agent Dashboard (Unified Native Architecture)
-------------------------------------------------------------
This script unifies the frontend and backend, bypassing FastAPI 
to prevent Playwright sync timeouts.
"""
from __future__ import annotations

import os
import sys
import time
import asyncio
import pandas as pd
import streamlit as st

# ── Windows/Streamlit Async Fix ──────────────────────────────────────────────
# Streamlit runs in threads. Playwright needs a strict event loop.
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

def run_async(coro):
    """Safely execute async code inside Streamlit's threaded environment."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
    return loop.run_until_complete(coro)

# ── Imports ──────────────────────────────────────────────────────────────────
from backend.config import settings
from backend.scheduler import runtime_state
from backend.database import (
    get_db_session, get_today_metrics, get_recent_actions,
    create_draft, list_drafts, update_draft_content, 
    mark_draft_approved, mark_draft_published
)
from backend.agent.execution import (
    execute_linkedin_action, bootstrap_linkedin_session,
    get_linkedin_session_status, _check_session_alive, _open_browser,
    CaptchaDetectedError, SafetyBlockedError, SessionExpiredError
)
from backend.agent.graph import run_daily_agent_workflow
from backend.agent.content import generate_blog_content
from backend.logging_utils import read_recent_logs, read_error_logs

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="EduBuild Agent",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("⚙️ Settings")
    st.success("✅ Backend connected natively (Unified Mode)")
    st.divider()

    st.markdown("**Agent Config**")
    st.code(
        f"Dry run:    {'YES ⚠️' if settings.agent_dry_run else 'NO  ✓'}\n"
        f"Headless:   {settings.playwright_headless}\n"
        f"Provider:   {settings.content_provider}\n"
        f"Interval:   every {settings.agent_interval_hours}h",
        language=None,
    )

    st.divider()
    if st.button("🔄 Refresh page", use_container_width=True):
        st.rerun()


# ── top status banner ─────────────────────────────────────────────────────────
col_a, col_b, col_c, col_d = st.columns(4)

with col_a:
    running = runtime_state.is_running
    st.metric("Agent", "🟢 RUNNING" if running else "⚪ Idle")
with col_b:
    paused = runtime_state.automation_paused
    st.metric("Automation", "⏸ PAUSED" if paused else "▶ Active")
with col_c:
    last_status = runtime_state.last_run_status
    icon = {"success": "✅", "failed": "❌", "never": "—"}.get(last_status, "?")
    st.metric("Last run", f"{icon} {last_status}")
with col_d:
    st.metric("Next scheduled", "Manual / Unified Mode")

st.divider()

# ── tabs ──────────────────────────────────────────────────────────────────────
tab_control, tab_linkedin, tab_drafts, tab_metrics, tab_logs = st.tabs([
    "🎮 Control", "🔗 LinkedIn Session", "📝 Drafts", "📊 Metrics", "📋 Logs",
])


# ═══════════════════════════════════════════════════════════════════
# TAB 1 — CONTROL
# ═══════════════════════════════════════════════════════════════════
with tab_control:
    st.header("Agent Control")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.subheader("Run Agent")
        require_session = st.checkbox("Require LinkedIn session", value=True)
        if st.button("▶ Run Agent Now", type="primary", use_container_width=True, disabled=running):
            st.session_state.agent_running = True
            with st.spinner("Running agent workflow…"):
                try:
                    with get_db_session() as db:
                        result = run_async(run_daily_agent_workflow(db))
                    st.success("✅ Agent run completed successfully")
                except Exception as e:
                    st.error(f"Run failed: {str(e)}")
            st.rerun()

    with c2:
        st.subheader("Automation")
        if paused:
            if st.button("▶ Resume Automation", use_container_width=True, type="primary"):
                runtime_state.automation_paused = False
                st.rerun()
        else:
            if st.button("⏸ Pause Automation", use_container_width=True):
                runtime_state.automation_paused = True
                st.rerun()

    with c3:
        st.subheader("Manual Post")
        manual_text = st.text_area(
            "Post text",
            placeholder="Type or paste your LinkedIn post here…",
            height=120,
        )
        if st.button("📤 Post to LinkedIn", use_container_width=True, disabled=running):
            if not manual_text.strip():
                st.warning("Post text cannot be empty.")
            else:
                with st.spinner("Posting…"):
                    try:
                        with get_db_session() as db:
                            res = run_async(execute_linkedin_action(db, "post", payload={"text": manual_text}))
                        st.success("✅ Posted to LinkedIn!")
                    except Exception as e:
                        st.error(f"Post failed: {str(e)}")

    st.divider()
    st.subheader("Manual Comment / Connection")
    col_left, col_right = st.columns(2)

    with col_left:
        comment_url = st.text_input("Post URL to comment on")
        comment_text = st.text_area("Comment text", height=80)
        if st.button("💬 Send Comment", use_container_width=True, disabled=running):
            if not comment_url or not comment_text:
                st.warning("Both URL and comment text are required.")
            else:
                with st.spinner("Commenting…"):
                    try:
                        with get_db_session() as db:
                            res = run_async(execute_linkedin_action(db, "comment", target_url=comment_url, payload={"text": comment_text}))
                        st.success("✅ Comment posted!")
                    except Exception as e:
                        st.error(f"Failed: {str(e)}")

    with col_right:
        conn_url = st.text_input("Profile URL to connect with")
        conn_note = st.text_area("Connection note (optional)", height=80)
        if st.button("🤝 Send Connection", use_container_width=True, disabled=running):
            if not conn_url:
                st.warning("Profile URL is required.")
            else:
                with st.spinner("Sending connection request…"):
                    try:
                        with get_db_session() as db:
                            res = run_async(execute_linkedin_action(db, "connection", target_url=conn_url, payload={"note": conn_note}))
                        st.success("✅ Connection request sent!")
                    except Exception as e:
                        st.error(f"Failed: {str(e)}")


# ═══════════════════════════════════════════════════════════════════
# TAB 2 — LINKEDIN SESSION
# ═══════════════════════════════════════════════════════════════════
with tab_linkedin:
    st.header("LinkedIn Account Access")

    sess = get_linkedin_session_status()

    col1, col2 = st.columns(2)
    with col1:
        if sess.get("session_exists"):
            st.success("✅ Session file exists on disk")
            st.caption(f"Path: `{sess.get('session_file', '—')}`")
        else:
            st.error("❌ No session file — bootstrap required")

    with col2:
        if st.button("🔍 Check if session is alive", use_container_width=True, disabled=running):
            with st.spinner("Launching headless browser to verify…"):
                try:
                    pw, browser, context, page = run_async(_open_browser())
                    alive = run_async(_check_session_alive(page))
                    if alive:
                        st.success("✅ Session is valid")
                    else:
                        st.error("❌ Session invalid or expired")
                except Exception as e:
                    st.error(f"Check failed: {str(e)}")
                finally:
                    if 'context' in locals(): run_async(context.close())
                    if 'browser' in locals(): run_async(browser.close())
                    if 'pw' in locals(): run_async(pw.stop())

    st.divider()
    st.subheader("Bootstrap New Session")
    st.info(
        "This opens a **visible** browser window. Log in to LinkedIn manually. "
        "Once you reach the LinkedIn feed, the session is automatically saved and this window closes."
    )

    timeout_min = st.slider("Login timeout (minutes)", 2, 10, 5)
    
    if st.button("🔐 Bootstrap LinkedIn Session", type="primary", use_container_width=True, disabled=running):
        with st.spinner(f"Browser opening… complete your LinkedIn login within {timeout_min} minutes."):
            res = run_async(bootstrap_linkedin_session(timeout_minutes=timeout_min))
            if res.get("status") == "success":
                st.success("✅ LinkedIn session saved! You can now run the agent live.")
            else:
                st.error(f"Bootstrap failed: {res.get('message', 'unknown error')}")

    if settings.agent_dry_run:
        st.warning(
            "⚠️ **AGENT_DRY_RUN=true** — even with a valid session, "
            "no real LinkedIn actions will be taken. "
            "Set `AGENT_DRY_RUN=false` in your `.env` file to go live."
        )


# ═══════════════════════════════════════════════════════════════════
# TAB 3 — DRAFTS
# ═══════════════════════════════════════════════════════════════════
with tab_drafts:
    st.header("Blog Studio — Drafts")

    with st.expander("✨ Generate New Draft", expanded=False):
        g_topic = st.text_input("Topic", placeholder="How AI is reshaping professional upskilling")
        g_audience = st.text_input("Audience", value="working professionals")
        g_tone = st.selectbox("Tone", ["professional", "casual", "inspiring", "technical"])
        g_words = st.slider("Approx. word count", 100, 400, 180)
        if st.button("🤖 Generate Draft", type="primary"):
            if not g_topic.strip():
                st.warning("Topic is required.")
            else:
                with st.spinner("Generating content via Gemini…"):
                    generated = generate_blog_content(g_topic, g_audience, g_tone, g_words)
                    with get_db_session() as db:
                        draft = create_draft(db, "linkedin", "blog", generated["content"], generated.get("title"), g_topic, g_audience, g_tone, generated.get("provider"))
                    st.success(f"✅ Draft #{draft.id} created!")
                    st.rerun()

    st.divider()

    with get_db_session() as db:
        drafts = list_drafts(db, limit=50)

    if not drafts:
        st.info("No drafts yet. Generate one above or run the agent.")
    else:
        for d in drafts:
            status_color = {"generated": "🟡", "approved": "🟢", "published": "✅"}.get(d.status, "⚪")

            with st.expander(f"{status_color} #{d.id} — {str(d.title)[:70]} [{d.status}]", expanded=False):
                new_title = st.text_input("Title", value=d.title or "", key=f"title_{d.id}")
                new_content = st.text_area("Content", value=d.content or "", height=200, key=f"content_{d.id}")

                btn1, btn2, btn3 = st.columns(3)

                with btn1:
                    if st.button("💾 Save", key=f"save_{d.id}", use_container_width=True):
                        with get_db_session() as db:
                            update_draft_content(db, d.id, new_title, new_content)
                        st.success("Saved ✓")
                        st.rerun()

                with btn2:
                    if d.status == "generated":
                        if st.button("✅ Approve", key=f"approve_{d.id}", use_container_width=True):
                            with get_db_session() as db:
                                mark_draft_approved(db, d.id)
                            st.success("Approved ✓")
                            st.rerun()

                with btn3:
                    if d.status in ("approved", "generated"):
                        if st.button("📤 Publish", key=f"publish_{d.id}", use_container_width=True, type="primary" if d.status == "approved" else "secondary", disabled=running):
                            with st.spinner("Publishing to LinkedIn…"):
                                try:
                                    with get_db_session() as db:
                                        payload_text = f"{new_title}\n\n{new_content}" if new_title else new_content
                                        run_async(execute_linkedin_action(db, "post", payload={"text": payload_text}))
                                        mark_draft_published(db, d.id)
                                    st.success("✅ Published to LinkedIn!")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Publish failed: {str(e)}")


# ═══════════════════════════════════════════════════════════════════
# TAB 4 — METRICS
# ═══════════════════════════════════════════════════════════════════
with tab_metrics:
    st.header("Today's Metrics")

    with get_db_session() as db:
        today = get_today_metrics(db)
        recent = get_recent_actions(db, limit=50)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Posts", today.get("linkedin_posts", 0))
    c2.metric("Comments", today.get("linkedin_comments", 0))
    c3.metric("Connections", today.get("linkedin_connections", 0))
    c4.metric("Blocked by limit", today.get("blocked_by_limit", 0))
    c5.metric("Errors", today.get("errors_or_captcha", 0))

    st.divider()
    st.subheader("Recent Actions")
    if recent:
        df = pd.DataFrame([{
            "timestamp": r.timestamp, "action_type": r.action_type, 
            "status": r.status, "platform": r.platform, "target_url": r.target_url, "details": r.details
        } for r in recent])
        
        df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%m-%d %H:%M")

        def _row_color(row):
            if row.status == "success": return ["background-color: #1a3a1a"] * len(row)
            if row.status in ("failed", "captcha_hit"): return ["background-color: #3a1a1a"] * len(row)
            if row.status == "blocked_limit": return ["background-color: #3a2a0a"] * len(row)
            return [""] * len(row)

        st.dataframe(df.style.apply(_row_color, axis=1), use_container_width=True, height=350)
    else:
        st.info("No actions recorded yet.")


# ═══════════════════════════════════════════════════════════════════
# TAB 5 — LOGS
# ═══════════════════════════════════════════════════════════════════
with tab_logs:
    st.header("Live Logs")
    log_col, err_col = st.columns([2, 1])

    with log_col:
        st.subheader("All logs")
        limit = st.slider("Lines to show", 50, 500, 200, key="log_limit")
        lines = read_recent_logs(limit)

        if lines:
            formatted = []
            for line in reversed(lines):
                if "ERROR" in line or "CRITICAL" in line: formatted.append(f"🔴 {line}")
                elif "WARNING" in line: formatted.append(f"🟡 {line}")
                elif "step:" in line or "SUCCESS" in line or "✓" in line: formatted.append(f"🟢 {line}")
                elif "screenshot" in line: formatted.append(f"📸 {line}")
                else: formatted.append(f"   {line}")
            st.code("\n".join(formatted), language=None)
        else:
            st.info("No log lines yet.")

    with err_col:
        st.subheader("⚠️ Errors only")
        err_lines = read_error_logs()
        if err_lines:
            for line in reversed(err_lines[-40:]):
                if "ERROR" in line or "CRITICAL" in line: st.error(line, icon="🔴")
                else: st.warning(line, icon="🟡")
        else:
            st.success("No errors — all clear ✅")

    st.divider()
    auto_refresh = st.checkbox("Auto-refresh logs every 5s")
    if auto_refresh:
        time.sleep(5)
        st.rerun()