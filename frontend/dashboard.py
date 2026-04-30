"""
EduBild Social Agent — Monitoring Dashboard v2.0
=================================================
Features:
  • JWT-authenticated login gate
  • Live Feed — real-time text of last posts/comments
  • KPI counters — posts, comments, connections, likes, follows (today + all-time)
  • Heartbeat Pulse — visual indicator; "STUCK" alert if silent > 5 min
  • Action timeout detection
  • Screenshot viewer toggle
  • Analytics graphs (7-day activity charts)
  • All existing tabs preserved: Control, LinkedIn Session, Drafts, Metrics, Logs
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
import streamlit as st

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="EduBild Agent Dashboard",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Pulse animation for heartbeat indicator */
@keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(0, 200, 100, 0.7); }
    70%  { box-shadow: 0 0 0 12px rgba(0, 200, 100, 0); }
    100% { box-shadow: 0 0 0 0 rgba(0, 200, 100, 0); }
}
.pulse-green {
    display: inline-block; width: 14px; height: 14px;
    border-radius: 50%; background: #00c864;
    animation: pulse 1.4s infinite;
    margin-right: 8px; vertical-align: middle;
}
.pulse-red {
    display: inline-block; width: 14px; height: 14px;
    border-radius: 50%; background: #e63946;
    margin-right: 8px; vertical-align: middle;
}
.pulse-grey {
    display: inline-block; width: 14px; height: 14px;
    border-radius: 50%; background: #888;
    margin-right: 8px; vertical-align: middle;
}
.kpi-card {
    background: #1a1a2e; border-radius: 10px; padding: 18px 14px;
    border: 1px solid #2d2d4e; text-align: center;
}
.live-feed-item {
    border-left: 3px solid #00c864; padding-left: 10px;
    margin-bottom: 10px; font-size: 0.88em; color: #ccc;
}
</style>
""", unsafe_allow_html=True)

# ── backend URL ───────────────────────────────────────────────────────────────
_DEFAULT_API = os.getenv("DASHBOARD_API_URL", "http://127.0.0.1:8000").rstrip("/")

TIMEOUT = 8


def _url(path: str) -> str:
    base = st.session_state.get("api_base", _DEFAULT_API).rstrip("/")
    return f"{base}{path}"


def _headers() -> Dict[str, str]:
    """Include JWT Bearer token if logged in."""
    h: Dict[str, str] = {}
    token = st.session_state.get("jwt_token")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(path: str, **kwargs) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(_url(path), timeout=TIMEOUT, headers=_headers(), **kwargs)
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        return None
    except Exception as exc:
        return {"_error": str(exc)}


def _post(path: str, json: Any = None) -> Optional[Dict[str, Any]]:
    try:
        r = requests.post(_url(path), json=json, timeout=TIMEOUT, headers=_headers())
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        return None
    except Exception as exc:
        return {"_error": str(exc)}


def _put(path: str, json: Any = None) -> Optional[Dict[str, Any]]:
    try:
        r = requests.put(_url(path), json=json, timeout=TIMEOUT, headers=_headers())
        r.raise_for_status()
        return r.json()
    except requests.ConnectionError:
        return None
    except Exception as exc:
        return {"_error": str(exc)}


def _is_error(data: Optional[Dict]) -> bool:
    return data is None or "_error" in data


def _err_msg(data: Optional[Dict]) -> str:
    if data is None:
        return "Cannot reach backend — is uvicorn running on the correct port?"
    return data.get("_error", data.get("detail", "Unknown error"))


# ── JWT Login Gate ────────────────────────────────────────────────────────────
def _login_wall() -> bool:
    """
    Show login form if no valid token in session.
    Returns True when authenticated (bypass gate).
    The backend health endpoint is public — we only gate sensitive actions.
    """
    if st.session_state.get("jwt_token"):
        return True

    st.title("🔐 EduBild Agent Dashboard")
    st.markdown("Sign in to access the monitoring dashboard.")
    with st.form("login_form"):
        username = st.text_input("Username", placeholder="admin")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign In", type="primary", use_container_width=True)

    if submitted:
        res = _post("/api/auth/login", json={"username": username, "password": password})
        if res and not _is_error(res) and res.get("access_token"):
            st.session_state["jwt_token"] = res["access_token"]
            st.success("✅ Logged in!")
            st.rerun()
        else:
            st.error(f"Login failed: {_err_msg(res)}")

    st.caption(
        "Default credentials: **admin / edubild2024** "
        "(change via `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` in `.env`)"
    )
    return False


# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("⚙️ Settings")

    if "api_base" not in st.session_state:
        st.session_state.api_base = _DEFAULT_API

    new_base = st.text_input(
        "Backend URL",
        value=st.session_state.api_base,
        help="Must match the port uvicorn is running on. Default: http://127.0.0.1:8000",
    )
    if new_base != st.session_state.api_base:
        st.session_state.api_base = new_base.rstrip("/")
        st.rerun()

    health = _get("/api/health")
    if health and not _is_error(health):
        st.success(f"✅ Backend connected\n{st.session_state.api_base}")
    else:
        st.error(
            "❌ Backend unreachable\n\n"
            f"**URL tried:** `{st.session_state.api_base}`\n\n"
            "**Fix:** Run in a terminal:\n"
            "```\nuvicorn backend.main:app --host 127.0.0.1 --port 8000\n```"
        )

    st.divider()
    cfg = _get("/api/config") or {}
    if not _is_error(cfg):
        st.markdown("**Agent Config**")
        st.code(
            f"Dry run:    {'YES ⚠️' if cfg.get('agent_dry_run') else 'NO  ✓'}\n"
            f"Headless:   {cfg.get('playwright_headless')}\n"
            f"Provider:   {cfg.get('content_provider')}\n"
            f"Interval:   every {cfg.get('agent_interval_hours')}h",
            language=None,
        )

    st.divider()

    if st.session_state.get("jwt_token"):
        if st.button("🚪 Sign Out", use_container_width=True):
            st.session_state.pop("jwt_token", None)
            st.rerun()

    if st.button("🔄 Refresh page", use_container_width=True):
        st.rerun()

    # Auto-refresh
    auto_refresh = st.checkbox("⟳ Auto-refresh every 10s", value=False)


# ── GATE: show login if not authenticated ─────────────────────────────────────
if not _login_wall():
    st.stop()

# ── top status banner ─────────────────────────────────────────────────────────
status = _get("/api/status") or {}
hb_data = _get("/api/heartbeat/last") or {}

col_a, col_b, col_c, col_d = st.columns(4)

if not _is_error(status):
    with col_a:
        running = status.get("agent_running", False)
        st.metric("Agent", "🟢 RUNNING" if running else "⚪ Idle")
    with col_b:
        paused = status.get("automation_paused", False)
        st.metric("Automation", "⏸ PAUSED" if paused else "▶ Active")
    with col_c:
        last_status = status.get("last_run_status", "never")
        icon = {"success": "✅", "failed": "❌", "never": "—"}.get(last_status, "?")
        st.metric("Last run", f"{icon} {last_status}")
    with col_d:
        nxt = status.get("next_scheduled_run")
        st.metric("Next scheduled", nxt.split("T")[1][:5] + " UTC" if nxt else "—")
else:
    st.error(
        f"**Backend connection issue** — {_err_msg(status)}\n\n"
        "👈 Check the sidebar — make sure the **Backend URL** matches uvicorn's port."
    )

# ── Heartbeat Pulse banner ─────────────────────────────────────────────────────
st.divider()
seconds_ago = hb_data.get("seconds_ago")
is_stuck = hb_data.get("stuck", False)
last_action = hb_data.get("action_type", "—")
last_detail = hb_data.get("detail", "")

if seconds_ago is None:
    pulse_html = '<span class="pulse-grey"></span>'
    pulse_label = "No heartbeat recorded yet"
    pulse_color = "info"
elif is_stuck:
    pulse_html = '<span class="pulse-red"></span>'
    pulse_label = f"⚠️ STUCK — last heartbeat {seconds_ago}s ago  ·  last action: {last_action}"
    pulse_color = "error"
else:
    pulse_html = '<span class="pulse-green"></span>'
    pulse_label = f"Agent alive — last heartbeat {seconds_ago}s ago  ·  action: {last_action}"
    if last_detail:
        pulse_label += f"  ({last_detail})"
    pulse_color = "success"

st.markdown(
    f'<div style="display:flex;align-items:center;padding:10px 0;">'
    f'{pulse_html}<span style="font-size:0.95em">{pulse_label}</span></div>',
    unsafe_allow_html=True,
)

if is_stuck:
    st.error(
        "🚨 **Stuck-Agent Alert**: The agent has not reported a heartbeat in over 5 minutes. "
        "It may be blocked by a CAPTCHA, a crash, or a long-running action. "
        "Check the Logs tab or restart the backend."
    )

st.divider()

# ── tabs ──────────────────────────────────────────────────────────────────────
(
    tab_overview,
    tab_control,
    tab_linkedin,
    tab_drafts,
    tab_metrics,
    tab_logs,
) = st.tabs([
    "📡 Overview",
    "🎮 Control",
    "🔗 LinkedIn Session",
    "📝 Drafts",
    "📊 Metrics",
    "📋 Logs",
])


# ═══════════════════════════════════════════════════════════════════
# TAB 0 — OVERVIEW  (Live Feed + KPIs + Analytics + Screenshot Viewer)
# ═══════════════════════════════════════════════════════════════════
with tab_overview:
    m = _get("/api/metrics") or {}
    analytics = _get("/api/metrics/analytics", params={"days": 7}) or {}

    # ── KPI counters (today + all-time) ────────────────────────────
    st.subheader("📈 KPI Counters")

    today_m = m.get("today", {})
    all_time_m = m.get("all_time", {})

    kpi_cols = st.columns(5)
    kpi_defs = [
        ("📝 Posts",       "linkedin_posts",       "total_posts",       "#4cc9f0"),
        ("💬 Comments",    "linkedin_comments",    "total_comments",    "#7bed9f"),
        ("🤝 Connections", "linkedin_connections", "total_connections", "#ffa502"),
        ("❤️ Likes",       "linkedin_likes",       "total_likes",       "#ff6b81"),
        ("➕ Follows",     "linkedin_follows",     "total_follows",     "#a29bfe"),
    ]
    for col, (label, today_key, alltime_key, color) in zip(kpi_cols, kpi_defs):
        with col:
            today_val = today_m.get(today_key, 0)
            alltime_val = all_time_m.get(alltime_key, 0)
            st.markdown(
                f'<div class="kpi-card">'
                f'<div style="font-size:1.6em;font-weight:700;color:{color}">{today_val}</div>'
                f'<div style="font-size:0.78em;color:#aaa">Today</div>'
                f'<div style="font-size:0.9em;color:#ccc;margin-top:6px">{label}</div>'
                f'<div style="font-size:0.72em;color:#666;margin-top:2px">All time: {alltime_val}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Analytics graphs ────────────────────────────────────────────
    st.subheader("📊 7-Day Activity Analytics")

    if not _is_error(analytics) and analytics.get("days"):
        import pandas as pd
        days = analytics["days"]
        series = analytics.get("series", {})

        df_chart = pd.DataFrame({"date": days})
        for action, values in series.items():
            df_chart[action] = values

        df_chart = df_chart.set_index("date")

        ch_left, ch_right = st.columns(2)

        with ch_left:
            st.markdown("**Posts & Comments per day**")
            post_comment_df = df_chart[["post", "comment"]].rename(
                columns={"post": "Posts", "comment": "Comments"}
            )
            st.bar_chart(post_comment_df, use_container_width=True, color=["#4cc9f0", "#7bed9f"])

        with ch_right:
            st.markdown("**Connections · Likes · Follows per day**")
            other_df = df_chart[["connection", "like", "follow"]].rename(
                columns={"connection": "Connections", "like": "Likes", "follow": "Follows"}
            )
            st.bar_chart(other_df, use_container_width=True, color=["#ffa502", "#ff6b81", "#a29bfe"])

        # Line chart: total engagement trend
        st.markdown("**Total daily engagement**")
        df_chart["total"] = df_chart.sum(axis=1)
        st.line_chart(df_chart[["total"]].rename(columns={"total": "Total actions"}), use_container_width=True)
    else:
        st.info("No activity data yet for the last 7 days.")

    st.divider()

    # ── Live Feed ──────────────────────────────────────────────────
    st.subheader("📡 Live Action Feed")
    st.caption("Most recent posts, comments, connections & follows — with the actual text the agent used.")

    recent_actions: List[Dict] = m.get("recent_actions", [])
    if recent_actions:
        feed_items = [
            a for a in recent_actions
            if a.get("action_type") in ("post", "comment", "connection", "follow", "like")
               and a.get("status") == "success"
        ][:15]

        if feed_items:
            for item in feed_items:
                atype = item.get("action_type", "?")
                ts_raw = item.get("timestamp", "")
                ts_display = ts_raw[5:16].replace("T", " ") if ts_raw else "?"
                content = item.get("content_body") or ""
                url = item.get("target_url") or ""
                action_icon = {
                    "post": "📝", "comment": "💬", "connection": "🤝",
                    "follow": "➕", "like": "❤️",
                }.get(atype, "•")

                url_part = f'<a href="{url}" target="_blank" style="color:#667eea;font-size:0.78em">↗ view</a>' if url else ""
                content_preview = f'<div style="color:#ddd;margin-top:4px">{content[:200]}{"…" if len(content) > 200 else ""}</div>' if content else ""

                st.markdown(
                    f'<div class="live-feed-item">'
                    f'<span style="color:#aaa;font-size:0.78em">{ts_display} UTC</span> '
                    f'<strong style="color:#eee">{action_icon} {atype.upper()}</strong> '
                    f'{url_part}'
                    f'{content_preview}'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No successful actions logged yet.")
    else:
        st.info("No actions recorded. Run the agent to see the live feed.")

    st.divider()

    # ── Screenshot Viewer ──────────────────────────────────────────
    with st.expander("📸 Screenshot Viewer (toggle)", expanded=False):
        st.caption("Screenshots taken by the agent during actions — newest first.")
        screenshots = _get("/api/screenshots") or {}
        items = screenshots.get("items", [])

        if items:
            selected = st.selectbox(
                "Select screenshot",
                options=[f["name"] for f in items],
                format_func=lambda n: f"{n}  ({next((f['size_kb'] for f in items if f['name'] == n), '?')} KB)",
            )
            if selected:
                img_url = _url(f"/api/screenshots/{selected}")
                st.image(img_url, caption=selected, use_column_width=True)
        else:
            st.info(
                "No screenshots yet. The agent saves screenshots on action failures to "
                "`data/screenshots/`."
            )

    # ── Action Timeout Detection ───────────────────────────────────
    if status.get("agent_running") and status.get("last_run_started_at"):
        try:
            started_str = status["last_run_started_at"]
            started_dt = datetime.fromisoformat(started_str.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - started_dt).total_seconds()
            if elapsed > 900:  # > 15 minutes
                st.warning(
                    f"⏱️ **Action timeout warning**: The current run has been active for "
                    f"**{int(elapsed // 60)} minutes**. Average agent run is 5–10 min. "
                    "It may be stuck. Check the Logs tab."
                )
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════
# TAB 1 — CONTROL
# ═══════════════════════════════════════════════════════════════════
with tab_control:
    st.header("Agent Control")

    backend_alive = health and not _is_error(health)
    if not backend_alive:
        st.warning("Start the backend first — see the sidebar for instructions.")
        st.stop()

    c1, c2, c3 = st.columns(3)

    with c1:
        st.subheader("Run Agent")
        require_session = st.checkbox("Require LinkedIn session", value=True)
        if st.button("▶ Run Agent Now", type="primary", use_container_width=True):
            with st.spinner("Running agent workflow…"):
                res = _post("/api/runagent", json={"require_linkedin_session": require_session})
            if _is_error(res):
                st.error(f"Run failed: {_err_msg(res)}")
            else:
                run_status = res.get("result", {}).get("status", "?")
                if run_status == "success":
                    st.success("✅ Agent run completed successfully")
                elif run_status == "skipped":
                    st.info(f"Skipped: {res.get('result', {}).get('reason', '')}")
                else:
                    st.error(f"Run finished with status: **{run_status}**\nCheck the Logs tab for details.")
            st.rerun()

    with c2:
        st.subheader("Automation")
        paused = status.get("automation_paused", False)
        if paused:
            if st.button("▶ Resume Automation", use_container_width=True, type="primary"):
                _post("/api/automation/resume")
                st.rerun()
        else:
            if st.button("⏸ Pause Automation", use_container_width=True):
                _post("/api/automation/pause")
                st.rerun()

        sched_running = status.get("scheduler_running", False)
        if sched_running:
            if st.button("⏹ Stop Scheduler", use_container_width=True):
                _post("/api/scheduler/stop")
                st.rerun()
        else:
            if st.button("▶ Start Scheduler", use_container_width=True):
                _post("/api/scheduler/start")
                st.rerun()

    with c3:
        st.subheader("Manual Post")
        manual_text = st.text_area(
            "Post text",
            placeholder="Type or paste your LinkedIn post here…",
            height=120,
        )
        if st.button("📤 Post to LinkedIn", use_container_width=True):
            if not manual_text.strip():
                st.warning("Post text cannot be empty.")
            else:
                with st.spinner("Posting…"):
                    res = _post(
                        "/api/manual/action",
                        json={"action_type": "post", "text": manual_text},
                    )
                if _is_error(res):
                    st.error(f"Post failed: {_err_msg(res)}")
                elif res.get("status") == "success":
                    st.success("✅ Posted to LinkedIn!")
                else:
                    st.error(f"Post failed: {res.get('error', 'unknown error')}")

    st.divider()
    st.subheader("Manual Comment / Connection")
    col_left, col_right = st.columns(2)

    with col_left:
        comment_url = st.text_input("Post URL to comment on")
        comment_text_input = st.text_area("Comment text", height=80)
        if st.button("💬 Send Comment", use_container_width=True):
            if not comment_url or not comment_text_input:
                st.warning("Both URL and comment text are required.")
            else:
                with st.spinner("Commenting…"):
                    res = _post(
                        "/api/manual/action",
                        json={"action_type": "comment", "target_url": comment_url, "text": comment_text_input},
                    )
                if _is_error(res):
                    st.error(f"Comment failed: {_err_msg(res)}")
                elif res.get("status") == "success":
                    st.success("✅ Comment posted!")
                else:
                    st.error(f"Failed: {res.get('error', 'unknown')}")

    with col_right:
        conn_url = st.text_input("Profile URL to connect with")
        conn_note = st.text_area("Connection note (optional)", height=80)
        if st.button("🤝 Send Connection", use_container_width=True):
            if not conn_url:
                st.warning("Profile URL is required.")
            else:
                with st.spinner("Sending connection request…"):
                    res = _post(
                        "/api/manual/action",
                        json={
                            "action_type": "connection",
                            "target_url": conn_url,
                            "text": conn_note if conn_note else None,
                        },
                    )
                if _is_error(res):
                    st.error(f"Connection failed: {_err_msg(res)}")
                elif res.get("status") == "success":
                    st.success("✅ Connection request sent!")
                else:
                    st.error(f"Failed: {res.get('error', 'unknown')}")

    if status.get("last_error"):
        st.divider()
        st.error(f"**Last run error:** {status['last_error']}")


# ═══════════════════════════════════════════════════════════════════
# TAB 2 — LINKEDIN SESSION
# ═══════════════════════════════════════════════════════════════════
with tab_linkedin:
    st.header("LinkedIn Account Access")

    sess = _get("/api/linkedin/session/status") or {}

    col1, col2 = st.columns(2)
    with col1:
        if sess.get("session_exists"):
            st.success("✅ Session file exists on disk")
            st.caption(f"Path: `{sess.get('session_file', '—')}`")
        else:
            st.error("❌ No session file — bootstrap required")

    with col2:
        if st.button("🔍 Check if session is alive", use_container_width=True):
            with st.spinner("Launching headless browser to verify…"):
                check = _get("/api/linkedin/session/check")
            if _is_error(check):
                st.error(f"Check failed: {_err_msg(check)}")
            elif check.get("alive"):
                st.success(f"✅ {check.get('detail', 'Session is valid')}")
            else:
                st.error(f"❌ {check.get('detail', 'Session invalid or expired')}")

    st.divider()
    st.subheader("Bootstrap New Session")
    st.info(
        "This opens a **visible** browser window. Log in to LinkedIn manually. "
        "Once you reach the LinkedIn feed, the session is automatically saved and this window closes."
    )

    timeout_min = st.slider("Login timeout (minutes)", 2, 10, 5)
    if st.button("🔐 Bootstrap LinkedIn Session", type="primary", use_container_width=True):
        with st.spinner(
            f"Browser opening… complete your LinkedIn login within {timeout_min} minutes."
        ):
            res = _post(
                "/api/linkedin/session/bootstrap",
                json={"timeout_minutes": timeout_min},
            )
        if _is_error(res):
            st.error(f"Bootstrap failed: {_err_msg(res)}")
        elif res.get("status") == "success":
            st.success("✅ LinkedIn session saved! You can now run the agent live.")
        else:
            st.error(f"Bootstrap failed: {res.get('message', 'unknown error')}")

    cfg2 = _get("/api/config") or {}
    if cfg2.get("agent_dry_run"):
        st.warning(
            "⚠️ **AGENT_DRY_RUN=true** — even with a valid session, "
            "no real LinkedIn actions will be taken. "
            "Set `AGENT_DRY_RUN=false` in your `.env` and restart the backend to go live."
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
                with st.spinner("Generating content via LLM…"):
                    res = _post(
                        "/api/drafts/generate",
                        json={"topic": g_topic, "audience": g_audience,
                              "tone": g_tone, "length_words": g_words},
                    )
                if _is_error(res):
                    st.error(f"Generation failed: {_err_msg(res)}")
                else:
                    st.success(f"✅ Draft #{res.get('id')} created (provider: {res.get('provider')})")
                    st.rerun()

    st.divider()

    drafts_data = _get("/api/drafts") or {}
    drafts: List[Dict] = drafts_data.get("items", [])

    if not drafts:
        st.info("No drafts yet. Generate one above or run the agent.")
    else:
        for d in drafts:
            status_color = {
                "generated": "🟡", "approved": "🟢", "published": "✅",
            }.get(d.get("status", ""), "⚪")

            with st.expander(
                f"{status_color} #{d['id']} — {d.get('title', 'Untitled')[:70]}  [{d.get('status', '?')}]",
                expanded=False,
            ):
                new_title = st.text_input("Title", value=d.get("title") or "", key=f"title_{d['id']}")
                new_content = st.text_area("Content", value=d.get("content") or "",
                                           height=200, key=f"content_{d['id']}")
                btn1, btn2, btn3 = st.columns(3)

                with btn1:
                    if st.button("💾 Save", key=f"save_{d['id']}", use_container_width=True):
                        res = _put(f"/api/drafts/{d['id']}", json={"title": new_title, "content": new_content})
                        if _is_error(res):
                            st.error(_err_msg(res))
                        else:
                            st.success("Saved ✓")
                            st.rerun()

                with btn2:
                    if d.get("status") == "generated":
                        if st.button("✅ Approve", key=f"approve_{d['id']}", use_container_width=True):
                            res = _post(f"/api/drafts/{d['id']}/approve")
                            if _is_error(res):
                                st.error(_err_msg(res))
                            else:
                                st.success("Approved ✓")
                                st.rerun()

                with btn3:
                    if d.get("status") in ("approved", "generated"):
                        force = d.get("status") == "generated"
                        if st.button("📤 Publish", key=f"publish_{d['id']}", use_container_width=True,
                                     type="primary" if d.get("status") == "approved" else "secondary"):
                            with st.spinner("Publishing to LinkedIn…"):
                                res = _post(
                                    f"/api/drafts/{d['id']}/publish",
                                    json={"force_publish": force, "override_title": new_title,
                                          "override_content": new_content},
                                )
                            if _is_error(res):
                                st.error(f"Publish failed: {_err_msg(res)}")
                            elif "published" in res.get("message", "").lower():
                                st.success("✅ Published to LinkedIn!")
                                st.rerun()
                            else:
                                st.error(f"Publish failed — {res.get('message', '')}. Check Logs tab.")

                if d.get("published_at"):
                    st.caption(f"Published: {d['published_at']}")
                else:
                    st.caption(f"Created: {d.get('created_at', '?')} | Provider: {d.get('source_provider', '?')}")


# ═══════════════════════════════════════════════════════════════════
# TAB 4 — METRICS
# ═══════════════════════════════════════════════════════════════════
with tab_metrics:
    st.header("Today's Metrics")

    m2 = _get("/api/metrics") or {}
    if _is_error(m2):
        st.error(f"Metrics unavailable: {_err_msg(m2)}")
    else:
        today2 = m2.get("today", {})
        c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
        c1.metric("Posts",       today2.get("linkedin_posts", 0))
        c2.metric("Comments",    today2.get("linkedin_comments", 0))
        c3.metric("Connections", today2.get("linkedin_connections", 0))
        c4.metric("Likes",       today2.get("linkedin_likes", 0))
        c5.metric("Follows",     today2.get("linkedin_follows", 0))
        c6.metric("Blocked",     today2.get("blocked_by_limit", 0))
        c7.metric("Errors",      today2.get("errors_or_captcha", 0))

        st.divider()
        st.subheader("Recent Actions")
        recent2 = m2.get("recent_actions", [])
        if recent2:
            import pandas as pd

            df = pd.DataFrame(recent2)
            display_cols = [c for c in ["timestamp", "action_type", "status", "platform",
                                         "target_url", "content_body", "details"] if c in df.columns]
            df = df[display_cols]
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%m-%d %H:%M")

            def _row_color(row):
                if row.status == "success":
                    return ["background-color: #1a3a1a"] * len(row)
                if row.status in ("failed", "captcha_hit"):
                    return ["background-color: #3a1a1a"] * len(row)
                if row.status == "blocked_limit":
                    return ["background-color: #3a2a0a"] * len(row)
                return [""] * len(row)

            st.dataframe(
                df.style.apply(_row_color, axis=1),
                use_container_width=True,
                height=400,
            )
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
        logs_data = _get("/api/logs", params={"limit": limit}) or {}
        lines: List[str] = logs_data.get("items", [])

        if lines:
            formatted = []
            for line in reversed(lines):
                if "ERROR" in line or "CRITICAL" in line:
                    formatted.append(f"🔴 {line}")
                elif "WARNING" in line:
                    formatted.append(f"🟡 {line}")
                elif "step:" in line or "SUCCESS" in line or "✓" in line:
                    formatted.append(f"🟢 {line}")
                elif "screenshot" in line:
                    formatted.append(f"📸 {line}")
                elif "[humanize]" in line or "[human_type]" in line:
                    formatted.append(f"🧠 {line}")
                else:
                    formatted.append(f"   {line}")

            st.code("\n".join(formatted), language=None)
        else:
            st.info("No log lines yet.")

    with err_col:
        st.subheader("⚠️ Errors only")
        err_data = _get("/api/logs/errors") or {}
        err_lines: List[str] = err_data.get("items", [])

        if err_lines:
            for line in reversed(err_lines[-40:]):
                if "ERROR" in line or "CRITICAL" in line:
                    st.error(line, icon="🔴")
                else:
                    st.warning(line, icon="🟡")
        else:
            st.success("No errors — all clear ✅")

    st.divider()
    st.caption(
        "Screenshots taken on action failure are saved to `data/screenshots/`. "
        "View them in the **Overview → Screenshot Viewer** tab."
    )

    if st.button("🗑️ Force-refresh logs", use_container_width=False):
        st.rerun()


# ── Auto-refresh ──────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(10)
    st.rerun()
