"""
LangGraph state machine: plan → generate → execute

Flow:
  plan_actions      → decides what to do (post/comment/connect)
  generate_content  → writes post text; marks comments/connections as AUTO
  execute_actions   → runs Playwright; auto-generates comment/note from live profile/post scrape
"""
from __future__ import annotations

from typing import Any, Dict, List, TypedDict

from langgraph.graph import END, StateGraph
from sqlalchemy.orm import Session

from backend.agent.content import generate_agent_topic, generate_blog_content, generate_post_image
import backend.agent.execution as _execution_module
from backend.agent.execution import (
    SafetyBlockedError, SessionExpiredError,
    execute_linkedin_action,
    _open_browser, _check_session_alive,
    _humanize_text,
)
from backend.config import settings


class AgentState(TypedDict, total=False):
    requested_actions: List[Dict[str, Any]]
    execution_results: List[Dict[str, Any]]


_active_db: Session | None = None


def _csv_urls(raw: str) -> list[str]:
    """Parse comma-separated URL list from config, ignoring blanks."""
    return [u.strip() for u in raw.split(",") if u.strip()]


# ── Node 1: Plan ──────────────────────────────────────────────────────────────

def plan_actions(state: AgentState) -> AgentState:
    """Decide what actions to take this run."""
    topic_result = generate_agent_topic()
    auto_topic = topic_result.get("topic", settings.agent_post_topic)
    category_id = topic_result.get("category_id", "ai_general")
    category_label = topic_result.get("category_label", "AI")

    actions: list[dict[str, Any]] = [
        # 1. Publish a post on the feed
        {
            "action_type": "post",
            "target_url": "https://www.linkedin.com/feed/",
            "topic": auto_topic,
            "category_id": category_id,
            "category_label": category_label,
            "audience": settings.agent_post_audience,
            "tone": settings.agent_post_tone,
            "length_words": 200,
            "payload": {"topic_provider": topic_result.get("provider", "template")},
        },
        # 2. Discover & engage — agent autonomously finds posts to comment on,
        #    people to connect with, and companies to follow (all relevant to the
        #    current category). Deduped against DB — never repeats targets.
        {
            "action_type": "discover_and_engage",
            "target_url": None,
            "payload": {
                "category_id": category_id,
                "category_label": category_label,
            },
        },
    ]

    return {"requested_actions": actions, "execution_results": []}


# ── Node 2: Generate post content ─────────────────────────────────────────────

def generate_post_content(state: AgentState) -> AgentState:
    """Generate the full post text for any post actions."""
    from backend.agent.content import TOPIC_CATEGORIES

    requested = state.get("requested_actions", [])
    for action in requested:
        if action.get("action_type") != "post":
            continue

        # Find the matching category dict for richer content prompts
        cat_id = action.get("category_id", "")
        category = next(
            (c for c in TOPIC_CATEGORIES if c["id"] == cat_id), None
        )

        generated = generate_blog_content(
            topic=action.get("topic", "EduBild update"),
            audience=action.get("audience", "professionals"),
            tone=action.get("tone", "professional"),
            length_words=int(action.get("length_words", 200)),
            category=category,
        )

        title = generated.get("title", "")
        content = generated.get("content", "")
        raw_text = f"{title}\n\n{content}" if title and not content.startswith(title) else content
        # Pass through humanizer to strip AI writing patterns before publishing
        humanized_text = _humanize_text(raw_text)

        # Generate a relevant image for the post using Gemini imagen
        image_path = generate_post_image(
            topic=action.get("topic", title),
            category_id=cat_id,
        )

        action["payload"] = {
            "text": humanized_text,
            "source_provider": generated.get("provider", "template"),
            "category": action.get("category_label", ""),
            "image_path": image_path,  # None if generation failed (post without image)
        }

    return {
        "requested_actions": requested,
        "execution_results": state.get("execution_results", []),
    }


# ── Node 3: Execute ───────────────────────────────────────────────────────────

async def execute_actions(state: AgentState) -> AgentState:
    """
    Run each planned action via Playwright — ONE shared browser for the entire run.

    Opening a single browser and keeping it alive across all actions (post + discover)
    prevents LinkedIn from flagging the session as expired between actions, which was
    happening when each action opened/closed its own separate browser instance.
    """
    import logging
    import traceback
    logger = logging.getLogger("edubild_agent")

    requested = state.get("requested_actions", [])
    results = []

    if _active_db is None:
        return {
            "requested_actions": requested,
            "execution_results": [{"status": "failed", "error": "Database session not available"}],
        }

    # Reset key rotation index at the start of each run so key[0] is tried first
    _execution_module._gemini_key_index = 0

    pw = browser = context = page = None
    try:
        pw, browser, context, page = await _open_browser()
        if not await _check_session_alive(page):
            raise SessionExpiredError("LinkedIn session expired. Re-bootstrap from dashboard.")

        for action in requested:
            try:
                result = await execute_linkedin_action(
                    db=_active_db,
                    action_type=action["action_type"],
                    target_url=action.get("target_url"),
                    payload=action.get("payload"),
                    shared_page=page,  # reuse the same browser page
                )
            except SafetyBlockedError as exc:
                result = {
                    "action_type": action["action_type"],
                    "status": "blocked_limit",
                    "error": str(exc),
                }
            except SessionExpiredError:
                raise  # bubble up — session gone, nothing more can be done
            results.append(result)

    finally:
        # Close the single shared browser once all actions are done
        for resource, name, method in [
            (context, "context", "close"),
            (browser, "browser", "close"),
            (pw,      "playwright", "stop"),
        ]:
            if resource is not None:
                try:
                    await getattr(resource, method)()
                    logger.debug("[browser] %s %s", name, method + "d")
                except Exception as e:
                    logger.warning("[browser] %s %s failed: %s", name, method, e)

    return {"requested_actions": requested, "execution_results": results}


# ── Graph assembly ────────────────────────────────────────────────────────────

def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("plan", plan_actions)
    graph.add_node("generate", generate_post_content)
    graph.add_node("execute", execute_actions)

    graph.set_entry_point("plan")
    graph.add_edge("plan", "generate")
    graph.add_edge("generate", "execute")
    graph.add_edge("execute", END)

    return graph.compile()


async def run_daily_agent_workflow(db: Session) -> Dict[str, Any]:
    global _active_db
    app = build_graph()
    _active_db = db
    try:
        final_state = await app.ainvoke({"requested_actions": [], "execution_results": []})
        return final_state
    finally:
        _active_db = None
