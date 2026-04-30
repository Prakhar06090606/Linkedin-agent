"""
Content generation for EduBild LinkedIn agent.
Rotates across 6 topic categories using Gemini.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from backend.config import settings, DATA_DIR
from backend.agent.prompts import (
    POST_CREATOR_PROMPT,
    TOPIC_GENERATOR_PROMPT,
)

# ── Used-topic memory ─────────────────────────────────────────────────────────
# Keeps the last 30 used topic titles so we never repeat them in consecutive runs.
_USED_TOPICS_FILE = DATA_DIR / "used_topics.json"
_MAX_USED_TOPICS = 30  # rolling window


def _load_used_topics() -> List[str]:
    try:
        if _USED_TOPICS_FILE.exists():
            return json.loads(_USED_TOPICS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def _save_used_topic(topic: str) -> None:
    used = _load_used_topics()
    if topic and topic not in used:
        used.append(topic)
    # Keep only the most recent N
    used = used[-_MAX_USED_TOPICS:]
    try:
        _USED_TOPICS_FILE.write_text(json.dumps(used, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── LLM helper with key rotation ─────────────────────────────────────────────
# content.py uses the same key pool as execution.py (_call_gemini).
# We share the rotation state via execution module so both callers advance
# the same index when a key is exhausted.

def _gemini_chat(prompt: str, system: str, temperature: float = 0.8) -> str | None:
    """
    Call Gemini. Delegates to execution._call_gemini so key rotation is shared
    with comment/post/connection note generation.
    """
    try:
        from backend.agent.execution import _call_gemini
        return _call_gemini(prompt, system, temperature)
    except Exception as e:
        print(f"[content] Gemini call failed: {e}")
        return None


# ── Topic categories ──────────────────────────────────────────────────────────
# 6 rotating categories. Agent picks one per run based on day + run index.

TOPIC_CATEGORIES = [
    {
        "id": "ai_general",
        "label": "AI Trends & Technology",
        "topic_prompt": (
            "Generate exactly one specific, compelling LinkedIn post topic about AI. "
            "Cover a real concept: AI agents, multimodal models, RAG pipelines, LLM fine-tuning, "
            "AI infrastructure, reasoning models, AI safety, or AI tooling. "
            "Be precise and specific — NOT vague like 'The power of AI'. "
            "Output only the topic title."
        ),
        "content_prompt": (
            "Write a LinkedIn post about the following AI topic: {topic}\n\n"
            "Audience: tech-savvy professionals, AI practitioners, product managers\n"
            "Include a specific insight, implication, or example. Keep it thought-provoking."
        ),
        "fallback_topics": [
            "Why AI Agents Are the Next Big Shift After LLMs",
            "RAG vs Fine-tuning: When to Use Which for Production AI",
            "The Hidden Cost of Running LLMs at Scale",
            "Multimodal AI: What It Means for Knowledge Work",
            "AI Reasoning Models Are Changing How We Build Products",
        ],
    },
    {
        "id": "education",
        "label": "AI in Education",
        "topic_prompt": (
            "Generate exactly one specific LinkedIn post topic about AI transforming education, "
            "learning, skill development, EdTech, or career readiness. "
            "Be specific — e.g., 'How AI tutors are personalizing STEM learning' not just 'AI in education'. "
            "Output only the topic title."
        ),
        "content_prompt": (
            "Write a LinkedIn post about this education + AI topic: {topic}\n\n"
            "Audience: educators, HR leaders, students, EdTech professionals, and career coaches\n"
            "Include a practical angle — what this means for learners or institutions."
        ),
        "fallback_topics": [
            "How AI Is Closing the Skill Gap Between Colleges and Employers",
            "AI Mock Interviews: The New Equalizer for First-Generation Job Seekers",
            "Why Skill Assessments Are Replacing Degrees in Modern Hiring",
            "The Role of AI in Making Career Guidance Actually Personal",
            "EdTech's Next Phase: From Content Delivery to Outcome Measurement",
        ],
    },
    {
        "id": "ai_fintech",
        "label": "AI in Fintech",
        "topic_prompt": (
            "Generate exactly one specific LinkedIn post topic about AI in financial services — "
            "credit scoring, fraud detection, algorithmic lending, insurance AI, risk management, "
            "AI-driven compliance (RegTech), or financial inclusion via AI. "
            "Be specific and professional. Output only the topic title."
        ),
        "content_prompt": (
            "Write a LinkedIn post about this AI + fintech topic: {topic}\n\n"
            "Audience: fintech professionals, bankers, risk managers, investors, and AI practitioners\n"
            "Include concrete implications — what changes, who benefits, what the risks are."
        ),
        "fallback_topics": [
            "How AI Credit Scoring Is Expanding Lending to the Underbanked",
            "Real-Time Fraud Detection: Why AI Is Outpacing Rules-Based Systems",
            "The Compliance Challenge: Using AI in Regulated Financial Environments",
            "AI in Insurance: From Underwriting to Claims — What's Changing",
            "Algorithmic Lending and the Bias Problem — What Fintechs Need to Fix",
        ],
    },
    {
        "id": "ai_hiring",
        "label": "AI in Hiring & Recruitment",
        "topic_prompt": (
            "Generate exactly one specific LinkedIn post topic about AI transforming recruitment, "
            "talent acquisition, skill-based hiring, candidate screening, HR tech, "
            "or the changing relationship between job seekers and employers. "
            "Be specific and timely. Output only the topic title."
        ),
        "content_prompt": (
            "Write a LinkedIn post about this AI + hiring topic: {topic}\n\n"
            "Audience: HR leaders, recruiters, talent acquisition professionals, and job seekers\n"
            "Include a practical perspective — what this means for hiring teams or candidates."
        ),
        "fallback_topics": [
            "Why AI Is Shifting Hiring From Resume Screening to Skill Verification",
            "The 90% Time-to-Hire Reduction: What AI Is Actually Doing Differently",
            "How AI Interviews Are Removing Interviewer Bias From Early Screening",
            "Skill-Based Hiring: The Move Away From Pedigree That AI Is Accelerating",
            "What Recruiters Need to Know About AI-Powered Candidate Assessment",
        ],
    },
    {
        "id": "ai_news",
        "label": "Latest AI News & Updates",
        "topic_prompt": (
            "Generate exactly one LinkedIn post topic based on a notable AI development from 2024–2025 — "
            "a major model release (GPT-5, Gemini 2.0, Claude 3.5, Llama 3, Mistral), "
            "a research breakthrough, a regulatory development (EU AI Act), "
            "or a major industry shift that professionals need to know about. "
            "Be specific and name the actual development. Output only the topic title."
        ),
        "content_prompt": (
            "Write a LinkedIn post covering this AI news or development: {topic}\n\n"
            "Audience: professionals across tech, HR, finance, and education who follow AI trends\n"
            "Frame it as important news — explain what happened, why it matters, "
            "and what the implications are for professionals and businesses."
        ),
        "fallback_topics": [
            "What the EU AI Act Means for Businesses Using AI in Hiring",
            "Gemini 2.5 Flash: What the Latest Google AI Release Changes",
            "OpenAI's o3 Reasoning Model: A New Benchmark for AI Problem Solving",
            "Meta's Llama 3: Why Open-Source AI Is Changing the Competitive Landscape",
            "The Rise of AI Agents in 2025: From Demos to Real Deployment",
        ],
    },
    {
        "id": "edubild",
        "label": "EduBild Mission & Impact",
        "topic_prompt": (
            "Generate exactly one LinkedIn post topic specifically about EduBild's impact — "
            "choose one angle: AI-powered mock interviews that build real confidence, "
            "skill gap assessment helping students become job-ready, cutting time-to-hire by 90% for employers, "
            "connecting students from tier-2/3 colleges to top employers, "
            "or AI-driven personalized career guidance. "
            "Make it authentic and value-driven — NOT salesy. Output only the topic title."
        ),
        "content_prompt": (
            "Write a LinkedIn post about this EduBild topic: {topic}\n\n"
            "This is a brand post for EduBild (https://www.edubild.com). "
            "Mention EduBild naturally — focus on the value for students or employers. "
            "Audience: students, HR professionals, recruiters, educators, and EdTech investors."
        ),
        "fallback_topics": [
            "How EduBild's AI Mock Interviews Are Helping Students Land Their First Jobs",
            "Why EduBild Is Helping Employers Cut Time-to-Hire by 90% With AI",
            "The Skill Gap Problem: How EduBild Turns Assessment Into Action",
            "From Campus to Career: EduBild's AI-Driven Approach to Job Readiness",
            "Why India's Top Employers Are Turning to EduBild for Smarter Hiring",
        ],
    },
]


def _get_category_for_run() -> dict:
    """
    Pick a topic category for this run.
    Rotates through all 6 categories, cycling by day + minute so consecutive
    manual triggers within the same hour still pick different categories.
    """
    now = datetime.now(timezone.utc)
    # Use minute-level entropy so rapid triggers get different categories
    entropy = now.timetuple().tm_yday * 1440 + now.hour * 60 + now.minute
    index = entropy % len(TOPIC_CATEGORIES)
    return TOPIC_CATEGORIES[index]


def generate_agent_topic() -> Dict[str, str]:
    """Generate a unique topic title, never repeating the last 30 used topics."""
    category = _get_category_for_run()
    used_topics = _load_used_topics()

    # Try Gemini first — ask it to avoid the recently used topics
    avoid_list = "\n".join(f"- {t}" for t in used_topics[-10:]) if used_topics else "None"
    topic = _gemini_chat(
        prompt=(
            f"{category['topic_prompt']}\n\n"
            f"IMPORTANT: Do NOT generate any of these recently used topics:\n{avoid_list}\n"
            f"Pick something genuinely different and specific."
        ),
        system=TOPIC_GENERATOR_PROMPT,
        temperature=0.95,
    )

    if topic and topic.strip() not in used_topics:
        _save_used_topic(topic.strip())
        return {
            "topic": topic.strip(),
            "category_id": category["id"],
            "category_label": category["label"],
            "provider": "gemini",
        }

    # Fallback: pick a fallback topic that hasn't been used recently
    available = [t for t in category["fallback_topics"] if t not in used_topics]
    if not available:
        # All exhausted — reset and use any
        available = category["fallback_topics"]
    fallback = random.choice(available)
    _save_used_topic(fallback)
    return {
        "topic": fallback,
        "category_id": category["id"],
        "category_label": category["label"],
        "provider": "template",
    }


def generate_post_image(topic: str, category_id: str = "") -> Optional[str]:
    """
    Generate a relevant image for the LinkedIn post.

    Tries image models in this order:
      1. Nano Banana      — gemini-2.5-flash-image
      2. Nano Banana 2    — gemini-3.1-flash-image-preview
      3. Nano Banana Pro  — gemini-3-pro-image-preview
      4. Imagen 4         — imagen-4.0-generate-001 (25 RPD dedicated model)

    Returns the path to the saved PNG, or None if all models fail.
    """
    import base64, time
    from google import genai
    from google.genai import types

    try:
        from backend.agent.execution import _get_gemini_keys, _gemini_key_index
    except Exception:
        return None

    keys = _get_gemini_keys()
    if not keys:
        return None

    key = keys[_gemini_key_index % len(keys)]

    visual_prompt = (
        f"Create a clean, professional LinkedIn post image about: {topic}. "
        "Style: modern flat design, minimal text, professional colour palette "
        "(deep blue, white, light grey). Include subtle visual metaphors relevant "
        "to the topic — e.g. neural network nodes for AI, graduation cap for education, "
        "chart/graph for data. No stock-photo faces. No text overlay needed. "
        "16:9 aspect ratio, high contrast, suitable for LinkedIn feed."
    )

    img_dir = DATA_DIR / "post_images"
    img_dir.mkdir(parents=True, exist_ok=True)

    # ── Attempt 1 & 2: Gemini multimodal image models (Nano Banana family) ──
    gemini_image_models = [
        "gemini-2.5-flash-image",       # Nano Banana (Gemini 2.5 Flash Image)
        "gemini-3.1-flash-image-preview",  # Nano Banana 2
        "gemini-3-pro-image-preview",      # Nano Banana Pro
    ]
    for model in gemini_image_models:
        try:
            client = genai.Client(api_key=key)
            response = client.models.generate_content(
                model=model,
                contents=visual_prompt,
                config=types.GenerateContentConfig(
                    response_modalities=["TEXT", "IMAGE"],
                ),
            )
            for part in response.candidates[0].content.parts:
                if hasattr(part, "inline_data") and part.inline_data is not None:
                    img_bytes = base64.b64decode(part.inline_data.data)
                    fname = img_dir / f"post_{int(time.time())}.png"
                    fname.write_bytes(img_bytes)
                    print(f"[content] image generated via {model} -> {fname.name}")
                    return str(fname)
        except Exception as e:
            print(f"[content] {model} failed: {str(e)[:120]}")
            continue

    # ── Attempt 3: Imagen 4 (dedicated image API, 25 RPD) ────────────────────
    try:
        client = genai.Client(api_key=key)
        response = client.models.generate_images(
            model="imagen-4.0-generate-001",
            prompt=visual_prompt,
            config=types.GenerateImagesConfig(number_of_images=1),
        )
        if response.generated_images:
            img_bytes = response.generated_images[0].image.image_bytes
            fname = img_dir / f"post_{int(time.time())}.png"
            fname.write_bytes(img_bytes)
            print(f"[content] image generated via imagen-4 -> {fname.name}")
            return str(fname)
    except Exception as e:
        print(f"[content] imagen-4 failed: {str(e)[:120]}")

    print("[content] all image models failed — posting without image")
    return None


def generate_blog_content(
    topic: str,
    audience: str = "professionals",
    tone: str = "professional",
    length_words: int = 200,
    category: Optional[dict] = None,
) -> Dict[str, str]:
    """Generate a full LinkedIn post for the given topic."""

    # Build content prompt — use category-specific prompt if available
    if category and "content_prompt" in category:
        content_prompt = category["content_prompt"].format(topic=topic)
    else:
        content_prompt = (
            f"Write a LinkedIn post about: {topic}\n\n"
            f"Audience: {audience}\n"
            f"Tone: {tone}\n"
            f"Target length: ~{length_words} words"
        )

    text = _gemini_chat(
        prompt=content_prompt,
        system=POST_CREATOR_PROMPT,
        temperature=0.8,
    )

    if text:
        return {"title": topic, "content": text, "provider": "gemini"}

    # Fallback template
    return _template_content(topic, audience, tone, length_words)


def _template_content(topic: str, audience: str, tone: str, length_words: int) -> Dict[str, str]:
    """Hardcoded fallback post when Gemini is unavailable."""
    body = (
        f"At EduBild, we believe that {topic.lower()} is one of the most important conversations "
        f"happening in professional development right now.\n\n"
        f"For {audience}, this means rethinking how skills are built, measured, and recognized. "
        f"The gap between what institutions teach and what employers need is real — and AI is finally "
        f"giving us the tools to close it.\n\n"
        f"Our approach at EduBild: start with clear outcomes, use AI to personalize the path, "
        f"and measure what actually matters — readiness, not just credentials.\n\n"
        f"What's your take — is the skills gap closing, or getting wider?"
    )
    hashtags = "#EduBild #AI #FutureOfWork #SkillDevelopment #CareerGrowth"
    return {
        "title": topic,
        "content": f"{body}\n\n{hashtags}",
        "provider": "template",
    }
