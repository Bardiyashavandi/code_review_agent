"""
scripts/adk_demo.py
--------------------
Small standalone script for the video demo: shows the ADK agent deciding,
on its own, to call review_repo_tool from a plain-language request.

Run it directly (from anywhere -- this adds the repo root to sys.path so
`agent` resolves as a top-level module either way):
    python3 scripts/adk_demo.py
"""

import asyncio
import os
import sys
from pathlib import Path

# This script lives in scripts/, one level below the repo root where
# agent.py and its sibling modules live as top-level modules (not a
# package) -- add the repo root to sys.path so `from agent import ...`
# below resolves the same way it would if this script were still at the
# repo root itself.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv
from google.adk.runners import InMemoryRunner
from google.genai import types

from agent import build_adk_agent

PROMPT = (
    "review https://github.com/anxolerd/dvpwa "
    "and summarize the top issues"
)


async def main() -> None:
    load_dotenv(override=True)  # loads .env into os.environ, overriding existing env vars

    adk_agent = build_adk_agent(
        github_token=os.environ["GITHUB_TOKEN"],
        gemini_api_key=os.environ["GEMINI_API_KEY"],
    )

    runner = InMemoryRunner(agent=adk_agent, app_name="code_review_agent")
    session = await runner.session_service.create_session(
        app_name="code_review_agent", user_id="demo_user"
    )

    message = types.Content(role="user", parts=[types.Part(text=PROMPT)])

    print(f"Prompt: {PROMPT}\n")
    async for event in runner.run_async(
        user_id="demo_user", session_id=session.id, new_message=message
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if getattr(part, "function_call", None):
                    print(f"[agent decided to call tool: {part.function_call.name}]")
                if getattr(part, "text", None):
                    print(part.text)


if __name__ == "__main__":
    asyncio.run(main())
