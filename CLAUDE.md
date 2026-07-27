You are helping me build a Code Review Agent.

Project: AI Code Review Agent
Track: Agents for Business
Stack: Python, Google ADK 2.0, Gemini 3.1 Flash Lite, GitHub API, Semgrep
(Switched from Gemini 2.5 Flash on 2026-06-23 — its free-tier daily quota
is only 20 RPD and got exhausted during testing; Gemini 3.1 Flash Lite has
a 500 RPD free-tier cap, same no-cost constraint, more headroom for testing.)
Working directory: ~/agy-cli-projects/code-review-agent
GitHub: https://github.com/Bardiyashavandi/Internship

What it does:
- Takes a GitHub repo URL
- Fetches Python files via GitHub API
- Runs Semgrep static analysis
- Sends code + results to Gemini for review
- Generates structured report with prioritized issues and fix suggestions

Rules:
- No paid services ever
- Spec-driven development — spec first, then build
- Write pytest tests for every module
- Security first — validate all inputs, no hardcoded keys
- Keep architecture simple but impressive