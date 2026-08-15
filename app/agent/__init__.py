# =============================================================================
# CTI Platform - Autonomous Triage & Enrichment Agent (app/agent/)
# -----------------------------------------------------------------------------
# LangGraph-based agent that autonomously investigates a high-risk indicator
# (IP / domain / hash / CVE) using free read-only tools, sanitises its input
# against prompt injection (Uber ADR-inspired sensor layer), and outputs our
# structured 4-part "Alert Sheet".
#
# Modules:
#   sensor.py   - input sanitisation + prompt-injection detection + trace logger
#   tools.py    - read-only tools: Shodan InternetDB + ClickHouse knowledge search
#   graph.py    - compiled StateGraph (nodes, edges, conditional router)
#
# The FastAPI route lives in app/routers/agent.py and is mounted under
# POST /api/v1/agent/triage.
# =============================================================================
