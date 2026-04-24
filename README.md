# AI Security POC

A fully containerised proof-of-concept for testing AI/LLM security using **Qualys TotalAI**, **CrowdStrike AIDR**, and an OWASP LLM Top 10 test suite — all running locally via Docker Compose.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Ollama (llama3.2:3b + nomic-embed-text)   port 11434           │
│  ChromaDB vector store                      port 8000            │
│  RAG API (FastAPI)                          port 9001            │
│  MCP Server (Qualys TotalAI, JSON-RPC 2.0) port 8765            │
│  LiteLLM + CrowdStrike AIDR guardrail       port 4000            │
│  POC Dashboard (FastAPI + live UI)          port 9002            │
│  Open WebUI                                 port 3001            │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Copy and fill in credentials
cp .env.example .env

# 2. Start all core services (models download automatically)
docker compose up -d

# 3. Run the full test suite
docker compose run --rm test-runner

# 4. Open the live dashboard
open http://localhost:9002
```

> **Mock mode:** `QUALYS_MOCK_MODE=1` (default) returns deterministic data without real credentials. Set to `0` with live Qualys credentials to scan real AI models.

## Test Suite (11 tests, 31+ attack vectors)

| # | Test | Coverage |
|---|------|----------|
| 01 | Service Health Check | Infrastructure |
| 02 | MCP Server Smoke | OWASP LLM07 |
| 03 | Prompt Injection | OWASP LLM01 |
| 04 | PII Detection (CrowdStrike AIDR) | OWASP LLM06 |
| 05 | Excessive Agency | OWASP LLM08 |
| 06 | RAG Pipeline Validation | Architecture |
| 07 | RAG Vector Poisoning | OWASP LLM03 |
| 08 | Model Extraction | OWASP LLM10 |
| 09 | Qualys TotalAI Scan | Qualys |
| 10 | CrowdStrike AIDR Guardrail | CrowdStrike |
| 11 | Malicious Injection Suite (31 vectors) | LLM01/07/08/10 |

## Malicious Injection Suite (Test 11)

Five attack categories:

- **A. MCP Protocol Abuse** — malformed JSON-RPC, prototype pollution, null args, oversized payloads, SSRF via `raw_request`, header injection
- **B. Direct Model Attacks** — classic jailbreak, DAN persona, many-shot normalisation, adversarial suffix, base64 obfuscation, Unicode homoglyphs, markdown injection, emotional manipulation, ZEUS persona, indirect extraction
- **C. Context Manipulation** — context poisoning, authority impersonation, false memory injection, incremental boundary escalation
- **D. MCP + AI Combined** — indirect prompt injection via tool output, JSON smuggling, LLM-driven tool misuse, poisoned response interpretation, recon→exploit chain
- **E. Info Disclosure** — model fingerprinting, config extraction, capability probing, training data extraction, system prompt probe

## Services

| Service | Port | Notes |
|---------|------|-------|
| Ollama | 11434 | Local LLM runtime |
| ChromaDB | 8000 | Vector store |
| RAG API | 9001 | Query + ingest |
| MCP Server | 8765 | Qualys TotalAI (JSON-RPC 2.0) |
| LiteLLM + AIDR | 4000 | Needs `CS_AIDR_TOKEN` |
| Dashboard | 9002 | Live findings UI |
| Open WebUI | 3001 | Chat interface |

## Running Tests

```bash
# Full suite inside Docker
docker compose run --rm test-runner

# Quick subset (health + MCP + RAG)
docker compose run --rm test-runner python3 test/run_tests.py --quick

# Standalone test 11 only
docker compose run --rm test-runner python3 test/11_malicious_injection.py

# On the host (requires Ollama + MCP running locally)
python3 test/run_tests.py
```

## Dashboard

Live at **http://localhost:9002** — auto-refreshes every 20 s.

- Findings table with severity/status/OWASP badges
- Filter by category, severity, status
- Click any row to expand payload + response preview + remediation
- OWASP LLM bar chart, service status, run history

## MCP Server Tool Reference

| Tool | Description |
|------|-------------|
| `server_status` | Health check and auth validation |
| `count_detections` | Count AI model findings with QQL filter |
| `search_detections` | Search findings with pagination |
| `launch_scan` | Start a Qualys TotalAI scan |
| `get_scan` | Poll scan status by ID |
| `raw_request` | Arbitrary Qualys API passthrough (attack surface) |

HTTP transport: `POST /mcp` (JSON-RPC 2.0), `GET /health`

## Environment Variables

See `.env.example` for the full list. Key variables:

- `QUALYS_MOCK_MODE` — `1` for safe demo mode, `0` for live scanning
- `CS_AIDR_TOKEN` — CrowdStrike AIDR token (enables tests 04 and 10)
- `OLLAMA_MODEL` — LLM model to use (default: `llama3.2:3b`)
- `CHROMA_AUTH_TOKEN` — ChromaDB auth token

## Framework Mapping

| Finding | OWASP LLM | MITRE ATLAS |
|---------|-----------|-------------|
| Prompt Injection | LLM01 | AML.T0051 |
| RAG Poisoning | LLM03 | AML.T0054 |
| Info Disclosure | LLM06 | AML.T0012 |
| Plugin/Tool Abuse | LLM07 | AML.T0051.002 |
| Excessive Agency | LLM08 | AML.T0048 |
| Model Extraction | LLM10 | AML.T0012 |
