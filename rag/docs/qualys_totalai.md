# Qualys TotalAI — Knowledge Base

## Overview
Qualys TotalAI reached GA in Q4 2024. Built on the Qualys Enterprise TruRisk Platform, extending existing agents and scanners to cover AI-specific workloads. No new agents required. Release 1.3 (June 2025) added chat completion model support and expanded attack method QIDs.

## Asset Discovery — AI Fingerprinting
- Identifies AI/ML workloads across hardware (GPUs), software frameworks, Python packages, and model files
- GPU inventory, CUDA driver versioning, ML library cataloguing
- Cloud service discovery: AWS Bedrock, Azure AI, GCP Vertex AI
- MCP Server inventory: MCP name, URL, last discovered date, associated endpoints
- Shadow AI discovery: detects unapproved AI workloads without security oversight

## Vulnerability Detection
- 1,000+ AI-specific QIDs covering CVEs in ML libraries, GPU drivers, CUDA, Python AI frameworks
- Covers TensorFlow, PyTorch, Hugging Face transformers, llama-cpp, vLLM, Triton Inference Server
- GPU-specific vulnerability detection including driver CVEs
- Infrastructure-to-model correlation

## LLM Model Scanning
Scans models against OWASP LLM Top 10. Supported model platforms:
- Hugging Face (external and internal)
- AWS Bedrock (Claude, Llama, Titan)
- Azure OpenAI (GPT-4o, GPT-4.1, GPT-4.1-mini)
- Google Vertex AI (Gemini family)
- Databricks Chat
- **Chat Completion API** — any OpenAI-compatible endpoint including local Ollama instances

## TruRisk Scoring
Combines: CVSS base score (technical severity) + EPSS exploit probability (real-world exploitability) + business asset context (criticality). Produces actionable prioritisation over raw vulnerability counts.

## Licensing and Scan Configuration
- One TotalAI licence = one model onboarded + five scans per month
- Internal scanning requires 64-bit scanner appliance deployed inside the network
- Option Profile defines: temperature, top-k, top-p, max tokens, retry attempts, timeout, parallelism
- OWASP LLM Top 10 coverage toggleable per scan

## API Endpoints
- POST /auth — authentication
- POST /ta/api/1.0/detection/count — count detections with QQL filter
- POST /ta/api/1.0/detection/search — search detections with fields and ordering
- POST /ta/api/1.0/scan/launch — launch a TotalAI scan
- GET /ta/api/1.0/scan/{id} — poll scan status

## MCP Integration
The Qualys TotalAI MCP server (server.js) wraps all API endpoints as MCP tools: server_status, count_detections, search_detections, launch_scan, get_scan, raw_request. Runs over stdio (default) or HTTP (port 8765).
