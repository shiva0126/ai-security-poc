# AI Security Architecture — Overview

## Four-Phase Funnel

### Phase 1: AI Attack Surface
Six threat categories:
1. **Endpoint AI Tools** — Copilot, Cursor, ChatGPT extensions. File system access, clipboard interception, authenticated browser sessions.
2. **AI Models & Workloads** — Self-hosted LLMs, fine-tuned models, training pipelines, GPU infrastructure. Ollama is the test environment representative.
3. **AI/API Gateways** — LiteLLM, Kong, Apigee, Azure API Management. Single misconfiguration exposes all downstream models.
4. **MCP Servers & Agents** — Highest-autonomy components. Agents can call external tools, execute code, query databases. Each tool expands blast radius.
5. **Cloud AI Services** — AWS SageMaker, Azure OpenAI, GCP Vertex AI. IAM misconfigurations, data residency violations, insufficient content filtering.
6. **Shadow AI** — Unapproved tools (Claude.ai, ChatGPT Free, Gemini). No audit trail, no DLP, no retention controls. Architecturally marked with red dashed uncontrolled flow.

### Phase 2: Security Platform Layer
- **CrowdStrike Falcon AIDR** — prompt and interaction layer. DLP, prompt injection detection, agent behavioural monitoring.
- **Morphisec Adaptive AI Defense** — runtime memory layer. AMTD, shadow AI discovery, rogue agent blocking.
- **Qualys TotalAI** — asset and vulnerability layer. AI fingerprinting, CVE detection, OWASP LLM Top 10 model scanning.

### Phase 3: SIEM & Analytics — Splunk
Five dedicated indexes: idx_ai_crowdstrike, idx_ai_morphisec, idx_ai_qualys, idx_ai_gateway, idx_ai_cloud. 15+ AI-specific detection use cases. Six dashboards. SOAR playbooks for automated response.

### Phase 4: Governance & Compliance
AI Governance Framework: AI Usage Policy, Access Control Matrix, Approval Workflow, Compliance Monitoring, Audit Trail, Governance Board. Maps to EU AI Act, ISO 42001, NIST AI RMF.

## Critical Gap: The Visibility Floor
The entire four-tool stack activates ONLY after model deployment. Pre-deployment attacks — training data poisoning, model weight tampering, serialization attacks, supply chain compromise — are completely invisible to all four tools. The model arrives already compromised.

## Test Environment Stack
- Ollama: localhost:11434 — model serving (llama3.2:3b, mistral)
- ChromaDB: localhost:8000 — vector store for RAG
- LiteLLM: localhost:4000 — AI gateway with AIDR guardrail
- RAG API: localhost:9001 — retrieval-augmented generation endpoint
- MCP Server: localhost:8765 — Qualys TotalAI tool interface
- Open WebUI: localhost:3001 — chat interface

## Remediation Roadmap
- Phase A (0-90 days): Deploy Protect AI ModelScan as CI/CD gate, SafeTensors enforcement, dataset provenance hashing, TotalAI internal scanner, LiteLLM AIDR guardrail
- Phase B (90-180 days): NHI platform (CyberArk/HashiCorp Vault), RAG integrity monitoring (Lakera Guard), MCP semantic validation, multi-agent authentication
- Phase C (180-365 days): HiddenLayer continuous monitoring, AI-BOM generation, ISO 42001 alignment, EU AI Act compliance, bias monitoring
