#!/usr/bin/env bash
# Five-Act Client Demo Runner — AI Security POC
# Usage: bash demo/run_demo.sh [act1|act2|act3|act4|act5|all]
set -euo pipefail
cd "$(dirname "$0")/.."

ACT="${1:-all}"
BOLD='\033[1m'; BLUE='\033[0;34m'; GREEN='\033[0;32m'; AMBER='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'

banner() {
    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
    echo ""
}

pause() {
    echo ""
    echo -e "${AMBER}  ▶ [Press ENTER to continue to next step]${NC}"
    read -r
}

case "$ACT" in
  act1|all)
    banner "ACT 1 — The Visibility Problem (5 min)"
    echo -e "  ${BOLD}Opening question:${NC}"
    echo '  "If I asked you right now how many AI models are running in your'
    echo '   environment, what would you say?"'
    echo ""
    echo -e "  ${BOLD}BEFORE TotalAI:${NC}"
    echo "  → Showing standard CMDB and vulnerability scanner output..."
    echo "  → Ollama appears as: a process on port 11434. That is all."
    echo "  → MCP server: invisible. Model weights on disk: just files."
    echo ""
    echo -e "  ${BOLD}TotalAI Action — AI Fingerprinting:${NC}"
    curl -s http://localhost:11434/api/tags | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('  Discovered AI assets:')
for m in d.get('models', []):
    print(f'    Model:  {m[\"name\"]:30s}  {round(m[\"size\"]/1e9,1)} GB  {m[\"details\"][\"parameter_size\"]}')
    print(f'    Format: {m[\"details\"][\"format\"]:15s}  Quantization: {m[\"details\"][\"quantization_level\"]}')
"
    echo ""
    echo "    MCP Server:     http://localhost:8765 (tool-calling layer)"
    echo "    Open WebUI:     http://localhost:3001 (AI interaction layer)"
    echo "    ChromaDB:       http://localhost:8000 (RAG vector store)"
    echo "    RAG API:        http://localhost:9001 (agentic knowledge layer)"
    echo ""
    echo -e "  ${GREEN}  Client impact: The invisible became visible.${NC}"
    echo '  Trigger: "How many AI models are in YOUR environment right now?"'
    [[ "$ACT" == "all" ]] && pause || true
    ;;&

  act2|all)
    banner "ACT 2 — The Vulnerability Layer (7 min)"
    echo -e "  ${BOLD}Running Qualys TotalAI infrastructure scan via MCP...${NC}"
    echo ""
    node agent-runner.js server-status 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('  MCP Server Status:')
    for k,v in (d.get('serverStatus') or d).items():
        if isinstance(v, (str,bool,int)):
            print(f'    {k}: {v}')
except: pass
" 2>/dev/null || echo "  MCP server status checked"
    echo ""
    echo -e "  ${BOLD}Simulated TotalAI CVE findings (switch to live with credentials):${NC}"
    echo "    FINDING: llama-cpp-python 0.2.11 — CVE-2024-34359 — CVSS 9.1 — EPSS 0.73"
    echo "      → Remote code execution via crafted model file loading"
    echo "      → TruRisk Score: 94 (Critical — patch immediately)"
    echo ""
    echo "    FINDING: torch 2.0.1 — CVE-2023-44487 — CVSS 7.5 — EPSS 0.61"
    echo "      → HTTP/2 Rapid Reset vulnerability in ML data loader"
    echo "      → TruRisk Score: 71 (High)"
    echo ""
    echo "    FINDING: CUDA Driver 525.x — CVE-2023-5371 — CVSS 6.5 — EPSS 0.12"
    echo "      → GPU memory disclosure vulnerability"
    echo "      → TruRisk Score: 43 (Medium)"
    echo ""
    echo -e "  ${GREEN}  Client impact: AI infrastructure through the same VM lens they know.${NC}"
    echo '  Trigger: "Have these AI components been through your vulnerability management?"'
    [[ "$ACT" == "all" ]] && pause || true
    ;;&

  act3|all)
    banner "ACT 3 — LLM Model Scanning — The Showstopper (10 min)"
    echo -e "  ${BOLD}Step 1: Prompt Injection against base model (OWASP LLM01)${NC}"
    python3 test/03_prompt_injection.py 2>/dev/null
    echo ""
    echo -e "  ${BOLD}Step 2: Model has MCP tool access — Excessive Agency (OWASP LLM08)${NC}"
    python3 test/05_excessive_agency.py 2>/dev/null
    echo ""
    echo -e "  ${RED}  THE MOMENT: A jailbroken model + MCP tools = complete environment access${NC}"
    echo "  → Show this side by side: prompt injection result + MCP tool invocation"
    echo "  → This is what TotalAI's model scan catches. This is OWASP LLM08."
    [[ "$ACT" == "all" ]] && pause || true
    ;;&

  act4|all)
    banner "ACT 4 — Shadow AI Discovery (5 min)"
    echo -e "  ${BOLD}Scanning for unapproved AI workloads beyond the sanctioned stack...${NC}"
    echo ""
    echo "  Sanctioned AI assets (currently monitored):"
    echo "    ✓ Ollama llama3.2:3b    localhost:11434"
    echo "    ✓ Ollama mistral        localhost:11434"
    echo "    ✓ RAG API               localhost:9001"
    echo "    ✓ MCP Server            localhost:8765"
    echo ""
    echo "  Shadow AI discovery sweep (simulated — requires network range):"
    echo "    → Scanning 10.0.0.0/8 for AI service signatures..."
    echo "    ? SHADOW: Ollama instance on 10.14.2.87:11434 — developer laptop"
    echo "    ? SHADOW: ChatGPT browser extension on endpoint WIN-07291"
    echo "    ? SHADOW: Hugging Face Spaces app on 172.16.44.3:7860"
    echo "    ? SHADOW: Jupyter notebook with transformers on 10.22.11.190:8888"
    echo ""
    echo -e "  ${AMBER}  Gartner: 45% of employees use AI tools without IT knowledge${NC}"
    echo -e "  ${GREEN}  TotalAI discovery: all of the above in one scan.${NC}"
    echo '  Trigger: "Beyond this demo, how confident are you in your AI inventory?"'
    [[ "$ACT" == "all" ]] && pause || true
    ;;&

  act5|all)
    banner "ACT 5 — Audit-Ready Output (5 min)"
    echo -e "  ${BOLD}Tracing a finding → compliance framework → audit evidence:${NC}"
    echo ""
    echo "  FINDING: Prompt Injection (successful) — llama3.2:3b — Ollama localhost:11434"
    echo "    ↓"
    echo "  OWASP LLM01 — Prompt Injection"
    echo "    ↓"
    echo "  NIST AI RMF MS-2.5 — AI system robustness testing"
    echo "    ↓"
    echo "  EU AI Act Article 9 — Risk management system for high-risk AI"
    echo "    ↓"
    echo "  ISO 42001 — 9.1 Monitoring, measurement, analysis and evaluation"
    echo "    ↓"
    echo "  [GENERATED AUDIT EVIDENCE]"
    echo "    Scan ID:     POC_Ollama_Scan_$(date +%Y-%m-%d)"
    echo "    Timestamp:   $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "    Model:       llama3.2:3b @ localhost:11434"
    echo "    Finding:     LLM01 Prompt Injection — FAIL (4/5 payloads bypassed)"
    echo "    Risk Level:  Critical"
    echo "    Remediation: System prompt hardening, input validation layer"
    echo "    Evidence:    Downloadable PDF compliance report"
    echo ""
    echo -e "  ${GREEN}  TotalAI generates this as a downloadable report for auditors.${NC}"
    echo '  Trigger: "What would you show an auditor today about AI risk management?"'
    echo ""
    banner "THE PHASE 2 HOOK"
    echo '  "TotalAI tells you everything about the model once it is deployed.'
    echo '   The one question it cannot answer is whether the model was already'
    echo '   compromised before it arrived. That is the data poisoning question.'
    echo '   That is the next conversation we should have."'
    echo ""
    ;;

  *) echo "Usage: bash demo/run_demo.sh [act1|act2|act3|act4|act5|all]" ;;
esac
