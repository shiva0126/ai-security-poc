#!/usr/bin/env bash
# Master test runner — runs all 10 tests in sequence with a summary report
set -euo pipefail

cd "$(dirname "$0")/.."
export PYTHONPATH="$(pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

PASS=0; FAIL=0; SKIP=0
declare -A RESULTS

run_test() {
    local num="$1" name="$2" cmd="$3"
    echo -e "\n${BOLD}━━━ TEST $num: $name ━━━${NC}"
    if eval "$cmd" 2>&1; then
        RESULTS[$num]="PASS"
        ((PASS++))
    else
        RESULTS[$num]="FAIL"
        ((FAIL++))
    fi
}

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   AI SECURITY POC — Full Test Suite      ║"
echo "║   AI Security POC    ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Environment:"
echo "  Ollama:     ${OLLAMA_BASE_URL:-http://localhost:11434}"
echo "  LiteLLM:    ${LITELLM_BASE_URL:-http://localhost:4000}"
echo "  ChromaDB:   ${CHROMA_HOST:-http://localhost:8000}"
echo "  RAG API:    ${RAG_API_URL:-http://localhost:9001}"
echo "  Qualys Mock: ${QUALYS_MOCK_MODE:-1}"
echo "  AIDR Token: $([ -n "${CS_AIDR_TOKEN:-}" ] && [ "${CS_AIDR_TOKEN}" != "PLACEHOLDER_CROWDSTRIKE_TOKEN" ] && echo 'CONFIGURED' || echo 'PLACEHOLDER')"
echo ""

run_test "01" "Service Health Check"       "bash test/01_health_check.sh"
run_test "02" "MCP Server Smoke"           "bash test/02_mcp_smoke.sh"
run_test "03" "Prompt Injection (LLM01)"   "python3 test/03_prompt_injection.py"
run_test "04" "PII Detection DLP"          "python3 test/04_pii_detection.py"
run_test "05" "Excessive Agency (LLM08)"   "python3 test/05_excessive_agency.py"
run_test "06" "RAG Pipeline Validation"    "python3 test/06_rag_query.py"
run_test "07" "RAG Poisoning Demo"         "python3 test/07_rag_poisoning.py"
run_test "08" "Model Extraction Probe"     "python3 test/08_model_extraction.py"
run_test "09" "Qualys TotalAI Scan"        "node --input-type=module < test/09_qualys_scan.js"
run_test "10" "CrowdStrike AIDR"           "python3 test/10_crowdstrike_aidr.py"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   TEST SUMMARY                           ║"
echo "╠══════════════════════════════════════════╣"
for num in $(seq -f "%02g" 1 10); do
    status="${RESULTS[$num]:-SKIP}"
    [[ "$status" == "PASS" ]] && color="$GREEN" || color="$RED"
    printf "║  Test %s: ${color}%-6s${NC}                        ║\n" "$num" "$status"
done
echo "╠══════════════════════════════════════════╣"
printf "║  ${GREEN}PASS: %-3d${NC}  ${RED}FAIL: %-3d${NC}  SKIP: %-3d          ║\n" $PASS $FAIL $SKIP
echo "╚══════════════════════════════════════════╝"
echo ""
