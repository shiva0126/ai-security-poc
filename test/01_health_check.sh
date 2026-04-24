#!/usr/bin/env bash
# Test 01 — Health check all services
set -euo pipefail

PASS=0; FAIL=0
check() {
    local name="$1" url="$2" expected="$3"
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
    if [[ "$code" == "$expected" ]]; then
        echo "  [PASS] $name ($url) → $code"
        ((PASS++))
    else
        echo "  [FAIL] $name ($url) → $code (expected $expected)"
        ((FAIL++))
    fi
}

echo ""
echo "=========================================="
echo "  TEST 01 — Service Health Check"
echo "=========================================="
echo ""

check "Ollama API"       "http://localhost:11434/api/tags"         "200"
check "Open WebUI"       "http://localhost:3001/"                  "200"
check "ChromaDB"         "http://localhost:8000/api/v2/heartbeat"  "200"
check "RAG API"          "http://localhost:9001/health"            "200"
check "MCP Server HTTP"  "http://localhost:8765/health"            "200"
check "LiteLLM"          "http://localhost:4000/health"            "200"

echo ""
echo "Models loaded in Ollama:"
curl -s http://localhost:11434/api/tags | python3 -c "
import sys, json
d = json.load(sys.stdin)
for m in d.get('models', []):
    size_gb = round(m['size']/1e9, 1)
    print(f'  {m[\"name\"]:30s} {size_gb} GB')
" 2>/dev/null || echo "  (could not parse)"

echo ""
echo "------------------------------------------"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "------------------------------------------"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
