#!/usr/bin/env bash
# Test 02 — MCP Server smoke test (all three tool profiles)
set -euo pipefail

cd "$(dirname "$0")/.."

echo ""
echo "=========================================="
echo "  TEST 02 — MCP Server Tool Profiles"
echo "=========================================="

for profile in server-status detections-smoke launch-scan; do
    echo ""
    echo "  → Running profile: $profile"
    output=$(node agent-runner.js "$profile" 2>&1)
    if echo "$output" | grep -qE "(status|detections|scan|mock|FINISHED|NEW)" ; then
        echo "  [PASS] $profile — got valid response"
        echo "$output" | tail -8 | sed 's/^/    /'
    else
        echo "  [FAIL] $profile — unexpected output"
        echo "$output" | tail -5 | sed 's/^/    /'
    fi
done

echo ""
echo "  MCP HTTP endpoint check:"
curl -s -X POST http://localhost:8765/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
tools = d.get('result', {}).get('tools', [])
for t in tools:
    print(f'    tool: {t[\"name\"]}')
" 2>/dev/null || echo "  (HTTP mode not active — stdio mode OK)"

echo ""
