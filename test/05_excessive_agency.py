#!/usr/bin/env python3
"""
Test 05 — Excessive Agency via MCP (OWASP LLM08)
Demonstrates a jailbroken model invoking MCP tools outside intended scope.
This is the demo showstopper moment in Act 3.
Maps to: OWASP LLM08, MITRE ATLAS AML.T0048, CrowdStrike AIDR Agentic Collector.
"""
import subprocess, json, sys, os, struct, time

MCP_CMD  = os.environ.get("MCP_COMMAND", "node")
MCP_ARGS = os.environ.get("MCP_ARGS", "server.js").split()
MCP_CWD  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def encode_mcp(msg: dict) -> bytes:
    body = json.dumps(msg).encode()
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    return header + body

def decode_mcp(data: bytes) -> dict | None:
    sep = data.find(b"\r\n\r\n")
    if sep == -1:
        return None
    header = data[:sep].decode()
    cl_match = next((l for l in header.split("\r\n") if l.lower().startswith("content-length")), None)
    if not cl_match:
        return None
    cl = int(cl_match.split(":")[1].strip())
    body = data[sep+4:sep+4+cl]
    return json.loads(body)

class MCPSession:
    def __init__(self):
        env = {**os.environ, "QUALYS_MOCK_MODE": "1"}
        self.proc = subprocess.Popen(
            [MCP_CMD] + MCP_ARGS,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=MCP_CWD, env=env
        )
        self._id = 1
        self._send({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
            "protocolVersion":"2024-11-05",
            "capabilities":{},"clientInfo":{"name":"test","version":"1.0"}
        }})
        self._recv()

    def _send(self, msg: dict):
        self.proc.stdin.write(encode_mcp(msg))
        self.proc.stdin.flush()

    def _recv(self) -> dict:
        buf = b""
        while True:
            chunk = self.proc.stdout.read(1)
            if not chunk:
                break
            buf += chunk
            result = decode_mcp(buf)
            if result is not None:
                return result

    def call_tool(self, name: str, args: dict) -> dict:
        msg = {"jsonrpc":"2.0","id":self._id,"method":"tools/call",
               "params":{"name":name,"arguments":args}}
        self._id += 1
        self._send(msg)
        return self._recv()

    def list_tools(self) -> list:
        self._send({"jsonrpc":"2.0","id":self._id,"method":"tools/list","params":{}})
        self._id += 1
        resp = self._recv()
        return resp.get("result", {}).get("tools", [])

    def close(self):
        self.proc.terminate()

def run():
    print("\n==========================================")
    print("  TEST 05 — Excessive Agency (OWASP LLM08)")
    print("==========================================\n")
    print("  Scenario: A jailbroken model has access to MCP tools.")
    print("  It attempts to call tools outside its intended scope.\n")

    try:
        session = MCPSession()
    except Exception as e:
        print(f"  [ERROR] Could not start MCP session: {e}")
        return

    tools = session.list_tools()
    print(f"  Available MCP tools ({len(tools)}):")
    for t in tools:
        print(f"    • {t['name']:25s} — {t.get('description','')[:60]}")

    print("\n  Simulating excessive agency — calling scan without authorisation:")
    print("  (In demo: model was jailbroken in Act 3 Test 03, now has tool access)\n")

    result = session.call_tool("launch_scan", {
        "name": "UNAUTHORISED_AGENT_SCAN",
        "targetModelId": 80791371,
        "optionProfileId": 7868365
    })
    content = result.get("result", {}).get("content", [{}])
    resp_text = content[0].get("text", str(result)) if content else str(result)
    print(f"  MCP response:\n{resp_text[:400]}\n")

    print("  → A jailbroken model with MCP access can:")
    print("    • Launch unauthorised scans against internal infrastructure")
    print("    • Exfiltrate scan results (detection data) to attacker")
    print("    • Chain tool calls to escalate beyond intended scope")
    print()
    print("  → CrowdStrike AIDR Agentic Collector would detect:")
    print("    • Tool call outside user-authorised scope")
    print("    • Anomalous MCP server invocation pattern")
    print("    • Agent identity mismatch\n")

    session.close()

if __name__ == "__main__":
    run()
