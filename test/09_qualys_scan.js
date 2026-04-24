#!/usr/bin/env node
/**
 * Test 09 — Qualys TotalAI Full Scan via MCP
 * Runs: server_status → count_detections → search_detections → launch_scan → get_scan
 * Mock mode (QUALYS_MOCK_MODE=1): safe, no real API calls.
 * Live mode: set QUALYS_MOCK_MODE=0 with real credentials in .env
 */
import { spawn } from "node:child_process";
import process from "node:process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT      = path.resolve(__dirname, "..");
const MOCK_MODE = process.env.QUALYS_MOCK_MODE ?? "1";

function encode(msg) {
  const body = Buffer.from(JSON.stringify(msg));
  return Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`), body]);
}

function makeReader(onMsg) {
  let buf = Buffer.alloc(0);
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (true) {
      const sep = buf.indexOf("\r\n\r\n");
      if (sep === -1) return;
      const header = buf.slice(0, sep).toString();
      const m = header.match(/Content-Length:\s*(\d+)/i);
      if (!m) return;
      const cl = parseInt(m[1]);
      if (buf.length < sep + 4 + cl) return;
      onMsg(JSON.parse(buf.slice(sep + 4, sep + 4 + cl).toString()));
      buf = buf.slice(sep + 4 + cl);
    }
  };
}

class MCP {
  constructor() {
    this.child = spawn("node", ["server.js"], {
      cwd: ROOT, env: process.env, stdio: ["pipe","pipe","pipe"]
    });
    this.pending = new Map();
    this.nextId  = 1;
    this.child.stdout.on("data", makeReader(msg => {
      const resolve = this.pending.get(msg.id);
      if (resolve) { this.pending.delete(msg.id); resolve(msg); }
    }));
    this.child.stderr.on("data", d => process.stderr.write(d));
  }
  send(method, params = {}) {
    return new Promise((resolve) => {
      const id = this.nextId++;
      this.pending.set(id, resolve);
      this.child.stdin.write(encode({ jsonrpc:"2.0", id, method, params }));
    });
  }
  async init() {
    await this.send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {}, clientInfo: { name: "qualys-test", version: "1.0" }
    });
  }
  async call(tool, args = {}) {
    const r = await this.send("tools/call", { name: tool, arguments: args });
    const text = r?.result?.content?.[0]?.text ?? JSON.stringify(r);
    try { return JSON.parse(text); } catch { return { raw: text }; }
  }
  close() { this.child.kill(); }
}

function print(label, data) {
  console.log(`\n  [${label}]`);
  console.log(JSON.stringify(data, null, 4).split("\n").map(l => "    " + l).join("\n"));
}

async function run() {
  console.log("\n==========================================");
  console.log("  TEST 09 — Qualys TotalAI Full Scan Flow");
  console.log("==========================================\n");
  console.log(`  Mode: ${MOCK_MODE === "1" ? "MOCK (safe)" : "LIVE — real API calls"}`);
  console.log(`  Qualys URL: ${process.env.QUALYS_BASE_URL ?? "https://gateway.qg1.apps.qualys.com"}\n`);

  const mcp = new MCP();
  await mcp.init();

  // Step 1 — Server Status
  console.log("  Step 1: server_status");
  const status = await mcp.call("server_status");
  print("STATUS", status);

  // Step 2 — Count Detections
  console.log("\n  Step 2: count_detections (all findings, severity >= 3)");
  const count = await mcp.call("count_detections", {
    filter: { detectionQql: "finding.severity>=3" }
  });
  print("COUNT", count);

  // Step 3 — Search Detections
  console.log("\n  Step 3: search_detections (FAIL findings, sorted by severity)");
  const search = await mcp.call("search_detections", {
    filter: { detectionQql: "finding.result:FAIL" },
    fields: "id,qid,name,attack,severity,result,failTestPercentage,model",
    orderBy: "severity",
    sortOrder: "DESC",
    size: 10
  });
  print("DETECTIONS", search);

  // Step 4 — Launch Scan
  console.log("\n  Step 4: launch_scan against Ollama (Chat Completion endpoint)");
  const scan = await mcp.call("launch_scan", {
    name: `POC_Ollama_Scan_${new Date().toISOString().slice(0,10)}`,
    targetModelId: 80791371,
    optionProfileId: 7868365
  });
  print("SCAN_LAUNCHED", scan);

  // Step 5 — Poll Scan Status
  const scanId = scan?.launchScan?.id ?? scan?.id;
  if (scanId) {
    console.log(`\n  Step 5: get_scan (id: ${scanId})`);
    const scanStatus = await mcp.call("get_scan", { id: scanId });
    print("SCAN_STATUS", scanStatus);
  }

  mcp.close();
  console.log("\n  → With live credentials: set QUALYS_MOCK_MODE=0 in .env");
  console.log("  → Configure Option Profile with OWASP LLM Top 10 full coverage");
  console.log("  → Set targetModelId to your Ollama Chat Completion endpoint ID\n");
}

run().catch(e => { console.error(e); process.exit(1); });
