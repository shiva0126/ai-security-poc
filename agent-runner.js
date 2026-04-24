#!/usr/bin/env node

import { spawn } from "node:child_process";
import process from "node:process";

const profileName = process.argv[2] || process.env.AGENT_PROFILE || "server-status";

const profiles = {
  "server-status": {
    description: "Inspect the MCP server readiness and summarize whether live or mock testing is available.",
    maxSteps: 3,
  },
  "detections-smoke": {
    description:
      "Run a basic detection workflow. Call server_status first, then count_detections, then search_detections, and summarize the results.",
    maxSteps: 5,
  },
  "launch-scan": {
    description:
      "Run a scan workflow in a safe test shape. Call server_status first, then launch_scan with a short test name and targetModelId 80791371, then get_scan for the launched id, and summarize the scan status.",
    maxSteps: 5,
  },
};

const profile = profiles[profileName];

if (!profile) {
  console.error(`Unknown agent profile: ${profileName}`);
  console.error(`Available profiles: ${Object.keys(profiles).join(", ")}`);
  process.exit(1);
}

function encodeMessage(message) {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  return Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "utf8"), body]);
}

function createFrameReader(onMessage) {
  let buffer = Buffer.alloc(0);

  return (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    while (true) {
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        return;
      }

      const headerText = buffer.slice(0, headerEnd).toString("utf8");
      const match = headerText.match(/Content-Length:\s*(\d+)/i);
      if (!match) {
        throw new Error("Agent runner received a frame without Content-Length");
      }

      const contentLength = Number.parseInt(match[1], 10);
      const frameLength = headerEnd + 4 + contentLength;
      if (buffer.length < frameLength) {
        return;
      }

      const body = buffer.slice(headerEnd + 4, frameLength).toString("utf8");
      buffer = buffer.slice(frameLength);
      onMessage(JSON.parse(body));
    }
  };
}

function parseToolText(result) {
  const text = result?.content?.find((entry) => entry.type === "text")?.text;
  if (!text) {
    return result;
  }

  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

class McpSession {
  constructor() {
    const command = process.env.MCP_COMMAND || process.execPath;
    const args = process.env.MCP_ARGS
      ? process.env.MCP_ARGS.split(/\s+/).filter(Boolean)
      : ["server.js"];
    const cwd = process.env.MCP_CWD || process.cwd();

    this.child = spawn(command, args, {
      cwd,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.responses = new Map();
    this.nextId = 1;

    this.child.stdout.on(
      "data",
      createFrameReader((message) => {
        if ("id" in message && this.responses.has(message.id)) {
          const resolve = this.responses.get(message.id);
          this.responses.delete(message.id);
          resolve(message);
        }
      }),
    );

    this.child.stderr.on("data", (chunk) => {
      process.stderr.write(`[mcp] ${chunk}`);
    });
  }

  waitForResponse(id, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.responses.delete(id);
        reject(new Error(`Timed out waiting for MCP response ${id}`));
      }, timeoutMs);

      this.responses.set(id, (message) => {
        clearTimeout(timeout);
        resolve(message);
      });
    });
  }

  async send(method, params) {
    const id = this.nextId++;
    const pending = this.waitForResponse(id);
    this.child.stdin.write(
      encodeMessage({
        jsonrpc: "2.0",
        id,
        method,
        params,
      }),
    );
    return pending;
  }

  async initialize() {
    await this.send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: {
        name: "ollama-agent-runner",
        version: "0.1.0",
      },
    });

    this.child.stdin.write(
      encodeMessage({
        jsonrpc: "2.0",
        method: "notifications/initialized",
        params: {},
      }),
    );
  }

  async listTools() {
    const response = await this.send("tools/list", {});
    return response.result?.tools || [];
  }

  async callTool(name, args) {
    const response = await this.send("tools/call", {
      name,
      arguments: args || {},
    });
    return {
      raw: response.result,
      parsed: parseToolText(response.result),
      isError: Boolean(response.result?.isError),
    };
  }

  close() {
    this.child.kill("SIGTERM");
  }
}

async function runModelStep(prompt) {
  const baseUrl = (process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434").replace(/\/+$/, "");
  const model = process.env.OLLAMA_MODEL || "llama3.2:3b";

  const response = await fetch(`${baseUrl}/api/generate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      prompt,
      stream: false,
      format: {
        type: "object",
        properties: {
          thought: { type: "string" },
          tool: { type: "string" },
          arguments: { type: "object" },
          final: { type: "string" },
        },
        additionalProperties: false,
      },
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Ollama request failed with HTTP ${response.status}: ${body}`);
  }

  const data = await response.json();
  const raw = data.response || "{}";

  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`Ollama returned invalid JSON: ${error.message}\n${raw}`);
  }
}

function buildPrompt({ tools, history }) {
  return [
    "You are a test agent validating a Qualys TotalAI MCP server.",
    "You must respond with JSON only.",
    "If another tool call is needed, respond with: {\"thought\":\"...\",\"tool\":\"tool_name\",\"arguments\":{}}",
    "If the task is complete, respond with: {\"final\":\"short useful summary\"}",
    `Current profile: ${profileName}`,
    `Task: ${profile.description}`,
    "Available tools:",
    JSON.stringify(
      tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
      })),
      null,
      2,
    ),
    "Interaction history:",
    JSON.stringify(history, null, 2),
    "Return the next best action now.",
  ].join("\n\n");
}

async function main() {
  const session = new McpSession();

  try {
    await session.initialize();
    const tools = await session.listTools();
    const history = [];

    for (let step = 0; step < profile.maxSteps; step += 1) {
      const prompt = buildPrompt({ tools, history });
      const decision = await runModelStep(prompt);

      if (decision.final) {
        console.log(
          JSON.stringify(
            {
              profile: profileName,
              final: decision.final,
              steps: history,
            },
            null,
            2,
          ),
        );
        return;
      }

      if (!decision.tool) {
        throw new Error("Model response did not include tool or final");
      }

      const result = await session.callTool(decision.tool, decision.arguments || {});
      history.push({
        step: step + 1,
        thought: decision.thought || "",
        tool: decision.tool,
        arguments: decision.arguments || {},
        result: result.parsed,
        isError: result.isError,
      });

      if (result.isError) {
        console.log(
          JSON.stringify(
            {
              profile: profileName,
              final: `Tool ${decision.tool} failed`,
              steps: history,
            },
            null,
            2,
          ),
        );
        return;
      }
    }

    console.log(
      JSON.stringify(
        {
          profile: profileName,
          final: "Agent stopped after maxSteps without emitting a final answer",
          steps: history,
        },
        null,
        2,
      ),
    );
  } finally {
    session.close();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
