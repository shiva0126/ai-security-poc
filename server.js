#!/usr/bin/env node

import http from "node:http";
import process from "node:process";
import { pathToFileURL } from "node:url";

const SERVER_INFO = {
  name: "qualys-totalai-mcp",
  version: "0.1.0",
};

const PROTOCOL_VERSION = "2024-11-05";

function readEnv(name, fallback = undefined) {
  const value = process.env[name];
  return value === undefined || value === "" ? fallback : value;
}

function parseBoolean(value, fallback = false) {
  if (value === undefined) {
    return fallback;
  }

  const normalized = String(value).trim().toLowerCase();
  return ["1", "true", "yes", "on"].includes(normalized);
}

function parseInteger(value, fallback) {
  if (value === undefined) {
    return fallback;
  }

  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeBaseUrl(baseUrl) {
  return String(baseUrl || "").replace(/\/+$/, "");
}

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requireObject(value, name) {
  if (!isObject(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function optionalString(value, name) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error(`${name} must be a string`);
  }
  return value;
}

function requiredString(value, name) {
  const parsed = optionalString(value, name);
  if (!parsed) {
    throw new Error(`${name} is required`);
  }
  return parsed;
}

function optionalNumber(value, name) {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${name} must be a finite number`);
  }
  return value;
}

function requiredNumber(value, name) {
  const parsed = optionalNumber(value, name);
  if (parsed === undefined) {
    throw new Error(`${name} is required`);
  }
  return parsed;
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch (error) {
    return undefined;
  }
}

class QualysTotalAiClient {
  constructor(config) {
    this.baseUrl = normalizeBaseUrl(config.baseUrl);
    this.username = config.username;
    this.password = config.password;
    this.timeoutMs = config.timeoutMs;
    this.mockMode = config.mockMode;
    this.token = null;
    this.tokenIssuedAt = 0;
  }

  describeConfig() {
    return {
      baseUrl: this.baseUrl || null,
      usernameConfigured: Boolean(this.username),
      passwordConfigured: Boolean(this.password),
      mockMode: this.mockMode,
      timeoutMs: this.timeoutMs,
    };
  }

  async authenticate() {
    if (this.mockMode) {
      this.token = "mock-qualys-token";
      this.tokenIssuedAt = Date.now();
      return this.token;
    }

    if (!this.baseUrl || !this.username || !this.password) {
      throw new Error(
        "QUALYS_BASE_URL, QUALYS_USERNAME, and QUALYS_PASSWORD must be set when QUALYS_MOCK_MODE is disabled",
      );
    }

    if (this.token && Date.now() - this.tokenIssuedAt < 10 * 60 * 1000) {
      return this.token;
    }

    const body = new URLSearchParams({
      username: this.username,
      password: this.password,
    });

    const response = await this.fetchJson("/auth", {
      method: "POST",
      body,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      skipAuth: true,
    });

    const token =
      response?.token ||
      response?.access_token ||
      response?.jwtToken ||
      response?.bearerToken;

    if (!token || typeof token !== "string") {
      throw new Error("Qualys authentication succeeded but no JWT token was returned");
    }

    this.token = token;
    this.tokenIssuedAt = Date.now();
    return token;
  }

  async fetchJson(path, options = {}) {
    if (this.mockMode) {
      return this.mockResponse(path, options);
    }

    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = {
        accept: "application/json",
        ...(options.headers || {}),
      };

      if (!options.skipAuth) {
        const token = await this.authenticate();
        headers.Authorization = `Bearer ${token}`;
      }

      const response = await fetch(url, {
        method: options.method || "GET",
        headers,
        body: options.body,
        signal: controller.signal,
      });

      const raw = await response.text();
      const data = raw ? safeJsonParse(raw) ?? { raw } : {};

      if (!response.ok) {
        const message =
          data?.message ||
          data?.error ||
          data?.raw ||
          `Qualys API request failed with HTTP ${response.status}`;
        throw new Error(message);
      }

      return data;
    } finally {
      clearTimeout(timeout);
    }
  }

  mockResponse(path, options = {}) {
    const method = options.method || "GET";

    if (path === "/auth" && method === "POST") {
      return { token: "mock-qualys-token" };
    }

    if (path === "/ta/api/1.0/detection/count" && method === "POST") {
      return { count: 3 };
    }

    if (path === "/ta/api/1.0/detection/search" && method === "POST") {
      return {
        totalElements: 2,
        content: [
          {
            id: 12345,
            qid: 900001,
            name: "Prompt Injection Baseline",
            attack: "PromptInjection-Basic",
            severity: 5,
            result: "FAIL",
            failTestPercentage: 92,
            model: {
              id: 80791371,
              name: "Mock Bedrock Model",
            },
          },
          {
            id: 12346,
            qid: 900002,
            name: "Sensitive Data Exfiltration",
            attack: "DataExfiltration-PII",
            severity: 4,
            result: "FAIL",
            failTestPercentage: 66,
            model: {
              id: 80791371,
              name: "Mock Bedrock Model",
            },
          },
        ],
      };
    }

    if (path === "/ta/api/1.0/scan/launch" && method === "POST") {
      const parsedBody = options.body ? safeJsonParse(options.body) : {};
      return {
        id: 9173960,
        name: parsedBody?.name || "Mock TotalAI Scan",
        status: "NEW",
        scanReference: "tai/mock/9173960",
        targetModel: {
          id: parsedBody?.targetModelId || 80791371,
          name: "Mock Bedrock Model",
        },
        optionProfile: {
          id: parsedBody?.optionProfileId || 7868365,
          name: "Mock Default Option Profile",
        },
      };
    }

    if (path.startsWith("/ta/api/1.0/scan/") && method === "GET") {
      const id = path.split("/").pop();
      return {
        id: Number(id),
        name: "Mock TotalAI Scan",
        status: "FINISHED",
        scanDate: Date.now(),
        scanReference: `tai/mock/${id}`,
        targetModel: {
          id: 80791371,
          name: "Mock Bedrock Model",
        },
        optionProfile: {
          id: 7868365,
          name: "Mock Default Option Profile",
        },
      };
    }

    return {
      ok: true,
      mockMode: true,
      path,
      method,
    };
  }

  async getServerStatus() {
    const authReady = this.mockMode
      ? true
      : Boolean(this.baseUrl && this.username && this.password);

    return {
      config: this.describeConfig(),
      authReady,
      recommendedNextSteps: authReady
        ? [
            "Use launch_scan with a real targetModelId to trigger a TotalAI scan.",
            "Use get_scan to poll the scan until the status is FINISHED or ERROR.",
            "Use search_detections or count_detections with QQL filters after the scan completes.",
          ]
        : [
            "Set QUALYS_BASE_URL, QUALYS_USERNAME, and QUALYS_PASSWORD.",
            "Disable QUALYS_MOCK_MODE to call the live Qualys TotalAI APIs.",
          ],
    };
  }

  async countDetections(args) {
    const input = requireObject(args, "input");
    const filter = requireObject(input.filter || {}, "filter");

    return this.fetchJson("/ta/api/1.0/detection/count", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ filter }),
    });
  }

  async searchDetections(args) {
    const input = requireObject(args, "input");
    const payload = {
      filter: requireObject(input.filter || {}, "filter"),
      fields: optionalString(input.fields, "fields"),
      scrollInfo: optionalString(input.scrollInfo, "scrollInfo"),
      orderBy: optionalString(input.orderBy, "orderBy"),
      sortOrder: optionalString(input.sortOrder, "sortOrder"),
      size: optionalNumber(input.size, "size"),
    };

    return this.fetchJson("/ta/api/1.0/detection/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  }

  async launchScan(args) {
    const input = requireObject(args, "input");
    const payload = {
      name: requiredString(input.name, "name"),
      targetModelId: requiredNumber(input.targetModelId, "targetModelId"),
      optionProfileId: optionalNumber(input.optionProfileId, "optionProfileId"),
      scannerType: optionalString(input.scannerType, "scannerType"),
      selectedScannerAppliance: optionalNumber(
        input.selectedScannerAppliance,
        "selectedScannerAppliance",
      ),
      selectedScannerTags: optionalNumber(input.selectedScannerTags, "selectedScannerTags"),
    };

    return this.fetchJson("/ta/api/1.0/scan/launch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  }

  async getScan(args) {
    const input = requireObject(args, "input");
    const id = requiredNumber(input.id, "id");
    const fields = optionalString(input.fields, "fields");
    const suffix = fields ? `?fields=${encodeURIComponent(fields)}` : "";
    return this.fetchJson(`/ta/api/1.0/scan/${id}${suffix}`, {
      method: "GET",
    });
  }

  async rawRequest(args) {
    const input = requireObject(args, "input");
    const method = requiredString(input.method, "method").toUpperCase();
    const path = requiredString(input.path, "path");
    const body = input.body;

    return this.fetchJson(path, {
      method,
      headers: isObject(input.headers) ? input.headers : {},
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }
}

export function createClientFromEnv(env = process.env) {
  return new QualysTotalAiClient({
    baseUrl: env.QUALYS_BASE_URL,
    username: env.QUALYS_USERNAME,
    password: env.QUALYS_PASSWORD,
    timeoutMs: parseInteger(env.QUALYS_TIMEOUT_MS, 30000),
    mockMode: parseBoolean(env.QUALYS_MOCK_MODE, false),
  });
}

export const toolDefinitions = [
  {
    name: "server_status",
    description:
      "Return the current Qualys TotalAI MCP server configuration status and live/mock readiness.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "count_detections",
    description:
      "Call Qualys TotalAI POST /ta/api/1.0/detection/count using modelQql and detectionQql filters.",
    inputSchema: {
      type: "object",
      properties: {
        filter: {
          type: "object",
          properties: {
            modelQql: { type: "string" },
            detectionQql: { type: "string" },
          },
          additionalProperties: true,
        },
      },
      required: ["filter"],
      additionalProperties: false,
    },
  },
  {
    name: "search_detections",
    description:
      "Call Qualys TotalAI POST /ta/api/1.0/detection/search to retrieve findings with optional fields, sort, and paging.",
    inputSchema: {
      type: "object",
      properties: {
        filter: {
          type: "object",
          properties: {
            modelQql: { type: "string" },
            detectionQql: { type: "string" },
          },
          additionalProperties: true,
        },
        fields: { type: "string" },
        scrollInfo: { type: "string" },
        orderBy: { type: "string" },
        sortOrder: { type: "string" },
        size: { type: "number" },
      },
      required: ["filter"],
      additionalProperties: false,
    },
  },
  {
    name: "launch_scan",
    description:
      "Call Qualys TotalAI POST /ta/api/1.0/scan/launch to start a new scan on a model.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        targetModelId: { type: "number" },
        optionProfileId: { type: "number" },
        scannerType: { type: "string" },
        selectedScannerAppliance: { type: "number" },
        selectedScannerTags: { type: "number" },
      },
      required: ["name", "targetModelId"],
      additionalProperties: false,
    },
  },
  {
    name: "get_scan",
    description:
      "Call Qualys TotalAI GET /ta/api/1.0/scan/{id} to inspect scan status and metadata.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number" },
        fields: { type: "string" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "raw_request",
    description:
      "Make a direct Qualys API request for endpoints not yet wrapped by a dedicated MCP tool.",
    inputSchema: {
      type: "object",
      properties: {
        method: { type: "string" },
        path: { type: "string" },
        headers: { type: "object" },
        body: {},
      },
      required: ["method", "path"],
      additionalProperties: false,
    },
  },
];

function makeTextResult(value) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(value, null, 2),
      },
    ],
  };
}

function createToolHandlers(client) {
  return {
    server_status: () => client.getServerStatus(),
    count_detections: (args) => client.countDetections(args),
    search_detections: (args) => client.searchDetections(args),
    launch_scan: (args) => client.launchScan(args),
    get_scan: (args) => client.getScan(args),
    raw_request: (args) => client.rawRequest(args),
  };
}

export class StdioJsonRpcServer {
  constructor(options = {}) {
    this.input = options.input || process.stdin;
    this.output = options.output || process.stdout;
    this.client = options.client || createClientFromEnv(options.env || process.env);
    this.buffer = Buffer.alloc(0);
    this.initialized = false;
    this.keepAlive =
      options.keepAlive === false ? null : setInterval(() => {}, 60 * 60 * 1000);
    this.toolHandlers = createToolHandlers(this.client);
    this.input.on("data", (chunk) => this.onData(chunk));
  }

  start() {
    this.input.resume();
  }

  onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);

    while (true) {
      const headerEnd = this.buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        return;
      }

      const headerText = this.buffer.slice(0, headerEnd).toString("utf8");
      const contentLengthMatch = headerText.match(/Content-Length:\s*(\d+)/i);
      if (!contentLengthMatch) {
        this.buffer = Buffer.alloc(0);
        this.writeError(null, -32700, "Missing Content-Length header");
        return;
      }

      const contentLength = Number.parseInt(contentLengthMatch[1], 10);
      const frameLength = headerEnd + 4 + contentLength;
      if (this.buffer.length < frameLength) {
        return;
      }

      const body = this.buffer.slice(headerEnd + 4, frameLength).toString("utf8");
      this.buffer = this.buffer.slice(frameLength);

      const message = safeJsonParse(body);
      if (!message) {
        this.writeError(null, -32700, "Invalid JSON");
        continue;
      }

      this.handleMessage(message).catch((error) => {
        this.writeError(message.id ?? null, -32000, error.message);
      });
    }
  }

  async handleMessage(message) {
    if (!isObject(message)) {
      this.writeError(null, -32600, "Invalid Request");
      return;
    }

    if (message.method === "notifications/initialized") {
      this.initialized = true;
      return;
    }

    if (!("id" in message)) {
      return;
    }

    switch (message.method) {
      case "initialize":
        this.writeResult(message.id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {
            tools: {},
          },
          serverInfo: SERVER_INFO,
        });
        return;

      case "ping":
        this.writeResult(message.id, {});
        return;

      case "tools/list":
        this.writeResult(message.id, {
          tools: toolDefinitions,
        });
        return;

      case "tools/call": {
        const params = requireObject(message.params, "params");
        const toolName = requiredString(params.name, "params.name");
        const handler = this.toolHandlers[toolName];

        if (!handler) {
          this.writeError(message.id, -32601, `Unknown tool: ${toolName}`);
          return;
        }

        try {
          const result = await handler(params.arguments || {});
          this.writeResult(message.id, makeTextResult(result));
        } catch (error) {
          this.writeResult(message.id, {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error: error.message,
                  },
                  null,
                  2,
                ),
              },
            ],
            isError: true,
          });
        }
        return;
      }

      default:
        this.writeError(message.id, -32601, `Method not found: ${message.method}`);
    }
  }

  writeResult(id, result) {
    this.writeMessage({
      jsonrpc: "2.0",
      id,
      result,
    });
  }

  writeError(id, code, message) {
    this.writeMessage({
      jsonrpc: "2.0",
      id,
      error: {
        code,
        message,
      },
    });
  }

  writeMessage(message) {
    const body = Buffer.from(JSON.stringify(message), "utf8");
    const header = Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "utf8");
    this.output.write(Buffer.concat([header, body]));
  }
}

function createJsonRpcProcessor(client) {
  const toolHandlers = createToolHandlers(client);

  return async (message) => {
    if (!isObject(message)) {
      return {
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32600,
          message: "Invalid Request",
        },
      };
    }

    if (message.method === "notifications/initialized") {
      return null;
    }

    if (!("id" in message)) {
      return null;
    }

    switch (message.method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: {
              tools: {},
            },
            serverInfo: SERVER_INFO,
          },
        };

      case "ping":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {},
        };

      case "tools/list":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            tools: toolDefinitions,
          },
        };

      case "tools/call": {
        const params = requireObject(message.params, "params");
        const toolName = requiredString(params.name, "params.name");
        const handler = toolHandlers[toolName];

        if (!handler) {
          return {
            jsonrpc: "2.0",
            id: message.id,
            error: {
              code: -32601,
              message: `Unknown tool: ${toolName}`,
            },
          };
        }

        try {
          const result = await handler(params.arguments || {});
          return {
            jsonrpc: "2.0",
            id: message.id,
            result: makeTextResult(result),
          };
        } catch (error) {
          return {
            jsonrpc: "2.0",
            id: message.id,
            result: {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({ error: error.message }, null, 2),
                },
              ],
              isError: true,
            },
          };
        }
      }

      default:
        return {
          jsonrpc: "2.0",
          id: message.id,
          error: {
            code: -32601,
            message: `Method not found: ${message.method}`,
          },
        };
    }
  };
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

export function startHttpServer(options = {}) {
  const client = options.client || createClientFromEnv(options.env || process.env);
  const host = options.host || readEnv("MCP_HOST", "0.0.0.0");
  const port = options.port || parseInteger(readEnv("MCP_PORT"), 8765);
  const processMessage = createJsonRpcProcessor(client);

  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          ok: true,
          name: SERVER_INFO.name,
          version: SERVER_INFO.version,
          transport: "http",
          host,
          port,
        }),
      );
      return;
    }

    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          name: SERVER_INFO.name,
          version: SERVER_INFO.version,
          transport: "http",
          endpoints: {
            rpc: "/mcp",
            health: "/health",
          },
        }),
      );
      return;
    }

    if (req.method === "POST" && req.url === "/mcp") {
      const rawBody = await readRequestBody(req);
      const message = safeJsonParse(rawBody);

      if (!message) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32700,
              message: "Invalid JSON",
            },
          }),
        );
        return;
      }

      const reply = await processMessage(message);
      if (reply === null) {
        res.writeHead(202, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ accepted: true }));
        return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(reply));
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });

  server.listen(port, host, () => {
    process.stdout.write(
      `HTTP MCP server listening on http://${host}:${port} and POST /mcp\n`,
    );
  });

  return server;
}

const isMainEntry =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMainEntry) {
  const transport = readEnv("MCP_TRANSPORT", "stdio");
  if (transport === "http") {
    startHttpServer();
  } else {
    new StdioJsonRpcServer().start();
  }
}
