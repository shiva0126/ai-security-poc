#!/usr/bin/env node

import { PassThrough } from "node:stream";
import { StdioJsonRpcServer, createClientFromEnv } from "./server.js";

function encodeMessage(message) {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  return Buffer.concat([
    Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, "utf8"),
    body,
  ]);
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
        throw new Error("Smoke test received a frame without Content-Length");
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

const serverInput = new PassThrough();
const serverOutput = new PassThrough();
const responses = new Map();
let nextId = 1;

serverOutput.on(
  "data",
  createFrameReader((message) => {
    if ("id" in message && responses.has(message.id)) {
      const resolve = responses.get(message.id);
      responses.delete(message.id);
      resolve(message);
    }
  }),
);

const server = new StdioJsonRpcServer({
  input: serverInput,
  output: serverOutput,
  keepAlive: false,
  client: createClientFromEnv({
    ...process.env,
    QUALYS_MOCK_MODE: process.env.QUALYS_MOCK_MODE || "1",
  }),
});

server.start();

function waitForResponse(id, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      responses.delete(id);
      reject(new Error(`Timed out waiting for response ${id}`));
    }, timeoutMs);

    responses.set(id, (message) => {
      clearTimeout(timeout);
      resolve(message);
    });
  });
}

function send(method, params) {
  const id = nextId++;
  const pending = waitForResponse(id);
  serverInput.write(
    encodeMessage({
      jsonrpc: "2.0",
      id,
      method,
      params,
    }),
  );
  return pending;
}

async function main() {
  const init = await send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: {
      name: "smoke-test",
      version: "0.1.0",
    },
  });

  serverInput.write(
    encodeMessage({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    }),
  );

  const tools = await send("tools/list", {});
  const status = await send("tools/call", {
    name: "server_status",
    arguments: {},
  });
  const launch = await send("tools/call", {
    name: "launch_scan",
    arguments: {
      name: "Smoke Test Scan",
      targetModelId: 80791371,
    },
  });

  console.log(
    JSON.stringify(
      {
        initialize: init.result?.serverInfo,
        tools: tools.result?.tools?.map((tool) => tool.name),
        serverStatus: JSON.parse(status.result.content[0].text),
        launchScan: JSON.parse(launch.result.content[0].text),
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
