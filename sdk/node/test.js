"use strict";
const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const { Client } = require("./watchtower");

function withServer(fn) {
  return new Promise((resolve, reject) => {
    const captured = {};
    const server = http.createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => {
        captured.path = req.url;
        captured.auth = req.headers.authorization;
        captured.body = JSON.parse(data);
        res.writeHead(200).end();
      });
    });
    server.listen(0, "127.0.0.1", () => {
      captured.port = server.address().port;
      fn(server, captured).then(resolve, reject);
    });
  });
}

test("capture posts expected payload", async () => {
  await withServer(async (server, captured) => {
    const client = new Client({
      endpoint: `http://127.0.0.1:${captured.port}`,
      token: "tok",
      host_id: "h-1",
      service: "api",
    });
    const ok = await client.capture("error", "ValueError", "bad input", [
      { file: "app.js", line: 42, function: "validate" },
    ]);
    assert.strictEqual(ok, true);
    assert.strictEqual(captured.path, "/v1/errors");
    assert.strictEqual(captured.auth, "Bearer tok");
    assert.strictEqual(captured.body.host_id, "h-1");
    assert.strictEqual(captured.body.service, "api");
    assert.strictEqual(captured.body.exception.type, "ValueError");
    assert.strictEqual(captured.body.exception.frames[0].file, "app.js");
    server.close();
  });
});

test("no config returns false without crashing", async () => {
  const client = new Client({});
  assert.strictEqual(await client.capture("error", "T", "m"), false);
});

test("server down retries then resolves false", async () => {
  const client = new Client({
    endpoint: "http://127.0.0.1:1",
    token: "tok",
  });
  assert.strictEqual(await client.capture("error", "T", "m"), false);
});

test("captureEvent posts a custom event", async () => {
  await withServer(async (server, captured) => {
    const client = new Client({
      endpoint: `http://127.0.0.1:${captured.port}`,
      token: "tok",
      service: "payment-api",
      environment: "production",
    });
    const ok = await client.captureEvent({
      kind: "payment.request_failed",
      summary: "Payment request failed",
      severity: "warning",
      subject: "merchant:mer_1",
      attributes: { merchant_id: "mer_1", status_code: 502 },
      measurements: { latency_ms: 812 },
    });
    assert.strictEqual(ok, true);
    assert.strictEqual(captured.path, "/v1/events");
    assert.strictEqual(captured.body.kind, "payment.request_failed");
    assert.strictEqual(captured.body.source, "payment-api");
    assert.strictEqual(captured.body.environment, "production");
    assert.strictEqual(captured.body.attributes.status_code, 502);
    assert.strictEqual(captured.body.measurements.latency_ms, 812);
    server.close();
  });
});
