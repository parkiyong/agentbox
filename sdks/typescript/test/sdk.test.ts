import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { AgentBoxClient, parseSSEFrame, verifyWebhookSignature } from "../src/index.js";

test("verifyWebhookSignature validates valid and rejects tampered payloads", () => {
  const secret = "whsec_demo_123";
  const body = JSON.stringify({ id: "evt_1", type: "session.completed" });
  const sig = "sha256=" + createHmac("sha256", secret).update(body).digest("hex");

  assert.equal(verifyWebhookSignature(secret, body, sig), true);
  assert.equal(verifyWebhookSignature(secret, body + "x", sig), false);
  assert.equal(verifyWebhookSignature("wrong", body, sig), false);
});

test("parseSSEFrame decodes canonical event envelopes", () => {
  const frame = [
    "id: evt_01",
    "event: approval.required",
    'data: {"id":"evt_01","seq":42,"timestamp":"2026-11-21T00:00:00Z","session_id":"ses_1","customer_id":"cust_1","type":"approval.required","payload":{"approval_id":"apr_1","action":"git.push","summary":"Push fix"}}',
  ].join("\n");
  const evt = parseSSEFrame(frame);
  assert.ok(evt);
  assert.equal(evt.id, "evt_01");
  assert.equal(evt.seq, 42);
  assert.equal(evt.type, "approval.required");
});

test("AgentBoxClient streams SSE events with Last-Event-ID header", async () => {
  let capturedLastEventId: string | null = null;
  const fakeFetch: typeof fetch = async (_url, init) => {
    const hdrs = new Headers(init?.headers);
    capturedLastEventId = hdrs.get("Last-Event-ID");
    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(
          encoder.encode(
            'id: evt_2\nevent: session.completed\ndata: {"id":"evt_2","seq":2,"timestamp":"2026-11-21T00:00:00Z","session_id":"ses_1","customer_id":"cust_1","type":"session.completed","payload":{"status":"completed"}}\n\n',
          ),
        );
        controller.close();
      },
    });
    return new Response(stream, {
      status: 200,
      headers: { "Content-Type": "text/event-stream" },
    });
  };

  const client = new AgentBoxClient({
    apiBaseUrl: "http://localhost:8080",
    clientToken: "jwt.tok.sig",
    fetchImpl: fakeFetch,
  });

  const received = [];
  for await (const evt of client.sessions.events("ses_1", { lastEventId: "evt_1" })) {
    received.push(evt);
  }
  assert.equal(capturedLastEventId, "evt_1");
  assert.equal(received.length, 1);
  assert.equal(received[0].type, "session.completed");
});
