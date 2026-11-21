import hashlib
import hmac
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from agentbox import AgentBoxClient, verify_webhook_signature


class TestAgentBoxPythonSDK(unittest.TestCase):
    def test_verify_webhook_signature(self) -> None:
        secret = "whsec_py_test"
        body = b'{"id":"evt_1","type":"session.completed"}'
        sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_webhook_signature(secret, body, sig))
        self.assertFalse(verify_webhook_signature(secret, body + b"!", sig))

    def test_rest_and_sse_streaming(self) -> None:
        captured_headers: dict[str, str] = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):  # noqa: A002
                return

            def do_POST(self):
                if self.path == "/v1/sessions":
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps(
                            {
                                "id": "ses_py1",
                                "org_id": "org_1",
                                "customer_id": "cust_1",
                                "workspace_id": "wksp_1",
                                "blueprint_name": "acme-swe",
                                "task": "fix bug",
                                "status": "queued",
                            }
                        ).encode()
                    )

            def do_GET(self):
                if self.path == "/v1/sessions/ses_py1/events":
                    captured_headers["last_event_id"] = self.headers.get("Last-Event-ID", "")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    evt = {
                        "id": "evt_2",
                        "seq": 2,
                        "timestamp": "2026-11-21T00:00:00Z",
                        "session_id": "ses_py1",
                        "customer_id": "cust_1",
                        "type": "session.completed",
                        "payload": {"status": "completed"},
                    }
                    self.wfile.write(f"id: evt_2\nevent: session.completed\ndata: {json.dumps(evt)}\n\n".encode())

        srv = HTTPServer(("127.0.0.1", 0), Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            client = AgentBoxClient(f"http://127.0.0.1:{srv.server_port}", api_key="abx_test")
            sess = client.create_session(customer_id="cust_1", blueprint="acme-swe", task="fix bug")
            self.assertEqual(sess.id, "ses_py1")

            events = list(client.stream_events("ses_py1", last_event_id="evt_1"))
            self.assertEqual(captured_headers["last_event_id"], "evt_1")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].type, "session.completed")
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
