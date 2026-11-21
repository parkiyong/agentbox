from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator

from .types import AgentBoxEvent, LimitsConfig, RepoSpec, Session


class AgentBoxError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"AgentBox API error ({status}): {message}")
        self.status = status
        self.message = message


class AgentBoxClient:
    """Zero-dependency Python client for the AgentBox Control Plane REST & SSE API."""

    def __init__(
        self,
        api_base_url: str,
        api_key: str | None = None,
        client_token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = api_base_url.rstrip("/")
        self.token = api_key or client_token or ""
        self.timeout = timeout

    def _headers(self, content_type: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _request(
        self,
        method: str,
        path: str,
        body: Any = None,
        content_type: str = "application/json",
    ) -> dict[str, Any]:
        data: bytes | None = None
        headers = self._headers(content_type if body is not None else None)
        if body is not None:
            if isinstance(body, (bytes, bytearray)):
                data = bytes(body)
            elif isinstance(body, str):
                data = body.encode("utf-8")
            else:
                data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            msg = exc.read().decode("utf-8", errors="replace")
            raise AgentBoxError(exc.code, msg) from exc

    # --- Blueprints ---

    def put_blueprint(self, name: str, yaml_or_spec: str | dict[str, Any]) -> dict[str, Any]:
        ct = "application/yaml" if isinstance(yaml_or_spec, str) else "application/json"
        return self._request("PUT", f"/v1/blueprints/{urllib.parse.quote(name)}", yaml_or_spec, ct)

    def get_blueprint(self, name: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/blueprints/{urllib.parse.quote(name)}")

    def list_blueprints(self) -> list[dict[str, Any]]:
        return list(self._request("GET", "/v1/blueprints").get("blueprints", []))

    # --- Sessions ---

    def create_session(
        self,
        *,
        customer_id: str,
        blueprint: str,
        task: str,
        repo: RepoSpec | dict[str, Any] | None = None,
        limits: LimitsConfig | dict[str, Any] | None = None,
        webhook_url: str | None = None,
        webhook_secret: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> Session:
        payload: dict[str, Any] = {
            "customer_id": customer_id,
            "blueprint": blueprint,
            "task": task,
        }
        if repo is not None:
            payload["repo"] = repo.to_dict() if isinstance(repo, RepoSpec) else repo
        if limits is not None:
            payload["limits"] = limits.to_dict() if isinstance(limits, LimitsConfig) else limits
        if webhook_url:
            payload["webhook_url"] = webhook_url
        if webhook_secret:
            payload["webhook_secret"] = webhook_secret
        if metadata:
            payload["metadata"] = metadata
        return Session.from_dict(self._request("POST", "/v1/sessions", payload))

    def get_session(self, session_id: str) -> Session:
        return Session.from_dict(self._request("GET", f"/v1/sessions/{urllib.parse.quote(session_id)}"))

    def create_client_token(
        self,
        session_id: str,
        *,
        scopes: list[str] | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if scopes is not None:
            payload["scopes"] = scopes
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        return self._request("POST", f"/v1/sessions/{urllib.parse.quote(session_id)}/client-token", payload)

    def send_message(self, session_id: str, content: str, sender: str | None = None) -> dict[str, Any]:
        payload = {"content": content}
        if sender:
            payload["sender"] = sender
        return self._request("POST", f"/v1/sessions/{urllib.parse.quote(session_id)}/messages", payload)

    def resolve_approval(
        self,
        session_id: str,
        approval_id: str,
        decision: str,
        feedback: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"decision": decision}
        if feedback:
            payload["feedback"] = feedback
        return self._request(
            "POST",
            f"/v1/sessions/{urllib.parse.quote(session_id)}/approvals/{urllib.parse.quote(approval_id)}",
            payload,
        )

    def resume_session(
        self,
        session_id: str,
        *,
        add_credits: float | None = None,
        add_turns: int | None = None,
        add_wall_clock_seconds: int | None = None,
        message: str | None = None,
    ) -> Session:
        payload = {
            k: v
            for k, v in {
                "add_credits": add_credits,
                "add_turns": add_turns,
                "add_wall_clock_seconds": add_wall_clock_seconds,
                "message": message,
            }.items()
            if v is not None
        }
        return Session.from_dict(
            self._request("POST", f"/v1/sessions/{urllib.parse.quote(session_id)}/resume", payload)
        )

    def fork_session(
        self,
        session_id: str,
        *,
        checkpoint_id: str | None = None,
        task: str | None = None,
    ) -> Session:
        payload = {
            k: v
            for k, v in {"checkpoint_id": checkpoint_id, "task": task}.items()
            if v is not None
        }
        return Session.from_dict(
            self._request("POST", f"/v1/sessions/{urllib.parse.quote(session_id)}/fork", payload)
        )

    def get_diff(self, session_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/sessions/{urllib.parse.quote(session_id)}/diff")

    def cancel_session(self, session_id: str) -> Session:
        return Session.from_dict(
            self._request("POST", f"/v1/sessions/{urllib.parse.quote(session_id)}/cancel", {})
        )

    def get_customer_usage(self, customer_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/customers/{urllib.parse.quote(customer_id)}/usage")

    def stream_events(
        self,
        session_id: str,
        *,
        last_event_id: str | None = None,
    ) -> Iterator[AgentBoxEvent]:
        headers = self._headers()
        headers["Accept"] = "text/event-stream"
        if last_event_id:
            headers["Last-Event-ID"] = last_event_id
        req = urllib.request.Request(
            f"{self.base_url}/v1/sessions/{urllib.parse.quote(session_id)}/events",
            headers=headers,
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=None) as resp:
                data_lines: list[str] = []
                for raw_line in resp:
                    line = raw_line.decode("utf-8").rstrip("\r\n")
                    if line == "":
                        if data_lines:
                            raw_json = "\n".join(data_lines)
                            data_lines.clear()
                            try:
                                yield AgentBoxEvent.from_dict(json.loads(raw_json))
                            except json.JSONDecodeError:
                                pass
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].lstrip())
        except urllib.error.HTTPError as exc:
            msg = exc.read().decode("utf-8", errors="replace")
            raise AgentBoxError(exc.code, msg) from exc
