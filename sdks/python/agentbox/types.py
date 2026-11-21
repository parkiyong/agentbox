from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AgentBoxEvent:
    id: str
    seq: int
    timestamp: str
    session_id: str
    customer_id: str
    type: str
    payload: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentBoxEvent":
        return cls(
            id=str(data.get("id", "")),
            seq=int(data.get("seq", 0)),
            timestamp=str(data.get("timestamp", "")),
            session_id=str(data.get("session_id", "")),
            customer_id=str(data.get("customer_id", "")),
            type=str(data.get("type", "")),
            payload=dict(data.get("payload") or {}),
        )


@dataclass(slots=True)
class RepoSpec:
    url: str | None = None
    base_branch: str | None = None
    local_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in {
            "url": self.url,
            "base_branch": self.base_branch,
            "local_path": self.local_path,
        }.items() if v is not None}


@dataclass(slots=True)
class LimitsConfig:
    max_credits: float | None = None
    max_turns: int | None = None
    max_wall_clock_seconds: int | None = None
    idle_hibernate_seconds: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in {
            "max_credits": self.max_credits,
            "max_turns": self.max_turns,
            "max_wall_clock_seconds": self.max_wall_clock_seconds,
            "idle_hibernate_seconds": self.idle_hibernate_seconds,
        }.items() if v is not None}


@dataclass(slots=True)
class Session:
    id: str
    org_id: str
    customer_id: str
    workspace_id: str
    blueprint_name: str
    task: str
    status: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Session":
        return cls(
            id=str(data["id"]),
            org_id=str(data.get("org_id", "")),
            customer_id=str(data.get("customer_id", "")),
            workspace_id=str(data.get("workspace_id", "")),
            blueprint_name=str(data.get("blueprint_name", "")),
            task=str(data.get("task", "")),
            status=str(data.get("status", "")),
            raw=dict(data),
        )
