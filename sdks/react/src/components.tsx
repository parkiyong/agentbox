import React, { useState } from "react";
import { useAgentBox } from "./context.js";

export interface SessionHeaderProps {
  showBudgetBar?: boolean;
  showStatus?: boolean;
  className?: string;
}

export function SessionHeader({
  showBudgetBar = true,
  showStatus = true,
  className,
}: SessionHeaderProps) {
  const { session, status, connected } = useAgentBox();
  const used = session?.usage.credits_used ?? 0;
  const cap = session?.limits.max_credits ?? 500;
  const pct = Math.min(100, Math.round((used / Math.max(1, cap)) * 100));

  return (
    <div
      className={className}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "12px 16px",
        borderBottom: "1px solid var(--abx-border, #e5e7eb)",
        fontFamily: "var(--abx-font, system-ui, sans-serif)",
      }}
    >
      <div>
        <div style={{ fontWeight: 600, fontSize: 15 }}>
          {session?.blueprint_name ?? "AgentBox SWE Session"}
        </div>
        <div style={{ fontSize: 12, color: "var(--abx-muted, #6b7280)" }}>
          {session?.id ?? "Connecting..."} {connected ? "• Live" : ""}
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        {showBudgetBar && (
          <div style={{ minWidth: 160 }}>
            <div style={{ fontSize: 11, color: "var(--abx-muted, #6b7280)" }}>
              Credits: {used.toFixed(1)} / {cap}
            </div>
            <div
              style={{
                height: 6,
                background: "var(--abx-track, #e5e7eb)",
                borderRadius: 999,
                overflow: "hidden",
                marginTop: 4,
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${pct}%`,
                  background:
                    pct > 85
                      ? "var(--abx-warn, #f59e0b)"
                      : "var(--abx-accent, #2563eb)",
                }}
              />
            </div>
          </div>
        )}
        {showStatus && (
          <span
            style={{
              padding: "4px 10px",
              borderRadius: 999,
              fontSize: 12,
              fontWeight: 600,
              background: "var(--abx-badge-bg, #eef2ff)",
              color: "var(--abx-badge-fg, #3730a3)",
            }}
          >
            {status}
          </span>
        )}
      </div>
    </div>
  );
}

export interface SessionTimelineProps {
  className?: string;
}

export function SessionTimeline({ className }: SessionTimelineProps) {
  const { plan, events } = useAgentBox();
  const [expandedTerminal, setExpandedTerminal] = useState(false);

  const terminalChunks = events.filter((e) => e.type === "terminal.chunk");
  const timelineEvents = events.filter(
    (e) =>
      e.type === "tool.started" ||
      e.type === "tool.completed" ||
      e.type === "checkpoint.created" ||
      e.type === "agent.message" ||
      e.type === "pr.created",
  );

  return (
    <div
      className={className}
      style={{
        padding: 16,
        display: "flex",
        flexDirection: "column",
        gap: 12,
        fontFamily: "var(--abx-font, system-ui, sans-serif)",
      }}
    >
      {plan.length > 0 && (
        <div
          style={{
            padding: 12,
            borderRadius: 8,
            border: "1px solid var(--abx-border, #e5e7eb)",
          }}
        >
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 8 }}>
            Execution Plan
          </div>
          {plan.map((step) => (
            <div key={step.id} style={{ fontSize: 13, padding: "2px 0" }}>
              {step.status === "completed"
                ? "[x]"
                : step.status === "in_progress"
                  ? "[~]"
                  : "[ ]"}{" "}
              {step.title}
            </div>
          ))}
        </div>
      )}

      {timelineEvents.map((evt) => (
        <div
          key={evt.id}
          style={{
            fontSize: 13,
            padding: "8px 10px",
            borderRadius: 6,
            background: "var(--abx-surface, #f9fafb)",
            border: "1px solid var(--abx-border, #e5e7eb)",
          }}
        >
          <strong style={{ marginRight: 8 }}>{evt.type}</strong>
          <span>
            {evt.type === "agent.message"
              ? String(evt.payload.content ?? "")
              : evt.type === "tool.started" || evt.type === "tool.completed"
                ? String(evt.payload.tool ?? "")
                : evt.type === "checkpoint.created"
                  ? `Checkpoint ${String(evt.payload.checkpoint_id ?? "")}: ${String(evt.payload.message ?? "")}`
                  : JSON.stringify(evt.payload)}
          </span>
        </div>
      ))}

      {terminalChunks.length > 0 && (
        <div
          style={{
            border: "1px solid var(--abx-border, #e5e7eb)",
            borderRadius: 8,
            overflow: "hidden",
          }}
        >
          <button
            type="button"
            onClick={() => setExpandedTerminal((v) => !v)}
            style={{
              width: "100%",
              textAlign: "left",
              padding: "8px 12px",
              background: "var(--abx-surface, #f3f4f6)",
              border: "none",
              cursor: "pointer",
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            Terminal Output ({terminalChunks.length} chunks){" "}
            {expandedTerminal ? "▲" : "▼"}
          </button>
          {expandedTerminal && (
            <pre
              style={{
                margin: 0,
                padding: 12,
                background: "#111827",
                color: "#e5e7eb",
                fontSize: 12,
                overflowX: "auto",
              }}
            >
              {terminalChunks.map((c) => String(c.payload.data ?? "")).join("")}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export interface ApprovalBannerProps {
  className?: string;
}

export function ApprovalBanner({ className }: ApprovalBannerProps) {
  const { pendingApproval, budgetAlert, approve, reject, resume } =
    useAgentBox();
  const [feedback, setFeedback] = useState("");
  const [busy, setBusy] = useState(false);

  if (!pendingApproval && !budgetAlert) return null;

  if (budgetAlert) {
    return (
      <div
        className={className}
        style={{
          margin: "0 16px 12px",
          padding: 14,
          borderRadius: 8,
          background: "#fffbeb",
          border: "1px solid #f59e0b",
          fontFamily: "var(--abx-font, system-ui, sans-serif)",
        }}
      >
        <div style={{ fontWeight: 600, fontSize: 14 }}>
          Session Paused: {budgetAlert.limit_type} limit reached
        </div>
        <div style={{ fontSize: 13, marginTop: 4 }}>{budgetAlert.message}</div>
        <button
          type="button"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await resume({ addCredits: 250, addTurns: 20 });
            } finally {
              setBusy(false);
            }
          }}
          style={{
            marginTop: 10,
            padding: "6px 14px",
            borderRadius: 6,
            border: "none",
            background: "#d97706",
            color: "#ffffff",
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Top Up & Resume Session
        </button>
      </div>
    );
  }

  return (
    <div
      className={className}
      style={{
        margin: "0 16px 12px",
        padding: 14,
        borderRadius: 8,
        background: "#eff6ff",
        border: "1px solid #3b82f6",
        fontFamily: "var(--abx-font, system-ui, sans-serif)",
      }}
    >
      <div style={{ fontWeight: 600, fontSize: 14 }}>
        Approval Required: {pendingApproval!.action}
      </div>
      <div style={{ fontSize: 13, marginTop: 4 }}>
        {pendingApproval!.summary}
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <input
          type="text"
          value={feedback}
          onChange={(e) => setFeedback(e.target.value)}
          placeholder="Optional feedback..."
          style={{
            flex: 1,
            padding: "6px 10px",
            borderRadius: 6,
            border: "1px solid #cbd5e1",
          }}
        />
        <button
          type="button"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await approve(pendingApproval!.approval_id, feedback);
              setFeedback("");
            } finally {
              setBusy(false);
            }
          }}
          style={{
            padding: "6px 14px",
            borderRadius: 6,
            border: "none",
            background: "#16a34a",
            color: "#fff",
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Approve
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await reject(pendingApproval!.approval_id, feedback);
              setFeedback("");
            } finally {
              setBusy(false);
            }
          }}
          style={{
            padding: "6px 14px",
            borderRadius: 6,
            border: "none",
            background: "#dc2626",
            color: "#fff",
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Reject
        </button>
      </div>
    </div>
  );
}

export interface DiffViewerProps {
  mode?: "split" | "unified";
  className?: string;
}

export function DiffViewer({ mode = "unified", className }: DiffViewerProps) {
  const { diffs } = useAgentBox();
  if (diffs.length === 0) return null;

  return (
    <div
      className={className}
      data-diff-mode={mode}
      style={{
        padding: "0 16px 16px",
        display: "flex",
        flexDirection: "column",
        gap: 12,
        fontFamily: "var(--abx-mono, ui-monospace, monospace)",
      }}
    >
      {diffs.map((d) => (
        <div
          key={d.path}
          style={{
            border: "1px solid var(--abx-border, #e5e7eb)",
            borderRadius: 8,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              padding: "8px 12px",
              background: "var(--abx-surface, #f9fafb)",
              borderBottom: "1px solid var(--abx-border, #e5e7eb)",
              fontSize: 12,
              fontWeight: 600,
              display: "flex",
              justifyContent: "space-between",
            }}
          >
            <span>{d.path}</span>
            <span>
              <span style={{ color: "#16a34a" }}>+{d.insertions}</span>{" "}
              <span style={{ color: "#dc2626" }}>-{d.deletions}</span>
            </span>
          </div>
          <pre
            style={{
              margin: 0,
              padding: 12,
              fontSize: 12,
              overflowX: "auto",
              lineHeight: 1.5,
            }}
          >
            {d.unified.split("\n").map((line, i) => {
              const bg = line.startsWith("+")
                ? "#dcfce7"
                : line.startsWith("-")
                  ? "#fee2e2"
                  : "transparent";
              return (
                <div key={i} style={{ background: bg }}>
                  {line}
                </div>
              );
            })}
          </pre>
        </div>
      ))}
    </div>
  );
}

export interface SteerInputProps {
  placeholder?: string;
  className?: string;
}

export function SteerInput({
  placeholder = "Guide the agent or answer its question...",
  className,
}: SteerInputProps) {
  const { steer, inputPrompt, status } = useAgentBox();
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);

  const disabled =
    sending ||
    status === "completed" ||
    status === "failed" ||
    status === "cancelled";

  return (
    <form
      className={className}
      onSubmit={async (e) => {
        e.preventDefault();
        if (!text.trim() || disabled) return;
        setSending(true);
        try {
          await steer(text.trim());
          setText("");
        } finally {
          setSending(false);
        }
      }}
      style={{
        padding: "12px 16px",
        borderTop: "1px solid var(--abx-border, #e5e7eb)",
        display: "flex",
        flexDirection: "column",
        gap: 6,
      }}
    >
      {inputPrompt && (
        <div style={{ fontSize: 12, color: "#1d4ed8", fontWeight: 500 }}>
          Agent question: {inputPrompt}
        </div>
      )}
      <div style={{ display: "flex", gap: 8 }}>
        <input
          type="text"
          value={text}
          disabled={disabled}
          onChange={(e) => setText(e.target.value)}
          placeholder={placeholder}
          style={{
            flex: 1,
            padding: "8px 12px",
            borderRadius: 6,
            border: "1px solid var(--abx-border, #d1d5db)",
          }}
        />
        <button
          type="submit"
          disabled={disabled || !text.trim()}
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "none",
            background: "var(--abx-accent, #2563eb)",
            color: "#ffffff",
            fontWeight: 600,
            cursor: disabled ? "not-allowed" : "pointer",
          }}
        >
          Send
        </button>
      </div>
    </form>
  );
}
