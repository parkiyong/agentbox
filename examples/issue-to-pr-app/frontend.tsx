import React from "react";
import {
  AgentBoxProvider,
  ApprovalBanner,
  DiffViewer,
  SessionHeader,
  SessionTimeline,
  SteerInput,
} from "@agentbox/react";

export interface EmbeddedAutoFixViewProps {
  clientToken: string;
  apiBaseUrl?: string;
}

/**
 * Drop-in white-label end-customer SWE agent view powered by `@agentbox/react`.
 * Uses ONLY a short-lived session-scoped clientToken — zero org API keys in the browser.
 */
export function EmbeddedAutoFixView({
  clientToken,
  apiBaseUrl = "http://127.0.0.1:8080",
}: EmbeddedAutoFixViewProps) {
  return (
    <AgentBoxProvider clientToken={clientToken} apiBaseUrl={apiBaseUrl}>
      <div
        style={{
          maxWidth: 960,
          margin: "0 auto",
          border: "1px solid #e5e7eb",
          borderRadius: 12,
          overflow: "hidden",
        }}
      >
        <SessionHeader showBudgetBar showStatus />
        <ApprovalBanner />
        <SessionTimeline />
        <DiffViewer mode="split" />
        <SteerInput placeholder="Guide the agent or answer its question..." />
      </div>
    </AgentBoxProvider>
  );
}
