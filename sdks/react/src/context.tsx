import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  AgentBoxClient,
  type AgentBoxEvent,
  type ApprovalRequiredPayload,
  type BudgetExceededPayload,
  type FileDiffPayload,
  type PlanStep,
  type PlanUpdatedPayload,
  type Session,
  type SessionStatus,
} from "@agentbox/sdk";

export interface AgentBoxContextValue {
  sessionId: string | null;
  session: Session | null;
  status: SessionStatus;
  events: AgentBoxEvent[];
  plan: PlanStep[];
  diffs: FileDiffPayload[];
  pendingApproval: ApprovalRequiredPayload | null;
  budgetAlert: BudgetExceededPayload | null;
  inputPrompt: string | null;
  connected: boolean;
  error: string | null;
  steer: (content: string) => Promise<void>;
  approve: (approvalId: string, feedback?: string) => Promise<void>;
  reject: (approvalId: string, feedback?: string) => Promise<void>;
  resume: (opts?: { addCredits?: number; addTurns?: number; message?: string }) => Promise<void>;
}

const AgentBoxContext = createContext<AgentBoxContextValue | null>(null);

export interface AgentBoxProviderProps {
  clientToken: string;
  apiBaseUrl: string;
  sessionId?: string;
  children: React.ReactNode;
}

function decodeSessionIdFromToken(jwt: string): string | null {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(base64);
    const claims = JSON.parse(json) as { session_id?: string };
    return claims.session_id ?? null;
  } catch {
    return null;
  }
}

export function AgentBoxProvider({
  clientToken,
  apiBaseUrl,
  sessionId: explicitSessionId,
  children,
}: AgentBoxProviderProps) {
  const sessionId = useMemo(
    () => explicitSessionId ?? decodeSessionIdFromToken(clientToken),
    [explicitSessionId, clientToken],
  );

  const client = useMemo(
    () => new AgentBoxClient({ apiBaseUrl, clientToken }),
    [apiBaseUrl, clientToken],
  );

  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState<SessionStatus>("queued");
  const [events, setEvents] = useState<AgentBoxEvent[]>([]);
  const [plan, setPlan] = useState<PlanStep[]>([]);
  const [diffs, setDiffs] = useState<FileDiffPayload[]>([]);
  const [pendingApproval, setPendingApproval] =
    useState<ApprovalRequiredPayload | null>(null);
  const [budgetAlert, setBudgetAlert] = useState<BudgetExceededPayload | null>(
    null,
  );
  const [inputPrompt, setInputPrompt] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastEventIdRef = useRef<string | undefined>(undefined);

  useEffect(() => {
    if (!sessionId) return;
    const abort = new AbortController();

    client.sessions
      .get(sessionId)
      .then((s) => {
        setSession(s);
        setStatus(s.status);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err));
      });

    (async () => {
      try {
        setConnected(true);
        for await (const evt of client.sessions.events(sessionId, {
          lastEventId: lastEventIdRef.current,
          signal: abort.signal,
        })) {
          lastEventIdRef.current = evt.id;
          setEvents((prev) => [...prev, evt]);

          switch (evt.type) {
            case "session.queued":
              setStatus("queued");
              break;
            case "session.booting":
              setStatus("provisioning");
              break;
            case "session.running":
              setStatus("running");
              setBudgetAlert(null);
              break;
            case "session.hibernated":
              setStatus("hibernated");
              break;
            case "session.completed":
              setStatus("completed");
              break;
            case "session.failed":
              setStatus("failed");
              break;
            case "session.cancelled":
              setStatus("cancelled");
              break;
            case "plan.updated": {
              const p = evt.payload as unknown as PlanUpdatedPayload;
              if (Array.isArray(p.steps)) setPlan(p.steps);
              break;
            }
            case "file.diff": {
              const d = evt.payload as unknown as FileDiffPayload;
              setDiffs((prev) => {
                const idx = prev.findIndex((item) => item.path === d.path);
                if (idx >= 0) {
                  const next = [...prev];
                  next[idx] = d;
                  return next;
                }
                return [...prev, d];
              });
              break;
            }
            case "approval.required":
              setStatus("waiting_approval");
              setPendingApproval(
                evt.payload as unknown as ApprovalRequiredPayload,
              );
              break;
            case "approval.resolved":
              setPendingApproval(null);
              setStatus("running");
              break;
            case "budget.exceeded":
              setStatus("budget_paused");
              setBudgetAlert(evt.payload as unknown as BudgetExceededPayload);
              break;
            case "input.requested":
              setStatus("waiting_input");
              setInputPrompt(String(evt.payload.prompt ?? ""));
              break;
            case "usage.reported": {
              const totalCredits = Number(evt.payload.total_credits ?? 0);
              setSession((prev) =>
                prev
                  ? {
                      ...prev,
                      usage: {
                        ...prev.usage,
                        credits_used: totalCredits,
                        turns_used: prev.usage.turns_used + 1,
                      },
                    }
                  : prev,
              );
              break;
            }
          }
        }
      } catch (err: unknown) {
        if (!abort.signal.aborted) {
          setError(err instanceof Error ? err.message : String(err));
        }
      } finally {
        setConnected(false);
      }
    })();

    return () => abort.abort();
  }, [client, sessionId]);

  const steer = useCallback(
    async (content: string) => {
      if (!sessionId) return;
      setInputPrompt(null);
      await client.sessions.sendMessage(sessionId, content);
    },
    [client, sessionId],
  );

  const approve = useCallback(
    async (approvalId: string, feedback?: string) => {
      if (!sessionId) return;
      await client.sessions.resolveApproval(
        sessionId,
        approvalId,
        "approved",
        feedback,
      );
      setPendingApproval(null);
    },
    [client, sessionId],
  );

  const reject = useCallback(
    async (approvalId: string, feedback?: string) => {
      if (!sessionId) return;
      await client.sessions.resolveApproval(
        sessionId,
        approvalId,
        "rejected",
        feedback,
      );
      setPendingApproval(null);
    },
    [client, sessionId],
  );

  const resume = useCallback(
    async (opts?: { addCredits?: number; addTurns?: number; message?: string }) => {
      if (!sessionId) return;
      const updated = await client.sessions.resume(sessionId, opts);
      setSession(updated);
      setBudgetAlert(null);
    },
    [client, sessionId],
  );

  const value = useMemo<AgentBoxContextValue>(
    () => ({
      sessionId,
      session,
      status,
      events,
      plan,
      diffs,
      pendingApproval,
      budgetAlert,
      inputPrompt,
      connected,
      error,
      steer,
      approve,
      reject,
      resume,
    }),
    [
      sessionId,
      session,
      status,
      events,
      plan,
      diffs,
      pendingApproval,
      budgetAlert,
      inputPrompt,
      connected,
      error,
      steer,
      approve,
      reject,
      resume,
    ],
  );

  return (
    <AgentBoxContext.Provider value={value}>
      {children}
    </AgentBoxContext.Provider>
  );
}

export function useAgentBox(): AgentBoxContextValue {
  const ctx = useContext(AgentBoxContext);
  if (!ctx) {
    throw new Error("useAgentBox must be used inside <AgentBoxProvider>");
  }
  return ctx;
}
