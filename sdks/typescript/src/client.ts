import type {
  AgentBoxEvent,
  ClientTokenResponse,
  CreateSessionParams,
  CustomerUsage,
  Session,
  SessionDiffResponse,
} from "./types.js";

export interface AgentBoxClientOptions {
  apiBaseUrl: string;
  apiKey?: string;
  clientToken?: string;
  fetchImpl?: typeof fetch;
}

export interface StreamEventsOptions {
  lastEventId?: string;
  signal?: AbortSignal;
}

export class AgentBoxError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "AgentBoxError";
  }
}

export class AgentBoxClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly fetchFn: typeof fetch;

  constructor(options: AgentBoxClientOptions) {
    this.baseUrl = options.apiBaseUrl.replace(/\/+$/, "");
    this.token = options.apiKey ?? options.clientToken ?? "";
    this.fetchFn = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  private headers(contentType?: string): Record<string, string> {
    const h: Record<string, string> = {};
    if (this.token) {
      h["Authorization"] = `Bearer ${this.token}`;
    }
    if (contentType) {
      h["Content-Type"] = contentType;
    }
    return h;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    contentType = "application/json",
  ): Promise<T> {
    const res = await this.fetchFn(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(body !== undefined ? contentType : undefined),
      body:
        body === undefined
          ? undefined
          : typeof body === "string"
            ? body
            : JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new AgentBoxError(res.status, text || `HTTP ${res.status}`);
    }
    return (await res.json()) as T;
  }

  readonly blueprints = {
    put: (name: string, yamlOrSpec: string | Record<string, unknown>) =>
      this.request<{ blueprint: unknown; hash: string }>(
        "PUT",
        `/v1/blueprints/${encodeURIComponent(name)}`,
        yamlOrSpec,
        typeof yamlOrSpec === "string" ? "application/yaml" : "application/json",
      ),

    get: (name: string) =>
      this.request<{ blueprint: unknown; hash: string }>(
        "GET",
        `/v1/blueprints/${encodeURIComponent(name)}`,
      ),

    list: () => this.request<{ blueprints: unknown[] }>("GET", "/v1/blueprints"),
  };

  readonly sessions = {
    create: (params: CreateSessionParams) =>
      this.request<Session>("POST", "/v1/sessions", {
        customer_id: params.customerId,
        blueprint: params.blueprint,
        repo: params.repo,
        task: params.task,
        limits: params.limits,
        webhook_url: params.webhookUrl,
        webhook_secret: params.webhookSecret,
        metadata: params.metadata,
      }),

    get: (sessionId: string) =>
      this.request<Session>("GET", `/v1/sessions/${encodeURIComponent(sessionId)}`),

    list: (customerId?: string) => {
      const q = customerId ? `?customer_id=${encodeURIComponent(customerId)}` : "";
      return this.request<{ sessions: Session[] }>("GET", `/v1/sessions${q}`);
    },

    createClientToken: (
      sessionId: string,
      opts?: { scopes?: string[]; ttlSeconds?: number },
    ) =>
      this.request<ClientTokenResponse>(
        "POST",
        `/v1/sessions/${encodeURIComponent(sessionId)}/client-token`,
        {
          scopes: opts?.scopes,
          ttl_seconds: opts?.ttlSeconds,
        },
      ),

    sendMessage: (sessionId: string, content: string, sender?: string) =>
      this.request<{ status: string }>(
        "POST",
        `/v1/sessions/${encodeURIComponent(sessionId)}/messages`,
        { content, sender },
      ),

    resolveApproval: (
      sessionId: string,
      approvalId: string,
      decision: "approved" | "rejected",
      feedback?: string,
    ) =>
      this.request<{ status: string; decision: string }>(
        "POST",
        `/v1/sessions/${encodeURIComponent(sessionId)}/approvals/${encodeURIComponent(approvalId)}`,
        { decision, feedback },
      ),

    resume: (
      sessionId: string,
      opts?: {
        addCredits?: number;
        addTurns?: number;
        addWallClockSeconds?: number;
        message?: string;
      },
    ) =>
      this.request<Session>(
        "POST",
        `/v1/sessions/${encodeURIComponent(sessionId)}/resume`,
        {
          add_credits: opts?.addCredits,
          add_turns: opts?.addTurns,
          add_wall_clock_seconds: opts?.addWallClockSeconds,
          message: opts?.message,
        },
      ),

    fork: (
      sessionId: string,
      opts?: { checkpointId?: string; task?: string },
    ) =>
      this.request<Session>(
        "POST",
        `/v1/sessions/${encodeURIComponent(sessionId)}/fork`,
        {
          checkpoint_id: opts?.checkpointId,
          task: opts?.task,
        },
      ),

    getDiff: (sessionId: string) =>
      this.request<SessionDiffResponse>(
        "GET",
        `/v1/sessions/${encodeURIComponent(sessionId)}/diff`,
      ),

    cancel: (sessionId: string) =>
      this.request<Session>(
        "POST",
        `/v1/sessions/${encodeURIComponent(sessionId)}/cancel`,
      ),

    events: (
      sessionId: string,
      opts?: StreamEventsOptions,
    ): AsyncIterable<AgentBoxEvent> => {
      const self = this;
      return {
        async *[Symbol.asyncIterator]() {
          const headers = self.headers();
          headers["Accept"] = "text/event-stream";
          if (opts?.lastEventId) {
            headers["Last-Event-ID"] = opts.lastEventId;
          }
          const res = await self.fetchFn(
            `${self.baseUrl}/v1/sessions/${encodeURIComponent(sessionId)}/events`,
            { headers, signal: opts?.signal },
          );
          if (!res.ok || !res.body) {
            throw new AgentBoxError(res.status, `SSE stream failed (${res.status})`);
          }
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              buffer += decoder.decode(value, { stream: true });
              let splitIdx = buffer.indexOf("\n\n");
              while (splitIdx !== -1) {
                const frame = buffer.slice(0, splitIdx);
                buffer = buffer.slice(splitIdx + 2);
                const parsed = parseSSEFrame(frame);
                if (parsed) {
                  yield parsed;
                }
                splitIdx = buffer.indexOf("\n\n");
              }
            }
          } finally {
            reader.releaseLock();
          }
        },
      };
    },
  };

  readonly customers = {
    getUsage: (customerId: string) =>
      this.request<CustomerUsage>(
        "GET",
        `/v1/customers/${encodeURIComponent(customerId)}/usage`,
      ),
  };
}

export function parseSSEFrame(frame: string): AgentBoxEvent | null {
  const dataLines: string[] = [];
  for (const line of frame.split(/\r?\n/)) {
    if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trimStart());
    }
  }
  if (dataLines.length === 0) return null;
  try {
    return JSON.parse(dataLines.join("\n")) as AgentBoxEvent;
  } catch {
    return null;
  }
}
