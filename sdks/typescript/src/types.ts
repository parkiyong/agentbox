export type SessionStatus =
  | "queued"
  | "provisioning"
  | "running"
  | "waiting_approval"
  | "waiting_input"
  | "budget_paused"
  | "hibernated"
  | "completed"
  | "failed"
  | "cancelled";

export type EventType =
  | "session.queued"
  | "session.booting"
  | "session.running"
  | "session.hibernated"
  | "session.completed"
  | "session.failed"
  | "session.cancelled"
  | "plan.updated"
  | "tool.started"
  | "tool.completed"
  | "terminal.chunk"
  | "file.diff"
  | "checkpoint.created"
  | "pr.created"
  | "agent.message"
  | "input.requested"
  | "approval.required"
  | "approval.resolved"
  | "budget.exceeded"
  | "usage.reported";

export interface AgentBoxEvent<T = Record<string, unknown>> {
  id: string;
  seq: number;
  timestamp: string;
  session_id: string;
  customer_id: string;
  type: EventType;
  payload: T;
}

export interface PlanStep {
  id: string;
  title: string;
  status: "pending" | "in_progress" | "completed" | "failed";
}

export interface PlanUpdatedPayload {
  summary?: string;
  steps: PlanStep[];
}

export interface ToolStartedPayload {
  call_id: string;
  tool: string;
  args?: Record<string, unknown>;
}

export interface ToolCompletedPayload {
  call_id: string;
  tool: string;
  success: boolean;
  duration_ms: number;
  output?: string;
  error?: string;
}

export interface TerminalChunkPayload {
  call_id?: string;
  command?: string;
  stream: "stdout" | "stderr";
  data: string;
  exit_code?: number;
}

export interface DiffStats {
  files_changed: number;
  insertions: number;
  deletions: number;
}

export interface FileDiffPayload {
  path: string;
  operation: "create" | "modify" | "delete";
  unified: string;
  insertions: number;
  deletions: number;
}

export interface ApprovalRequiredPayload {
  approval_id: string;
  action: string;
  summary: string;
  details?: Record<string, unknown>;
  diff_stats?: DiffStats;
}

export interface BudgetExceededPayload {
  limit_type: "credits" | "turns" | "wall_clock";
  current: number;
  limit: number;
  checkpoint_id?: string;
  message: string;
}

export interface UsageReportedPayload {
  model: string;
  profile?: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  credits_delta: number;
  total_credits: number;
  compute_seconds?: number;
}

export interface LimitsConfig {
  max_credits?: number;
  max_turns?: number;
  max_wall_clock_seconds?: number;
  idle_hibernate_seconds?: number;
}

export interface RepoSpec {
  url?: string;
  base_branch?: string;
  local_path?: string;
}

export interface UsageStats {
  credits_used: number;
  prompt_tokens: number;
  completion_tokens: number;
  turns_used: number;
  wall_clock_seconds: number;
}

export interface Approval {
  id: string;
  session_id: string;
  action: string;
  summary: string;
  details?: Record<string, unknown>;
  diff_stats?: DiffStats;
  status: "pending" | "approved" | "rejected";
  feedback?: string;
  created_at: string;
  resolved_at?: string;
}

export interface Checkpoint {
  id: string;
  ref: string;
  commit_sha: string;
  step: number;
  message: string;
  created_at: string;
}

export interface Session {
  id: string;
  org_id: string;
  customer_id: string;
  workspace_id: string;
  blueprint_name: string;
  blueprint_version?: string;
  blueprint_hash?: string;
  repo: RepoSpec;
  task: string;
  status: SessionStatus;
  limits: LimitsConfig;
  usage: UsageStats;
  branch?: string;
  pr_url?: string;
  latest_checkpoint?: string;
  checkpoints?: Checkpoint[];
  pending_approval?: Approval;
  summary?: string;
  error?: string;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CreateSessionParams {
  customerId: string;
  blueprint: string;
  repo?: RepoSpec;
  task: string;
  limits?: LimitsConfig;
  webhookUrl?: string;
  webhookSecret?: string;
  metadata?: Record<string, string>;
}

export interface ClientTokenResponse {
  token: string;
  session_id: string;
  customer_id: string;
  scopes: string[];
  expires_at: string;
}

export interface SessionDiffResponse {
  session_id: string;
  branch?: string;
  unified: string;
  stats: DiffStats;
}

export interface CustomerUsage {
  org_id: string;
  customer_id: string;
  credits_used: number;
  credits_cap?: number;
  prompt_tokens: number;
  completion_tokens: number;
  sessions_count: number;
}
