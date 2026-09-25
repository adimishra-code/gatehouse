export type Decision = "allowed" | "blocked" | "pending" | "approved" | "denied";

export interface CallEvent {
  id: number;
  ts: string;
  agent: string;
  sessionId: string;
  server: string;
  tool: string;
  action: string;
  decision: Decision;
  reasons: string[];
  latencyUs: number;
  request: unknown;
  response?: unknown;
  redactions: number;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  event: CallEvent;
  prevHash: string;
  hash: string;
}

export interface Stats {
  callsTotal: number;
  blocked: number;
  pendingApprovals: number;
  pendingRecent: number;
  activeAgents: number;
  p50Us: number;
  p95Us: number;
  auditEntries: number;
  chainVerified: boolean;
  lastChainHash: string;
}

export interface ToolPolicy {
  tool: string;
  action: "allow" | "deny" | "requireApproval";
  maskParams?: string[];
  approvalAfterUses?: number;
  denyIfSessionUsed?: string | null;
  note?: string;
}

export interface PolicySet {
  version: number;
  tools: Record<string, ToolPolicy>;
  wildcard?: ToolPolicy;
}

export interface PendingApproval {
  id: string;
  agent: string;
  sessionId: string;
  server: string;
  tool: string;
  request: unknown;
  created: string;
  ageSecs: number;
}

export interface SessionRow {
  sessionId: string;
  agent: string;
  started: string;
  lastSeen: string;
  calls: number;
  blocked: number;
  toolsUsed: string[];
}

export interface OwaspItem {
  id: string;
  name: string;
  status: "covered" | "partial" | "roadmap";
  how: string;
  view: string;
}

export interface ServerInfo {
  name: string;
  transport: "http" | "stdio";
  command?: string | null;
  args: string[];
  upstreamUrl?: string | null;
  authFromEnv: boolean;
  hasCredential: boolean;
}

export interface SettingsInfo {
  listen: string;
  spendLimitUsd: number;
  maxCallsPerMin: number;
  costPerCall: number;
  servers: ServerInfo[];
  redactionRules: { name: string; applies: string }[];
}
