import type { AuditEntry, OwaspItem, PendingApproval, PolicySet, SessionRow, SettingsInfo, Stats, ToolPolicy } from "./types";

const j = async <T,>(r: Response): Promise<T> => {
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json() as Promise<T>;
};

export const api = {
  stats: () => fetch("/api/stats").then(j<Stats>),
  events: (limit = 200) => fetch(`/api/events?limit=${limit}`).then(j<{ entries: AuditEntry[] }>),
  policies: () => fetch("/api/policies").then(j<PolicySet>),
  setPolicy: (p: ToolPolicy) =>
    fetch("/api/policies", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(p),
    }).then(j<{ ok: boolean; error?: string }>),
  pending: () => fetch("/api/pending").then(j<{ items: PendingApproval[] }>),
  resolve: (id: string, approve: boolean) =>
    fetch(`/api/pending/${id}/resolve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ approve }),
    }).then(j<{ ok: boolean }>),
  kill: (agent: string) => fetch(`/api/agents/${encodeURIComponent(agent)}/kill`, { method: "POST" }).then(j<{ ok: boolean }>),
  sessions: () => fetch("/api/sessions").then(j<{ items: SessionRow[]; killed: string[] }>),
  owasp: () => fetch("/api/owasp").then(j<{ items: OwaspItem[] }>),
  settings: () => fetch("/api/settings").then(j<SettingsInfo>),
};

export function useLiveStream(onEntry: (e: AuditEntry) => void) {
  // Connects once per mount; returns a disconnect via cleanup.
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/stream`);
  ws.onmessage = (m) => {
    try {
      const entry = JSON.parse(m.data) as AuditEntry;
      if (entry && entry.event) onEntry(entry);
    } catch {
      /* welcome frames and partials are ignored */
    }
  };
  return () => ws.close();
}
