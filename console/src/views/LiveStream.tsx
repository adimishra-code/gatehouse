import { useMemo, useState } from "react";
import { api } from "../api";
import type { AuditEntry, PendingApproval } from "../types";
import { fmtUs, headline, hhmmss } from "./Overview";

export default function LiveStream({ entries, pending }: { entries: AuditEntry[]; pending: PendingApproval[] }) {
  const [q, setQ] = useState("");
  const [decision, setDecision] = useState("all");
  const [agent, setAgent] = useState("all");
  const [open, setOpen] = useState<AuditEntry | null>(null);

  const agents = useMemo(() => [...new Set(entries.map((e) => e.event.agent))].sort(), [entries]);

  const filtered = entries.filter((e) => {
    if (decision !== "all" && e.event.decision !== decision) return false;
    if (agent !== "all" && e.event.agent !== agent) return false;
    if (q && !`${e.event.tool} ${e.event.server} ${e.event.reasons.join(" ")} ${JSON.stringify(e.event.request)}`.toLowerCase().includes(q.toLowerCase()))
      return false;
    return true;
  });

  const decide = async (id: string, approve: boolean) => {
    await api.resolve(id, approve);
  };

  return (
    <>
      {pending.map((p) => (
        <div className="approve-card" key={p.id}>
          <div className="t">Approval needed: {p.agent} wants {p.server}.{p.tool}</div>
          <div className="m">{JSON.stringify(p.request).slice(0, 220)}</div>
          <button className="act ok" onClick={() => decide(p.id, true)}>Approve</button>{" "}
          <button className="act danger" onClick={() => decide(p.id, false)}>Deny</button>
          <span className="hint" style={{ marginLeft: 10, color: "#5d6575", fontSize: 12 }}>
            waiting {p.ageSecs}s — silence denies at 120s
          </span>
        </div>
      ))}

      <div className="panel">
        <header>
          <span className={`live-dot on`} /> Live call stream
          <span className="spacer" />
          <div className="filters">
            <input placeholder="filter text…" value={q} onChange={(e) => setQ(e.target.value)} />
            <select value={decision} onChange={(e) => setDecision(e.target.value)}>
              <option value="all">all decisions</option>
              <option value="allowed">allowed</option>
              <option value="blocked">blocked</option>
              <option value="pending">pending</option>
              <option value="approved">approved</option>
              <option value="denied">denied</option>
            </select>
            <select value={agent} onChange={(e) => setAgent(e.target.value)}>
              <option value="all">all agents</option>
              {agents.map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </div>
        </header>

        <div className="rows">
          {filtered.map((e) => (
            <div className="row" key={e.seq} onClick={() => setOpen(open?.seq === e.seq ? null : e)}>
              <span className="t">{hhmmss(e.ts)}</span>
              <span className="agent">{e.event.agent}</span>
              <span className="what">
                {e.event.server}.{e.event.tool} <span className="rsn">· {headline(e.event)}</span>
              </span>
              <span className={`pill ${e.event.decision}`}>{e.event.decision}</span>
              <span className="t" style={{ textAlign: "right" }}>{fmtUs(e.event.latencyUs)}</span>
            </div>
          ))}
          {filtered.length === 0 && <div className="empty">No calls match. Run the demo agent to light this up.</div>}
        </div>

        {open && (
          <div className="drawer">
            <h3>
              {open.event.server}.{open.event.tool} — entry #{open.seq}
            </h3>
            <pre>{JSON.stringify(open.event.request, null, 2)}</pre>
            {open.event.response != null && (
              <>
                <h3>Tool response (redacted)</h3>
                <pre>{JSON.stringify(open.event.response, null, 2)}</pre>
              </>
            )}
            {open.event.reasons.length > 0 && (
              <>
                <h3>Why</h3>
                {open.event.reasons.map((r, i) => (
                  <div className="alert-why" key={i} style={{ marginBottom: 6 }}>{r}</div>
                ))}
              </>
            )}
            <div className="hash">
              chain: {open.prevHash.slice(0, 20)}… → {open.hash.slice(0, 20)}…
            </div>
          </div>
        )}
      </div>
    </>
  );
}
