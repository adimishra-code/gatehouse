import { useEffect, useState } from "react";
import { api } from "../api";
import type { AuditEntry, OwaspItem, SessionRow } from "../types";
import { hhmmss } from "./Overview";

export default function AgentsTools({ entries }: { entries: AuditEntry[] }) {
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [killed, setKilled] = useState<string[]>([]);
  const [owasp, setOwasp] = useState<OwaspItem[]>([]);

  const refresh = () =>
    api.sessions().then((r) => {
      setSessions(r.items);
      setKilled(r.killed);
    });
  useEffect(() => {
    refresh();
    api.owasp().then((r) => setOwasp(r.items));
  }, []);

  const kill = async (agent: string) => {
    await api.kill(agent);
    refresh();
  };

  // Derive the tool inventory from observed traffic — what the gate has
  // actually seen, not what someone claims is deployed.
  const tools = useMemoTools(entries);

  return (
    <>
      <div className="panel">
        <header>
          Agents
          <span className="hint">kill switch revokes mid-session, instantly (ASI10)</span>
        </header>
        <table className="grid">
          <thead>
            <tr>
              <th>agent</th>
              <th>session</th>
              <th>calls</th>
              <th>blocked</th>
              <th>tools used</th>
              <th>last seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.sessionId}>
                <td>{s.agent}</td>
                <td style={{ color: "#5d6575" }}>{s.sessionId.slice(0, 12)}…</td>
                <td>{s.calls}</td>
                <td className={s.blocked ? "perm d" : ""}>{s.blocked}</td>
                <td className="plain" style={{ fontSize: 12 }}>{s.toolsUsed.join(", ") || "—"}</td>
                <td>{hhmmss(s.lastSeen)}</td>
                <td>
                  <button className="act danger" onClick={() => kill(s.agent)}>Kill agent</button>
                </td>
              </tr>
            ))}
            {sessions.length === 0 && (
              <tr>
                <td colSpan={7} className="plain" style={{ textAlign: "center", color: "#5d6575" }}>
                  No agent sessions yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {killed.length > 0 && (
          <div className="panel-body" style={{ paddingTop: 10 }}>
            <span className="perm d">revoked: {killed.join(", ")}</span>
          </div>
        )}
      </div>

      <div className="panel">
        <header>
          Tools observed through the gate
          <span className="hint">derived from live traffic (ASI02/ASI04 inventory)</span>
        </header>
        <table className="grid">
          <thead>
            <tr>
              <th>server</th>
              <th>tool</th>
              <th>calls</th>
              <th>blocked</th>
              <th>last decision</th>
            </tr>
          </thead>
          <tbody>
            {tools.map((t) => (
              <tr key={`${t.server}.${t.tool}`}>
                <td>{t.server}</td>
                <td>{t.tool}</td>
                <td>{t.calls}</td>
                <td className={t.blocked ? "perm d" : ""}>{t.blocked}</td>
                <td className={`perm ${t.last === "allowed" || t.last === "approved" ? "a" : t.last === "pending" ? "p" : "d"}`}>{t.last}</td>
              </tr>
            ))}
            {tools.length === 0 && (
              <tr>
                <td colSpan={5} className="plain" style={{ textAlign: "center", color: "#5d6575" }}>
                  Nothing observed yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <header>
          OWASP Agentic Top 10 coverage
          <span className="hint">what gatehouse enforces, and where you see it</span>
        </header>
        <div className="panel-body cov">
          {owasp.map((o) => (
            <div className="cov-item" key={o.id}>
              <span className="id">{o.id}</span>
              <span>
                <div className="nm">{o.name}</div>
                <div className="how">{o.how}</div>
              </span>
              <span className={`st ${o.status}`}>{o.status}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function useMemoTools(entries: AuditEntry[]) {
  const map = new Map<string, { server: string; tool: string; calls: number; blocked: number; last: string }>();
  for (const e of entries) {
    if (e.event.action !== "tools/call") continue;
    const key = `${e.event.server}.${e.event.tool}`;
    const rec = map.get(key) ?? { server: e.event.server, tool: e.event.tool, calls: 0, blocked: 0, last: e.event.decision };
    rec.calls += 1;
    if (e.event.decision === "blocked" || e.event.decision === "denied") rec.blocked += 1;
    rec.last = e.event.decision;
    map.set(key, rec);
  }
  return [...map.values()];
}
