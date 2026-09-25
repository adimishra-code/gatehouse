import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AuditEntry, PendingApproval, Stats } from "../types";

export default function Overview({
  stats,
  entries,
  pending,
  onGo,
}: {
  stats: Stats | null;
  entries: AuditEntry[];
  pending: PendingApproval[];
  onGo: (t: "stream" | "alerts" | "audit") => void;
}) {
  const flagged = entries.filter((e) => e.event.decision === "blocked" || e.event.decision === "denied");
  const blockRate = entries.length ? Math.round((flagged.length / entries.length) * 100) : 0;

  // Calls per second over the last 60s, bucketed.
  const series = (() => {
    const now = Date.now();
    const buckets = new Map<number, number>();
    for (let i = 0; i < 30; i++) buckets.set(Math.floor((now - i * 2000) / 2000), 0);
    for (const e of entries) {
      const b = Math.floor(new Date(e.ts).getTime() / 2000);
      if (buckets.has(b)) buckets.set(b, (buckets.get(b) ?? 0) + 1);
    }
    return [...buckets.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([t, n]) => ({ t: new Date(t * 2000).toLocaleTimeString([], { hour12: false }), calls: n }));
  })();

  return (
    <>
      <div className="stats">
        <div className="stat">
          <div className="k">Calls in window</div>
          <div className="v">{entries.length}</div>
        </div>
        <div className="stat">
          <div className="k">Block rate</div>
          <div className={`v ${blockRate > 0 ? "flag" : ""}`}>{blockRate}<small>%</small></div>
        </div>
        <div className="stat">
          <div className="k">Active agents</div>
          <div className="v">{stats?.activeAgents ?? 0}</div>
        </div>
        <div className="stat">
          <div className="k">Gateway overhead p50</div>
          <div className="v">{fmtUs(stats?.p50Us ?? 0)}</div>
        </div>
        <div className="stat">
          <div className="k">p95</div>
          <div className="v">{fmtUs(stats?.p95Us ?? 0)}</div>
        </div>
        <div className="stat">
          <div className="k">Waiting on you</div>
          <div className={`v ${pending.length ? "flag" : ""}`}>{pending.length}</div>
        </div>
      </div>

      <div className="panel">
        <header>
          Call volume, last 60 seconds
          <span className="spacer" />
          <span className="hint">every call through the gate, blocked ones included</span>
        </header>
        <div className="panel-body" style={{ height: 180 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={series} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
              <defs>
                <linearGradient id="callsFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#c9a227" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#c9a227" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <XAxis dataKey="t" tick={{ fill: "#5d6575", fontSize: 10, fontFamily: "IBM Plex Mono" }} tickLine={false} axisLine={{ stroke: "#2a2f3a" }} interval={9} />
              <YAxis tick={{ fill: "#5d6575", fontSize: 10, fontFamily: "IBM Plex Mono" }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "#1b1f27", border: "1px solid #2a2f3a", borderRadius: 6, fontSize: 12, fontFamily: "IBM Plex Mono" }}
                labelStyle={{ color: "#8b93a3" }}
                itemStyle={{ color: "#e7e9ee" }}
              />
              <Area type="monotone" dataKey="calls" stroke="#c9a227" strokeWidth={1.5} fill="url(#callsFill)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="panel">
        <header>
          Recent flagged events
          <span className="spacer" />
          <button className="act" onClick={() => onGo("alerts")}>All alerts</button>
        </header>
        {flagged.length === 0 ? (
          <div className="empty">Nothing flagged in this window. Quiet gate is a good gate.</div>
        ) : (
          <div className="rows">
            {flagged.slice(0, 6).map((e) => (
              <div className="row" key={e.seq} onClick={() => onGo("alerts")}>
                <span className="t">{hhmmss(e.ts)}</span>
                <span className="agent">{e.event.agent}</span>
                <span className="what">{headline(e.event)}</span>
                <span className="pill blocked">blocked</span>
                <span className="t" style={{ textAlign: "right" }}>{fmtUs(e.event.latencyUs)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

export function hhmmss(ts: string): string {
  return new Date(ts).toLocaleTimeString([], { hour12: false });
}

export function fmtUs(us: number): string {
  if (us >= 1000) return `${(us / 1000).toFixed(1)}ms`;
  return `${us}µs`;
}

export function headline(ev: AuditEntry["event"]): string {
  if (ev.reasons.length === 0) return `${ev.action} ${ev.tool}`;
  const r = ev.reasons[0];
  return r.length > 90 ? `${r.slice(0, 90)}…` : r;
}
