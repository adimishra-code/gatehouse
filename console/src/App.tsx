import { useEffect, useMemo, useState } from "react";
import { api, useLiveStream } from "./api";
import type { AuditEntry, PendingApproval, Stats } from "./types";
import Overview from "./views/Overview";
import LiveStream from "./views/LiveStream";
import Policies from "./views/Policies";
import AuditTimeline from "./views/AuditTimeline";
import AgentsTools from "./views/AgentsTools";
import Alerts from "./views/Alerts";
import Settings from "./views/Settings";

type Tab = "overview" | "stream" | "policies" | "audit" | "agents" | "alerts" | "settings";

const NAV: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "stream", label: "Live stream" },
  { id: "policies", label: "Policies" },
  { id: "audit", label: "Audit timeline" },
  { id: "agents", label: "Agents & tools" },
  { id: "alerts", label: "Alerts" },
  { id: "settings", label: "Settings" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [stats, setStats] = useState<Stats | null>(null);
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [pending, setPending] = useState<PendingApproval[]>([]);
  const [live, setLive] = useState(false);

  // One stream for the whole app: every view reads from this buffer.
  const push = (e: AuditEntry) => setEntries((prev) => [e, ...prev].slice(0, 400));

  useEffect(() => {
    const close = useLiveStream(push);
    setLive(true);
    return close;
  }, []);

  useEffect(() => {
    const tick = () => {
      api.stats().then(setStats).catch(() => setLive(false));
      api.pending().then((r) => setPending(r.items)).catch(() => {});
    };
    tick();
    const iv = setInterval(tick, 4000);
    return () => clearInterval(iv);
  }, []);

  const alerts = useMemo(() => entries.filter((e) => e.event.decision === "blocked" || e.event.decision === "denied"), [entries]);

  const title = NAV.find((n) => n.id === tab)?.label ?? "";

  return (
    <div className="shell">
      <aside className="side">
        <div className="wordmark">
          gate<span>house</span>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <button key={n.id} className={tab === n.id ? "on" : ""} onClick={() => setTab(n.id)}>
              {n.label}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <b>{live ? "stream connected" : "stream offline"}</b>
          <br />
          chain {stats?.chainVerified ? "verified" : "—"}
          <br />
          {stats ? `${stats.auditEntries} entries` : ""}
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <h1>{title}</h1>
          <span className="sub">
            <span className={`live-dot ${live ? "on" : ""}`} style={{ marginRight: 8 }} />
            {live ? "live" : "reconnecting"}
          </span>
        </div>

        {pending.length > 0 && (tab === "overview" || tab === "stream") && (
          <div className="notice">
            {pending.length} tool call{pending.length > 1 ? "s" : ""} waiting for operator approval. Open{" "}
            <button className="act" style={{ padding: "2px 8px" }} onClick={() => setTab("stream")}>
              live stream
            </button>{" "}
            to decide.
          </div>
        )}

        {tab === "overview" && <Overview stats={stats} entries={entries} pending={pending} onGo={setTab} />}
        {tab === "stream" && <LiveStream entries={entries} pending={pending} />}
        {tab === "policies" && <Policies />}
        {tab === "audit" && <AuditTimeline entries={entries} chainOk={stats?.chainVerified ?? false} lastHash={stats?.lastChainHash ?? ""} />}
        {tab === "agents" && <AgentsTools entries={entries} />}
        {tab === "alerts" && <Alerts alerts={alerts} />}
        {tab === "settings" && <Settings />}
      </main>
    </div>
  );
}
