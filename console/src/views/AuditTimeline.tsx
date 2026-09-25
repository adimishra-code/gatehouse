import { useMemo, useState } from "react";
import type { AuditEntry } from "../types";
import { fmtUs, hhmmss } from "./Overview";

export default function AuditTimeline({ entries, chainOk, lastHash }: { entries: AuditEntry[]; chainOk: boolean; lastHash: string }) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<AuditEntry | null>(null);

  const filtered = useMemo(
    () =>
      entries.filter((e) =>
        q
          ? `${e.event.agent} ${e.event.tool} ${e.event.server} ${e.event.action} ${e.event.decision} ${e.hash}`
              .toLowerCase()
              .includes(q.toLowerCase())
          : true,
      ),
    [entries, q],
  );

  return (
    <>
      <div className="panel">
        <header>
          <span className={`chain ${chainOk ? "ok" : "bad"}`}>
            {chainOk ? "hash chain verified — every entry intact" : "chain check failed — evidence may be tampered"}
          </span>
          <span className="spacer" />
          <span className="hint">last hash {lastHash ? `${lastHash.slice(0, 24)}…` : "—"}</span>
        </header>
        <div className="panel-body" style={{ paddingBottom: 4 }}>
          <div className="filters" style={{ marginBottom: 10 }}>
            <input
              style={{ width: "100%" }}
              placeholder="search agent, tool, action, decision, hash…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
        </div>
        <div className="rows">
          {filtered.map((e) => (
            <div className="row" key={e.seq} onClick={() => setOpen(open?.seq === e.seq ? null : e)} style={{ gridTemplateColumns: "66px 92px 1fr 130px 110px" }}>
              <span className="t">{hhmmss(e.ts)}</span>
              <span className="agent">#{e.seq}</span>
              <span className="what">
                {e.event.agent} → {e.event.server}.{e.event.tool} <span className="rsn">· {e.event.action}</span>
              </span>
              <span className={`pill ${e.event.decision}`}>{e.event.decision}</span>
              <span className="t" style={{ textAlign: "right" }}>{fmtUs(e.event.latencyUs)}</span>
            </div>
          ))}
          {filtered.length === 0 && <div className="empty">No entries match this search.</div>}
        </div>
        {open && (
          <div className="drawer">
            <h3>Entry #{open.seq} · recorded {new Date(open.ts).toLocaleString()}</h3>
            <pre>{JSON.stringify(open, null, 2)}</pre>
            <div className="hash">
              prev {open.prevHash} → this {open.hash}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
