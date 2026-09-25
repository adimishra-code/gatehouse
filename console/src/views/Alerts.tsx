import { useState } from "react";
import type { AuditEntry } from "../types";
import { headline, hhmmss } from "./Overview";

export default function Alerts({ alerts }: { alerts: AuditEntry[] }) {
  const [open, setOpen] = useState<AuditEntry | null>(null);

  return (
    <div className="panel">
      <header>
        Blocked and flagged calls
        <span className="hint">injection attempts, exfiltration patterns, policy denials</span>
      </header>
      {alerts.length === 0 && <div className="empty">No alerts. Either it's quiet, or nothing is pointed at the gate yet — run the demo agent.</div>}
      {alerts.map((e) => (
        <div key={e.seq}>
          <div className="alert-row" onClick={() => setOpen(open?.seq === e.seq ? null : e)}>
            <div className="alert-head">
              <span className="what">
                {e.event.agent} tried {e.event.server}.{e.event.tool}
              </span>
              <span className="when">{hhmmss(e.ts)}</span>
              <span className={`pill ${e.event.decision}`} style={{ marginLeft: "auto" }}>{e.event.decision}</span>
            </div>
            <div className="alert-why">{headline(e.event)}</div>
          </div>
          {open?.seq === e.seq && (
            <div className="drawer">
              <h3>What was blocked</h3>
              {e.event.reasons.map((r, i) => (
                <div className="alert-why" key={i} style={{ marginBottom: 8 }}>{r}</div>
              ))}
              <h3>Raw request (redacted before storage)</h3>
              <pre>{JSON.stringify(e.event.request, null, 2)}</pre>
              <h3>Evidence</h3>
              <div className="hash">
                entry #{e.seq} · chain hash {e.hash}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
