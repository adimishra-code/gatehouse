import { useEffect, useState } from "react";
import { api } from "../api";
import type { PolicySet, ToolPolicy } from "../types";

const BLANK: ToolPolicy = {
  tool: "",
  action: "allow",
  maskParams: [],
  approvalAfterUses: 0,
  denyIfSessionUsed: null,
  note: "",
};

export default function Policies() {
  const [set, setSet] = useState<PolicySet | null>(null);
  const [form, setForm] = useState<ToolPolicy>({ ...BLANK });
  const [raw, setRaw] = useState("");
  const [mode, setMode] = useState<"visual" | "raw">("visual");
  const [msg, setMsg] = useState("");

  const refresh = () =>
    api
      .policies()
      .then((s) => {
        setSet(s);
        setRaw(JSON.stringify(s, null, 2));
      })
      .catch(() => {});

  useEffect(() => {
    refresh();
  }, []);

  const save = async (p: ToolPolicy) => {
    const r = await api.setPolicy(p);
    setMsg(r.ok ? `saved — policy v${(set?.version ?? 0) + 1} (this change is itself an audited event)` : r.error ?? "failed");
    refresh();
  };

  return (
    <div className="panel">
      <header>
        Policy editor
        <span className="spacer" />
        <button className={mode === "visual" ? "act primary" : "act"} onClick={() => setMode("visual")}>Visual</button>
        <button className={mode === "raw" ? "act primary" : "act"} onClick={() => setMode("raw")}>Raw</button>
        <span className="hint">{set ? `v${set.version}` : ""}</span>
      </header>
      <div className="panel-body">
        {msg && <div className="notice" style={{ borderColor: "rgba(79,178,134,0.35)", background: "rgba(79,178,134,0.06)", color: "#4fb286" }}>{msg}</div>}

        {mode === "visual" ? (
          <div className="pol-grid">
            <div>
              <div className="field">
                <label>Tool (exact name, or * for the wildcard default)</label>
                <input value={form.tool} onChange={(e) => setForm({ ...form, tool: e.target.value })} placeholder="read_file" />
              </div>
              <div className="field">
                <label>Decision</label>
                <select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value as ToolPolicy["action"] })}>
                  <option value="allow">allow</option>
                  <option value="deny">deny</option>
                  <option value="requireApproval">require approval</option>
                </select>
              </div>
              <div className="field">
                <label>Require approval after N uses in one session (0 disables)</label>
                <input
                  type="number"
                  min={0}
                  value={form.approvalAfterUses ?? 0}
                  onChange={(e) => setForm({ ...form, approvalAfterUses: Number(e.target.value) })}
                />
              </div>
              <div className="field">
                <label>Deny if the session already used tool…</label>
                <input
                  value={form.denyIfSessionUsed ?? ""}
                  onChange={(e) => setForm({ ...form, denyIfSessionUsed: e.target.value || null })}
                  placeholder="e.g. read_env — breaks exfil ladders"
                />
              </div>
              <div className="field">
                <label>Operator note</label>
                <input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} placeholder="why this rule exists" />
              </div>
              <button
                className="act primary"
                disabled={!form.tool}
                onClick={() =>
                  save({
                    ...form,
                    maskParams: Array.isArray(form.maskParams) ? form.maskParams : [],
                  })
                }
              >
                Save policy
              </button>
            </div>
            <div>
              <label style={{ fontSize: 12.5, color: "#8b93a3", display: "block", marginBottom: 6 }}>Existing rules</label>
              <table className="grid">
                <thead>
                  <tr>
                    <th>tool</th>
                    <th>action</th>
                    <th>session rule</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {set &&
                    Object.values(set.tools).map((p) => (
                      <tr key={p.tool}>
                        <td>{p.tool}</td>
                        <td className={`perm ${p.action === "allow" ? "a" : p.action === "deny" ? "d" : "p"}`}>{p.action}</td>
                        <td className="plain" style={{ fontSize: 12, color: "#8b93a3" }}>
                          {p.approvalAfterUses ? `approval after ${p.approvalAfterUses}×` : ""}
                          {p.denyIfSessionUsed ? `deny after ${p.denyIfSessionUsed}` : ""}
                          {!p.approvalAfterUses && !p.denyIfSessionUsed ? "—" : ""}
                        </td>
                        <td>
                          <button className="act danger" onClick={() => { if (set) { fetchReject(p.tool).then(refresh); } }}>remove</button>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <>
            <textarea className="code" value={raw} onChange={(e) => setRaw(e.target.value)} spellCheck={false} />
            <div style={{ marginTop: 10 }}>
              <button
                className="act primary"
                onClick={async () => {
                  try {
                    const parsed = JSON.parse(raw);
                    for (const p of Object.values(parsed.tools ?? {}) as ToolPolicy[]) {
                      await api.setPolicy(p);
                    }
                    setMsg("raw policy applied");
                    refresh();
                  } catch (e) {
                    setMsg(`invalid JSON: ${String(e)}`);
                  }
                }}
              >
                Apply raw
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

async function fetchReject(tool: string) {
  // DELETE semantics via POST with an empty rule is avoided; the API exposes
  // removal through the raw editor, so mirror it here with a fetch.
  await fetch("/api/policies", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tool, action: "allow", note: "reset to allow" }),
  });
}
