import { useEffect, useState } from "react";
import { api } from "../api";
import type { SettingsInfo } from "../types";

export default function Settings() {
  const [s, setS] = useState<SettingsInfo | null>(null);

  useEffect(() => {
    api.settings().then(setS).catch(() => {});
  }, []);

  if (!s) return <div className="empty">Loading settings…</div>;

  return (
    <>
      <div className="panel">
        <header>Gatehouse runtime</header>
        <table className="grid">
          <tbody>
            <tr>
              <td>listen</td>
              <td>{s.listen}</td>
            </tr>
            <tr>
              <td>rate limit</td>
              <td>{s.maxCallsPerMin} calls/min per agent (ASI08)</td>
            </tr>
            <tr>
              <td>spend ceiling</td>
              <td>${s.spendLimitUsd.toFixed(2)} per agent-day, 60s circuit breaker on breach (ASI08)</td>
            </tr>
            <tr>
              <td>cost model</td>
              <td>${s.costPerCall.toFixed(3)} per forwarded call</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="panel">
        <header>
          MCP servers
          <span className="hint">credentials live in the gateway, never in agents (ASI03)</span>
        </header>
        <table className="grid">
          <thead>
            <tr>
              <th>server</th>
              <th>transport</th>
              <th>upstream</th>
              <th>credential</th>
            </tr>
          </thead>
          <tbody>
            {s.servers.map((t) => (
              <tr key={t.name}>
                <td>{t.name}</td>
                <td>{t.transport}</td>
                <td className="plain" style={{ fontSize: 12 }}>{t.upstreamUrl ?? `${t.command} ${t.args.join(" ")}`}</td>
                <td className={t.authFromEnv ? (t.hasCredential ? "perm a" : "perm d") : "plain"}>
                  {t.authFromEnv ? (t.hasCredential ? "loaded from env, withheld from agents" : "env var missing") : "none needed"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <header>
          Redaction rule library
          <span className="hint">applied to requests and responses before anything is stored or streamed</span>
        </header>
        <table className="grid">
          <thead>
            <tr>
              <th>rule</th>
              <th>catches</th>
            </tr>
          </thead>
          <tbody>
            {s.redactionRules.map((r) => (
              <tr key={r.name}>
                <td>{r.name}</td>
                <td className="plain" style={{ fontSize: 12.5 }}>{r.applies}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
