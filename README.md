# Gatehouse

**The security checkpoint for AI agents — every tool call inspected, every decision on the record.**

You gave an agent write access to production. Gatehouse is the thing between it and your tools:
a reverse proxy for MCP tool calls that enforces policy, catches prompt injection and exfiltration
patterns, redacts secrets and PII in both directions, rate-limits spend, parks dangerous calls for
human approval, and writes every decision to a tamper-evident, hash-chained audit trail — with a
live operator console built for watching it happen.

```
agent (LangGraph / Claude / cursor / custom)
      │  JSON-RPC over HTTP, agent + session headers
      ▼
┌─────────────────────── gatehouse ────────────────────────┐
│  kill switch ──► rate/spend ──► redact ──► detect ──►    │
│  session-aware policy ──► approval parking lot ──►       │
│  short-lived scoped credential issuance (ASI03)          │
│  hash-chained audit trail ──► live WebSocket stream      │
└──────────────────────────────────────────────────────────┘
      │                    │
      ▼                    ▼
 stdio MCP server      HTTP MCP server
 (spawned + multiplexed)  (proxied with upstream auth)
```

The Rust core is the proxy. The console is the reason to star the repo.

---

## Quickstart

**Prereqs:** Rust 1.85+, Node 22.

> Windows note: if Windows Smart App Control blocks freshly compiled cargo build
> scripts (os error 4551), verify via the GitHub Actions workflow or build in WSL —
> SAC ignores path exemptions.

```bash
# 1. build the console
cd console && npm install && npm run build && cd ..

# 2. run the gateway (serves the console at http://127.0.0.1:8080)
cd gatehouse && cargo run --release && cd ..

# 3. light it up
npm run demo:policy     # send_email now requires human approval
npm run demo:attack     # seven calls: injections, exfil attempts, a poisoned response
```

Open **http://127.0.0.1:8080** — you'll see the seven calls land in the live stream,
five blocked with reasons, one response getting its secrets masked before your agent
could read them, one write action parked until you decide its fate.

### Docker (one command)

```bash
docker compose -f deploy/docker-compose.yml up --build
```

### Point a real agent at it

Any MCP client that speaks HTTP JSON-RPC works. LangGraph example in
[`demo/langgraph_agent.py`](demo/langgraph_agent.py). Custom agent, minimal form:

```bash
curl -X POST http://127.0.0.1:8080/mcp-echo \
  -H 'content-type: application/json' \
  -H 'x-gatehouse-agent: my-agent' \
  -H 'x-gatehouse-session: sess-42' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}'
```

---

## What it enforces, mapped to the OWASP Agentic Top 10 (2026)

Gatehouse is built against the **OWASP Top 10 for Agentic Applications (ASI01–ASI10)** —
not just the 2025 LLM chatbot list. The same table renders live in the console
(Agents & tools → coverage view) and is served by `GET /api/owasp`.

| ID | Threat | Gatehouse control | Where you see it |
|----|--------|-------------------|------------------|
| ASI01 | Agent goal hijack | Tier-1 injection scanner on every request: override, system-prompt probe, exfil-instruction, jailbreak families | Stream reasons, Alerts |
| ASI02 | Tool misuse & exploitation | Per-tool allow / deny / require-approval / mask rules, versioned; every policy change is itself an audited event | Policies |
| ASI03 | Identity & privilege abuse | Gateway holds real upstream credentials; agents get 120-second, tool-scoped, HMAC-signed assertions — revocable mid-flight | Agents & tools, Settings |
| ASI04 | Agentic supply chain | Server/tool inventory derived from live traffic (partial; provenance verification on the roadmap) | Agents & tools |
| ASI05 | Unexpected code execution | Command substitution, shell chaining, `../../`, `~/.ssh`, `.env` patterns blocked in both directions | Alerts |
| ASI06 | Memory & context poisoning | Tool **responses** scanned for injected instructions and redacted (keys, Luhn-validated cards, emails) before they re-enter agent context | Stream ("flagged in response") |
| ASI07 | Insecure inter-agent comms | Roadmap — agent-to-agent trust brokering is out of MVP scope | Roadmap |
| ASI08 | Cascading failures | Per-agent calls/min rate, daily spend ceiling, automatic 60s circuit breaker | Overview, Settings |
| ASI09 | Human-agent trust exploitation | Require-approval policies park calls in an operator queue; silence = denied after 120s; approval and denial both audited | Approval cards in Live stream |
| ASI10 | Rogue agents | Kill switch: one click (or `POST /api/agents/{name}/kill`) revokes an agent and its outstanding credentials instantly | Agents & tools |

Also informed by the OWASP Top 10 for LLM Apps 2025 (prompt injection, excessive agency,
sensitive info disclosure), but the agentic list is the spec.

---

## Why this one and not the other gateways

The honest positioning: inline MCP policy proxies exist (Enkrypt AI, agentsec-gateway,
several infra-grade gateways). Three things here are deliberately different:

1. **The console is the product.** Competitors are backend/CLI-first with thin UIs.
   Gatehouse is console-first: a real-time call stream with payload drill-down,
   an approval queue an operator can actually work, and a hash-chain integrity
   indicator you can point an auditor at.
2. **Built to the Agentic Top 10, benchmarked against it.** The coverage table is
   generated from the same source the console renders — if a control regresses,
   the table and the product both show it.
3. **Session-aware policy + short-lived credentials.** Rules like "deny `send_email`
   if this session already touched `read_env`" and per-call 120s scoped assertions
   are what single-request filters structurally cannot express.

---

## Architecture notes

- **Two transports, one policy pipeline.** Agents always speak HTTP to the gateway.
  Upstream is chosen per tool config: a stdio MCP server gets spawned, managed, and
  multiplexed by the gateway (lifecycle, request routing, and fast-fail on process
  death handled explicitly); an HTTP MCP server gets proxied with the real upstream
  credential injected from the environment.
- **Detection is Tier-1 first.** Regex/heuristic families for injection, exfil,
  code-exec, credential formats, plus entropy scoring — all deterministic, all
  under the latency budget, zero network calls on the hot path. Logging is
  synchronous-but-cheap by design at MVP scale; the audit append is O(1).
- **The audit chain is the evidence.** Every entry stores `SHA-256(prev_hash ‖ canonical entry)`;
  `GET /api/stats` re-verifies the chain on demand. Tamper with the log file and the
  console turns red.
- **State is boring on purpose.** Policies in `policies.json`, audit in append-only
  `data/audit.log`, limits in-process. The config reserves `database_url` / `redis_url`
  for the Postgres/Redis backends in multi-replica deployments.

### Latency budget

Gateway overhead (kill switch + limits + redaction + detection + policy, excluding
upstream execution and approval waits) is displayed live in the Overview as p50/p95.
Tier-1 checks target sub-10ms p50; the demo's calls typically land well under.

---

## Roadmap

- Tier-2 LLM-as-judge escalation for ambiguous payloads only (short timeout, never the default path)
- Postgres + Redis backends for multi-replica audit and shared limit state
- ASI04 provenance verification for MCP servers (signature checking, registry lookups)
- ASI07 inter-agent trust brokering
- OAuth 2.1 upstream flows beyond bearer-token injection

## License

MIT — see [LICENSE](LICENSE).
