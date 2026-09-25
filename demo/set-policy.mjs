#!/usr/bin/env node
/**
 * demo:policy — flip send_email to require-approval in one call, the way an
 * operator would from the console's policy editor.
 */
const GATEWAY = process.env.GATEWAY ?? "http://127.0.0.1:8080";

const res = await fetch(`${GATEWAY}/api/policies`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    tool: "send_email",
    action: "requireApproval",
    note: "email is a write action; a human signs off before anything leaves the building",
  }),
});
const body = await res.json();
console.log(body.ok ? `policy saved (v${body.version}) — send_email now needs operator approval (ASI09)` : `failed: ${body.error}`);
