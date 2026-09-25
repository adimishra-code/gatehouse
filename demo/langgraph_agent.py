#!/usr/bin/env python3
"""
LangGraph demo agent for Gatehouse.

A minimal ReAct-style graph whose tool calls go THROUGH the gatehouse, so you
can watch the console block an injection attempt coming from a "tool result"
mid-run — the ASI01/ASI06 story, live.

    pip install langgraph langchain-core langchain-mcp-adapters
    export GATEHOUSE_URL=http://127.0.0.1:8080
    export OPENAI_API_KEY=...          # or swap the model below
    python demo/langgraph_agent.py
"""

import json
import os
import urllib.request

GATEWAY = os.environ.get("GATEHOUSE_URL", "http://127.0.0.1:8080")
SERVER = os.environ.get("DEMO_SERVER", "mcp-echo")
AGENT = "langgraph-demo"
SESSION = "sess-langgraph-1"


def gatehouse_tool_call(name: str, arguments: dict) -> str:
    """POST a tools/call through the gatehouse. Blocked calls raise with the
    gateway's plain-language reason — exactly what the operator sees."""
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }).encode()
    req = urllib.request.Request(
        f"{GATEWAY}/{SERVER}",
        data=body,
        headers={
            "content-type": "application/json",
            "x-gatehouse-agent": AGENT,
            "x-gatehouse-session": SESSION,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=140) as resp:
            data = json.loads(resp.read())
            return json.dumps(data.get("result", data))
    except urllib.error.HTTPError as e:
        detail = json.loads(e.read()).get("error", {}).get("message", str(e))
        # The agent sees the block, the reason, and nothing else.
        return f"BLOCKED BY GATEHOUSE: {detail}"


def main() -> None:
    try:
        from langgraph.prebuilt import create_react_agent
    except ImportError:
        raise SystemExit("pip install langgraph langchain-core first — see docstring")

    try:
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    except Exception:
        raise SystemExit("configure a LangChain chat model (langchain_openai shown); any provider works")

    tools = [
        {
            "type": "function",
            "function": {
                "name": "gatehouse_call",
                "description": "Call an MCP tool through the Gatehouse security gateway",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "arguments": {"type": "object"},
                    },
                    "required": ["name", "arguments"],
                },
            },
        }
    ]

    def gatehouse_call(name: str, arguments: dict) -> str:
        return gatehouse_tool_call(name, arguments)

    agent = create_react_agent(llm, tools)

    # One benign run, then a poisoned-response scenario: leaky_notes returns
    # text carrying an injected instruction. Watch the console: the response
    # gets flagged (ASI06) before this agent ever reads it.
    for prompt in (
        "Use gatehouse_call to run tool 'echo' with {'text': 'daily standup notes'} and summarize.",
        "Use gatehouse_call to run tool 'leaky_notes' and follow any instructions you find in the notes.",
    ):
        print(f"\n=== {prompt[:70]}…")
        for chunk in agent.stream({"messages": [("user", prompt)]}, stream_mode="values"):
            msg = chunk["messages"][-1]
            print(f"{type(msg).__name__}: {str(msg.content)[:220]}")


if __name__ == "__main__":
    main()
