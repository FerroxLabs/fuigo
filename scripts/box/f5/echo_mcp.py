"""Minimal stdio MCP server for the B-F5 fixture: one `echo` tool."""
import json
import sys
import time

DELAY = float(sys.argv[sys.argv.index("--init-delay") + 1]) if "--init-delay" in sys.argv else 0.0

for raw in sys.stdin:
    try:
        msg = json.loads(raw)
    except ValueError:
        continue
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        time.sleep(DELAY)
        result = {"protocolVersion": msg.get("params", {}).get("protocolVersion", "2024-11-05"),
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "f5echo", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "echo", "description": "echo text",
                             "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}]}
    elif method == "tools/call":
        text = msg.get("params", {}).get("arguments", {}).get("text", "")
        result = {"content": [{"type": "text", "text": "F5 ECHO " + text}]}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "no"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
