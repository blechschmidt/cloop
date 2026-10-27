#!/usr/bin/env python3
# model.py PORT LOG — a model for the GitHub Copilot CLI to talk to, so a copilot
# run needs no GitHub account and no Copilot seat (Task 20450).
#
# The CLI's bring-your-own-key mode (COPILOT_PROVIDER_BASE_URL, with
# COPILOT_OFFLINE) speaks OpenAI's chat-completions API, streamed. This answers
# as an agent would: the first turn of a conversation asks for one bash tool
# call — write copilot-hello.txt and show it — and once the tool's result is in
# the conversation it signs off with TASK_DONE. Every request is logged to LOG
# as one JSON line: the model asked for, the tools the CLI offered, and the
# tool result it sent back, which is the proof the command ran where the CLI
# runs.
#
# It listens on 127.0.0.1 only: it runs on the device, beside the agent whose
# payload calls it.
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = open(sys.argv[2], "a", buffering=1)
WORK = "printf 'written by copilot on the device\\n' > copilot-hello.txt && cat copilot-hello.txt"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            self.send_error(404)
            return
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        result = next((m.get("content") for m in req.get("messages", []) if m.get("role") == "tool"), None)
        LOG.write(json.dumps({
            "model": req.get("model"),
            "tools": [t.get("function", {}).get("name") for t in req.get("tools", [])],
            "tool_result": result,
        }) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()

        def event(**fields):
            fields.update(id="rig-1", object="chat.completion.chunk", created=int(time.time()), model=req.get("model"))
            self.wfile.write(("data: " + json.dumps(fields) + "\n\n").encode())
            self.wfile.flush()

        if result is None:
            args = json.dumps({"command": WORK, "description": "write the file", "mode": "sync"})
            event(choices=[{"index": 0, "delta": {"role": "assistant", "content": "Writing the file."}}])
            event(choices=[{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                                                   "function": {"name": "bash", "arguments": args}}]}}])
            event(choices=[{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                  usage={"prompt_tokens": 900, "completion_tokens": 30, "total_tokens": 930})
        else:
            event(choices=[{"index": 0, "delta": {"role": "assistant",
                                                  "content": "Wrote copilot-hello.txt on the device.\nTASK_DONE"}}])
            event(choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}],
                  usage={"prompt_tokens": 1000, "completion_tokens": 12, "total_tokens": 1012})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
