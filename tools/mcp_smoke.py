"""Smoke-test a stdio MCP server the way a real client does.

Why this exists as a separate check: the unit tests call the tool functions directly,
which proves the logic works but says nothing about whether the server starts, speaks
MCP over stdio, and registers its tools. Those are different failures, and only one of
them shows up in pytest.

Run after installing:

    python tools/mcp_smoke.py

Exits non-zero on the first failed check, so it is usable as a release gate.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

EXPECTED_TOOLS = {
    "memory_write",
    "memory_recall",
    "memory_forget",
    "memory_sweep",
    "memory_explain",
    "memory_stats",
    "memory_audit_tail",
    "memory_flagged",
    "memory_report",
    "memory_verify",
    "memory_policy",
}


def _pump(stream, sink: queue.Queue) -> None:
    """Drain a pipe into a queue on its own thread.

    Necessary rather than merely tidy: closing stdin to signal EOF makes the server exit
    before it has answered pending requests, so the replies are simply lost. A real MCP
    client keeps the connection open and reads as replies arrive.
    """
    try:
        for line in stream:
            sink.put(line)
    except (ValueError, OSError):  # pragma: no cover - stream closed underneath us
        pass


def _drain(sink: queue.Queue) -> str:
    chunks: list[str] = []
    while True:
        try:
            chunks.append(sink.get_nowait())
        except queue.Empty:
            return "".join(chunks)


def _collect(out: queue.Queue, wanted: set[int], timeout: float) -> dict[int, dict]:
    """Read replies until every wanted id has been seen, or the deadline passes."""
    replies: dict[int, dict] = {}
    deadline = time.monotonic() + timeout
    while set(replies) < wanted and time.monotonic() < deadline:
        try:
            line = out.get(timeout=0.25)
        except queue.Empty:
            continue
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue  # servers may log to stdout; not our problem here
        if isinstance(message.get("id"), int):
            replies[message["id"]] = message
    return replies


def result_payload(result: dict) -> dict:
    """Tool results arrive as `structuredContent` plus a JSON string in `content[0].text`.

    A tool that raised comes back as `isError: true` with empty content and no
    `structuredContent`. Raising the raw result here rather than letting `json.loads` fail
    on an empty string keeps the failure legible and says which tool misbehaved.
    """
    if "structuredContent" in result:
        return result["structuredContent"]
    content = result.get("content") or []
    text = (content[0].get("text") if content else "") or ""
    if not text:
        raise RuntimeError(
            f"tool returned no payload (isError={result.get('isError')!r}): {result!r}"
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        # When a tool raises, MCP returns `isError` with the exception message as plain
        # text. Surface it verbatim -- a JSON traceback here would hide the actual fault.
        raise RuntimeError(
            f"tool returned a non-JSON payload (isError={result.get('isError')!r}): "
            f"{text[:600]!r}"
        ) from exc


def main() -> int:
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'ok' if ok else 'FAIL'}] {name}{(' -- ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    # `ignore_cleanup_errors` because Windows can keep the SQLite file and its -wal/-shm
    # companions locked for a few milliseconds after the child exits. A release gate that
    # fails intermittently is a release gate people learn to ignore.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        env = dict(os.environ)
        env.update(
            {
                "AMNESIA_POLICY": str(REPO / "policies" / "default.yaml"),
                "AMNESIA_DB": str(Path(tmp) / "smoke.db"),
                "AMNESIA_AUDIT": str(Path(tmp) / "smoke.jsonl"),
            }
        )

        # Prefer the installed console script; fall back to the module so this works
        # from a source checkout without an install.
        script = Path(sys.executable).parent / (
            "amnesia-server.exe" if os.name == "nt" else "amnesia-server"
        )
        command = [str(script)] if script.exists() else [sys.executable, "-m", "amnesia.server"]
        print(f"Server: {' '.join(command)}")

        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=env,
        )
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None

        stdout_queue: queue.Queue = queue.Queue()
        stderr_queue: queue.Queue = queue.Queue()
        threading.Thread(target=_pump, args=(process.stdout, stdout_queue), daemon=True).start()
        threading.Thread(target=_pump, args=(process.stderr, stderr_queue), daemon=True).start()

        def send(message: dict) -> None:
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()

        try:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "mcp_smoke", "version": "0"},
                    },
                }
            )
            # Consume the initialize reply now, but keep it: _collect removes lines from
            # the queue, so the final gather below would never see it again.
            replies = _collect(stdout_queue, {1}, timeout=15)
            if not replies:
                check("server responded to initialize", False, _drain(stderr_queue)[:300])
                process.kill()
                return 1

            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            # Await each reply before issuing the next call, exactly as a real client does.
            # Firing tool calls back to back lets the server dispatch them concurrently, so
            # the recall can race the write it depends on and the check fails for a reason
            # that has nothing to do with the server. Sequencing here is what makes this a
            # faithful simulation rather than a source of phantom bugs.
            replies.update(_collect(stdout_queue, {2}, timeout=15))

            send(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "memory_write",
                        "arguments": {
                            "content": "Dana Whitfield's 2025 performance rating is B+.",
                            "source": "hr-system",
                            "tenant": "acme",
                            "scope": "hr_only",
                            "owner": "dana",
                            "subject": "perf:dana",
                        },
                    },
                }
            )
            replies.update(_collect(stdout_queue, {3}, timeout=15))

            send(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "memory_recall",
                        "arguments": {
                            "query": "performance rating",
                            "principal_id": "alice",
                            "tenant": "acme",
                            "roles": "employee",
                        },
                    },
                }
            )
            replies.update(_collect(stdout_queue, {4}, timeout=20))
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
                process.wait(timeout=10)
            # Let the child's file handles be released before the temp directory goes
            # away. Without this the cleanup raced the OS and failed intermittently.
            time.sleep(0.3)

        stderr = _drain(stderr_queue)

        server_info = replies.get(1, {}).get("result", {}).get("serverInfo", {})
        check("initialize", server_info.get("name") == "amnesia", str(server_info))

        tools = {t["name"] for t in replies.get(2, {}).get("result", {}).get("tools", [])}
        check("tools registered", tools == EXPECTED_TOOLS, f"{len(tools)} tools")
        missing, extra = EXPECTED_TOOLS - tools, tools - EXPECTED_TOOLS
        if missing or extra:
            check("tool set matches", False, f"missing={sorted(missing)} extra={sorted(extra)}")

        write_reply = replies.get(3)
        if write_reply is None:
            check("write over the wire", False, "no reply")
        elif "error" in write_reply:
            check("write over the wire", False, str(write_reply["error"])[:200])
        else:
            payload = result_payload(write_reply["result"])
            check("write over the wire", payload.get("stored") is True, payload.get("reason", ""))

        recall_reply = replies.get(4)
        if recall_reply is None:
            check("read gate holds over the wire", False, "no reply")
        elif "error" in recall_reply:
            check("read gate holds over the wire", False, str(recall_reply["error"])[:200])
        else:
            payload = result_payload(recall_reply["result"])
            returned = len(payload.get("results", []))
            withheld = payload.get("denied_count", 0)
            check(
                "read gate holds over the wire",
                returned == 0 and withheld == 1,
                f"returned {returned}, withheld {withheld}",
            )
            if payload.get("denied"):
                check("refusal carries a reason", bool(payload["denied"][0].get("reason")))

        check("stderr clean", not stderr.strip(), stderr.strip()[:200])

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("MCP server smoke test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
