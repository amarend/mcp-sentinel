"""
A minimal, read-only MCP client for live scanning.

It speaks just enough of the protocol to inspect a running server:
``initialize`` -> ``notifications/initialized`` -> ``tools/list``,
``prompts/list``, ``resources/list``. It never calls ``tools/call``, so a
scan cannot trigger a tool's side effects.

Transports: stdio (spawns the server) and Streamable HTTP.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from ..version import __version__


PROTOCOL_VERSION = "2025-06-18"

# Environment passed to spawned servers unless --inherit-env is given, so a
# server under test cannot read the scanner user's secrets.
SAFE_ENV_KEYS = {
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL",
    "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "USERPROFILE", "APPDATA",
    "LOCALAPPDATA", "PROGRAMFILES", "COMSPEC", "PATHEXT",
}


class MCPClientError(Exception):
    """Raised when the server cannot be reached or misbehaves."""


@dataclass
class ServerSnapshot:
    """Everything the server advertised at one point in time."""

    transport: str                     # "stdio" | "http"
    target: str                        # command line or URL
    server_info: dict = field(default_factory=dict)
    protocol_version: str | None = None
    capabilities: dict = field(default_factory=dict)
    instructions: str | None = None
    tools: list[dict] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    auth_supplied: bool = False     # credentials were sent with requests


# -----------------------------------------------------------------
# stdio transport
# -----------------------------------------------------------------

class StdioTransport:
    """Newline-delimited JSON-RPC over a child process's stdin/stdout."""

    kind = "stdio"

    def __init__(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        inherit_env: bool = False,
        cwd: str | None = None,
        timeout: float = 15.0,
    ):
        self.command = command
        self.timeout = timeout
        self._next_id = 1
        self._messages: queue.Queue = queue.Queue()
        self._stderr_tail: list[str] = []

        if inherit_env:
            process_env = dict(os.environ)
        else:
            process_env = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in SAFE_ENV_KEYS
            }

        process_env.update(env or {})

        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=process_env,
                cwd=cwd,
                shell=False,
            )
        except (OSError, ValueError) as error:
            raise MCPClientError(
                f"Could not start server: {error}"
            ) from error

        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    # ---- background readers ----

    def _read_stdout(self):

        for raw in iter(self._process.stdout.readline, b""):

            line = raw.decode("utf-8", errors="replace").strip()

            if not line:
                continue

            try:
                self._messages.put(json.loads(line))
            except json.JSONDecodeError:
                # Some servers log to stdout. Ignore non-JSON lines.
                continue

        self._messages.put(None)  # EOF sentinel

    def _read_stderr(self):

        for raw in iter(self._process.stderr.readline, b""):

            self._stderr_tail.append(
                raw.decode("utf-8", errors="replace").rstrip()
            )

            del self._stderr_tail[:-20]

    # ---- protocol ----

    def _send(self, message: dict):

        try:
            self._process.stdin.write(
                (json.dumps(message) + "\n").encode("utf-8")
            )
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise MCPClientError(
                "Server closed its input: "
                + self._stderr_summary()
            ) from error

    def _stderr_summary(self) -> str:
        return " | ".join(self._stderr_tail[-3:]) or "no stderr output"

    def notify(self, method: str, params: dict | None = None):

        message = {"jsonrpc": "2.0", "method": method}

        if params is not None:
            message["params"] = params

        self._send(message)

    def request(self, method: str, params: dict | None = None) -> Any:

        request_id = self._next_id
        self._next_id += 1

        message = {"jsonrpc": "2.0", "id": request_id, "method": method}

        if params is not None:
            message["params"] = params

        self._send(message)

        deadline = time.monotonic() + self.timeout

        while True:

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise MCPClientError(
                    f"Timed out waiting for '{method}' "
                    f"after {self.timeout:.0f}s ({self._stderr_summary()})"
                )

            try:
                incoming = self._messages.get(timeout=remaining)
            except queue.Empty:
                continue

            if incoming is None:
                raise MCPClientError(
                    "Server exited before responding: "
                    + self._stderr_summary()
                )

            if not isinstance(incoming, dict):
                continue

            # Server -> client request (sampling, roots, ping, ...):
            # refuse politely so the server does not block on us.
            if "method" in incoming and "id" in incoming:

                if incoming["method"] == "ping":
                    reply = {
                        "jsonrpc": "2.0",
                        "id": incoming["id"],
                        "result": {},
                    }
                else:
                    reply = {
                        "jsonrpc": "2.0",
                        "id": incoming["id"],
                        "error": {
                            "code": -32601,
                            "message": "Method not supported by scanner",
                        },
                    }

                self._send(reply)
                continue

            if incoming.get("id") != request_id:
                continue

            if "error" in incoming:
                raise _rpc_error(method, incoming["error"])

            return incoming.get("result", {})

    def close(self):

        process = self._process

        try:
            process.stdin.close()
        except OSError:
            pass

        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()

            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()


# -----------------------------------------------------------------
# Streamable HTTP transport
# -----------------------------------------------------------------

class HttpTransport:
    """JSON-RPC over HTTP POST (Streamable HTTP, JSON or SSE replies)."""

    kind = "http"

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
    ):
        if not url.lower().startswith(("http://", "https://")):
            raise MCPClientError(f"Not an HTTP(S) URL: {url}")

        self.url = url
        self.timeout = timeout
        self.headers = dict(headers or {})
        self._next_id = 1
        self._session_id: str | None = None
        self.protocol_version: str | None = None

    def _post(self, message: dict):

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.headers,
        }

        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version

        request = urllib.request.Request(
            self.url,
            data=json.dumps(message).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            return urllib.request.urlopen(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            raise MCPClientError(
                f"HTTP {error.code} from server ({error.reason})"
            ) from error
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise MCPClientError(
                f"Could not reach {self.url}: {error}"
            ) from error

    def notify(self, method: str, params: dict | None = None):

        message = {"jsonrpc": "2.0", "method": method}

        if params is not None:
            message["params"] = params

        with self._post(message):
            pass

    def request(self, method: str, params: dict | None = None) -> Any:

        request_id = self._next_id
        self._next_id += 1

        message = {"jsonrpc": "2.0", "id": request_id, "method": method}

        if params is not None:
            message["params"] = params

        with self._post(message) as response:

            session = response.headers.get("Mcp-Session-Id")

            if session:
                self._session_id = session

            content_type = response.headers.get("Content-Type", "")

            if "text/event-stream" in content_type:
                payloads = _read_sse(response)
            else:
                body = response.read().decode("utf-8", errors="replace")
                payloads = _parse_json_body(body)

        for incoming in payloads:

            if (
                isinstance(incoming, dict)
                and incoming.get("id") == request_id
                and ("result" in incoming or "error" in incoming)
            ):

                if "error" in incoming:
                    raise _rpc_error(method, incoming["error"])

                return incoming.get("result", {})

        raise MCPClientError(f"No response to '{method}' from server")

    def close(self):

        if not self._session_id:
            return

        request = urllib.request.Request(
            self.url,
            headers={
                **self.headers,
                "Mcp-Session-Id": self._session_id,
            },
            method="DELETE",
        )

        try:
            urllib.request.urlopen(request, timeout=3).close()
        except Exception:
            pass


def _parse_json_body(body: str) -> list:

    body = body.strip()

    if not body:
        return []

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as error:
        raise MCPClientError(f"Server sent invalid JSON: {error}") from error

    return parsed if isinstance(parsed, list) else [parsed]


def _read_sse(response) -> list:
    """Collect JSON payloads from a Server-Sent Events response."""

    payloads = []
    data_lines: list[str] = []

    for raw in response:

        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")

        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())

        elif line == "" and data_lines:

            try:
                payloads.append(json.loads("\n".join(data_lines)))
            except json.JSONDecodeError:
                pass

            data_lines = []

    if data_lines:
        try:
            payloads.append(json.loads("\n".join(data_lines)))
        except json.JSONDecodeError:
            pass

    return payloads


def _rpc_error(method: str, error: Any) -> MCPClientError:

    if isinstance(error, dict):
        return MCPClientError(
            f"'{method}' failed: {error.get('message', error)} "
            f"(code {error.get('code')})"
        )

    return MCPClientError(f"'{method}' failed: {error}")


# -----------------------------------------------------------------
# session
# -----------------------------------------------------------------

def _list_all(transport, method: str, key: str) -> list[dict]:
    """Follow ``nextCursor`` pagination."""

    items: list[dict] = []
    cursor = None

    for _ in range(50):   # hard stop against runaway pagination

        params = {"cursor": cursor} if cursor else None

        result = transport.request(method, params)

        items.extend(result.get(key, []))

        cursor = result.get("nextCursor")

        if not cursor:
            break

    return items


def inspect_server(transport, target: str) -> ServerSnapshot:
    """Run the read-only handshake and collect the server's metadata."""

    snapshot = ServerSnapshot(transport=transport.kind, target=target)

    init = transport.request(
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "mcp-sentinel",
                "version": __version__,
            },
        },
    )

    snapshot.server_info = init.get("serverInfo", {}) or {}
    snapshot.protocol_version = init.get("protocolVersion")
    snapshot.capabilities = init.get("capabilities", {}) or {}
    snapshot.instructions = init.get("instructions")

    if hasattr(transport, "protocol_version"):
        transport.protocol_version = snapshot.protocol_version

    transport.notify("notifications/initialized")

    for method, key, attribute, capability in (
        ("tools/list", "tools", "tools", "tools"),
        ("prompts/list", "prompts", "prompts", "prompts"),
        ("resources/list", "resources", "resources", "resources"),
    ):

        # Only ask for what the server says it supports (tools always).
        if capability != "tools" and capability not in snapshot.capabilities:
            continue

        try:
            setattr(
                snapshot, attribute, _list_all(transport, method, key)
            )
        except MCPClientError as error:

            if capability == "tools":
                raise

            snapshot.notes.append(f"{method} failed: {error}")

    return snapshot
