"""High-level entry points for live scanning."""

from __future__ import annotations

import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from ..findings.models import SecurityFinding
from ..rules import dedupe_findings, sort_findings
from .analyzer import analyze_snapshot
from .baseline import compare, fingerprint, load_baseline
from .client import (
    HttpTransport,
    MCPClientError,
    ServerSnapshot,
    StdioTransport,
    inspect_server,
)


@dataclass
class LiveTarget:
    """Where to find the server. Exactly one of command / url."""

    command: str | None = None
    url: str | None = None
    env: dict[str, str] | None = None
    headers: dict[str, str] | None = None
    inherit_env: bool = False
    cwd: str | None = None
    timeout: float = 30.0

    def validate(self):

        if bool(self.command) == bool(self.url):
            raise ValueError("Provide exactly one of --command or --url.")

    @property
    def label(self) -> str:
        """Display name for reports. URLs lose credentials and query."""

        if self.url:
            parsed = urlsplit(self.url)
            host = parsed.hostname or ""

            if parsed.port:
                host += f":{parsed.port}"

            return f"{parsed.scheme}://{host}{parsed.path}"

        return self.command or "?"


@dataclass
class LiveResult:
    snapshot: ServerSnapshot
    findings: list[SecurityFinding]
    fingerprint: dict


def _has_auth(headers: dict[str, str] | None) -> bool:

    return any(
        any(word in key.lower() for word in ("auth", "token", "key"))
        for key in (headers or {})
    )


def fetch_snapshot(target: LiveTarget) -> ServerSnapshot:
    """Connect, run the read-only handshake and disconnect."""

    target.validate()

    if target.command:

        try:
            argv = shlex.split(target.command)
        except ValueError as error:
            raise MCPClientError(f"Bad --command: {error}") from error

        if not argv:
            raise MCPClientError("--command is empty")

        transport = StdioTransport(
            argv,
            env=target.env,
            inherit_env=target.inherit_env,
            cwd=target.cwd,
            timeout=target.timeout,
        )

    else:

        transport = HttpTransport(
            target.url,
            headers=target.headers,
            timeout=target.timeout,
        )

    try:
        snapshot = inspect_server(transport, target.label)
    finally:
        transport.close()

    snapshot.auth_supplied = _has_auth(target.headers)

    return snapshot


def scan_live(
    target: LiveTarget,
    baseline_path: Path | None = None,
) -> LiveResult:
    """Fetch a snapshot, analyse it and (optionally) diff vs a baseline."""

    snapshot = fetch_snapshot(target)

    findings = analyze_snapshot(snapshot)

    current = fingerprint(snapshot)

    if baseline_path is not None:

        label = f"live://{snapshot.transport}/{snapshot.target}"

        findings.extend(
            compare(load_baseline(baseline_path), current, label)
        )

    return LiveResult(
        snapshot=snapshot,
        findings=sort_findings(dedupe_findings(findings)),
        fingerprint=current,
    )


def watch_live(
    target: LiveTarget,
    interval: float,
    on_result: Callable[[int, LiveResult, list[SecurityFinding]], None],
    on_error: Callable[[int, Exception], None],
    baseline_path: Path | None = None,
    max_runs: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
):
    """
    Re-scan every ``interval`` seconds.

    The first run is compared against ``baseline_path`` (if given); every
    later run is compared against the previous run, so any change to a
    tool or the server's instructions while it is running is reported
    immediately. ``on_result`` receives only the *new* change findings
    plus all analysis findings on the first run.
    """

    previous: dict | None = None
    runs = 0

    while max_runs is None or runs < max_runs:

        runs += 1

        try:
            result = scan_live(target, baseline_path if runs == 1 else None)

            label = f"live://{result.snapshot.transport}/{result.snapshot.target}"

            if previous is None:
                reported = result.findings
            else:
                changes = compare(previous, result.fingerprint, label)
                reported = sort_findings(changes)

            previous = result.fingerprint

            on_result(runs, result, reported)

        except (MCPClientError, ValueError) as error:
            on_error(runs, error)

        if max_runs is not None and runs >= max_runs:
            break

        sleep(interval)
