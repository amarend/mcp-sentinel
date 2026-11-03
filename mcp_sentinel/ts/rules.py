"""
Security rules for JavaScript / TypeScript MCP servers.

These mirror the Python rules (same IDs, same severities) so reports are
comparable across languages. MCP-012 (folded into MCP-005) and MCP-015
(redundant with schema validation such as zod) are intentionally not
implemented for JS/TS.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from ..analysis.poisoning import find_override_phrases
from ..findings.models import SecurityFinding
from ..rules.dangerous_capability import DANGEROUS_TOOL_NAMES
from ..rules.environment_exposure import SENSITIVE_ENV_NAMES
from .lexer import Source, find_closing, lex, split_top_level
from .taint import SANITIZER_CALL, expr_is_tainted, identifiers
from .tools import TSTool, discover_tools, is_mcp_source


TS_EXTENSIONS = {".ts", ".js", ".mjs", ".cjs", ".mts", ".cts"}


def is_ts_file(file: Path) -> bool:
    name = file.name

    return (
        file.suffix in TS_EXTENSIONS
        and not name.endswith(".d.ts")
        and not name.endswith(".min.js")
        and ".test." not in name
        and ".spec." not in name
    )


# ----------------------------------------------------------------
# Sink vocabularies
# ----------------------------------------------------------------

FS_RECEIVERS = {"fs", "fsp", "fsPromises", "promises", "fs.promises"}

FS_FUNCTIONS = {
    "readFile", "readFileSync", "writeFile", "writeFileSync",
    "appendFile", "appendFileSync", "createReadStream",
    "createWriteStream", "open", "openSync", "unlink", "unlinkSync",
    "rm", "rmSync", "rmdir", "rmdirSync", "readdir", "readdirSync",
    "rename", "renameSync", "copyFile", "copyFileSync", "mkdir",
    "mkdirSync", "truncate", "chmod", "symlink",
}

PATH_RECEIVERS = {"path", "nodePath", "posix", "path.posix"}
PATH_FUNCTIONS = {"join", "resolve", "normalize"}

NET_RECEIVERS = {
    "axios", "got", "http", "https", "needle",
    "superagent", "ky", "request", "undici",
}
NET_FUNCTIONS = {
    "get", "post", "put", "patch", "delete", "request", "head", "fetch",
}
NET_BARE = {"fetch", "axios", "got", "ky"}

CP_RECEIVERS = {"child_process", "cp", "childProcess"}
CP_SHELL_FUNCTIONS = {"exec", "execSync"}
CP_SPAWN_FUNCTIONS = {
    "execFile", "execFileSync", "spawn", "spawnSync",
}

SECRET_NAMES = {
    "apikey", "secretkey", "accesskey", "authtoken", "accesstoken",
    "password", "passwd", "token", "clientsecret", "privatekey",
    "awsaccesskeyid", "awssecretaccesskey",
}

PROMPT_VARIABLES = {
    "prompt", "systemprompt", "userprompt", "instruction", "message",
}

_CALL = re.compile(
    r"(?<![\w$.])(?P<receiver>(?:[A-Za-z_$][\w$]*\s*\.\s*)*)"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\("
)

_SECRET_ASSIGN = re.compile(
    r"(?P<name>[A-Za-z_$][\w$]*)\s*[:=]\s*"
    r"(?P<q>[\"'])(?P<value>[^\"'\n]+)(?P=q)"
)

_ENV_DOT = re.compile(r"(?<![\w$.])process\s*\.\s*env\s*\.\s*([A-Za-z_]\w*)")
_ENV_INDEX = re.compile(
    r"(?<![\w$.])process\s*\.\s*env\s*\[\s*[\"'`]([^\"'`]+)[\"'`]\s*\]"
)
_ENV_WHOLE = re.compile(r"(?<![\w$.])process\s*\.\s*env\b(?!\s*[.\[])")

_PROMPT_DECL = re.compile(
    r"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+?)?=\s*"
)

_EVAL = re.compile(r"(?<![\w$.])eval\s*\(")
_NEW_FUNCTION = re.compile(r"(?<![\w$.])new\s+Function\s*\(")
_VM = re.compile(
    r"(?<![\w$])vm\s*\.\s*(?:runInThisContext|runInNewContext|"
    r"runInContext)\s*\(|(?<![\w$.])new\s+vm\s*\.\s*Script\s*\("
)
_UNSERIALIZE = re.compile(
    r"(?<![\w$.])(?:[\w$]+\s*\.\s*)?unserialize\s*\(|"
    r"(?<![\w$.])v8\s*\.\s*deserialize\s*\("
)

_FS_IMPORT = re.compile(
    r"from\s+['\"](?:node:)?fs(?:/promises)?['\"]|"
    r"require\(\s*['\"](?:node:)?fs(?:/promises)?['\"]"
)
_CP_IMPORT = re.compile(
    r"from\s+['\"](?:node:)?child_process['\"]|"
    r"require\(\s*['\"](?:node:)?child_process['\"]"
)

_CONSTANT_ARG = re.compile(r"^\s*([\"'`])\s*\1\s*$")


# ----------------------------------------------------------------
# helpers
# ----------------------------------------------------------------

@lru_cache(maxsize=2048)
def _lex_cached(path: str, mtime_ns: int, size: int) -> Source | None:
    try:
        return lex(Path(path).read_text(errors="ignore"))
    except OSError:
        return None


def load_source(file: Path) -> Source | None:
    try:
        stat = file.stat()
    except OSError:
        return None

    return _lex_cached(str(file), stat.st_mtime_ns, stat.st_size)


def _snake(name: str) -> str:
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return name.replace("-", "_").replace(" ", "_").lower()


class _Context:
    """Everything the rules need about one file."""

    def __init__(self, file: Path, src: Source, tools: list[TSTool]):
        self.file = file
        self.src = src
        self.tools = tools
        self.fs_imported = bool(_FS_IMPORT.search(src.text))
        self.cp_imported = bool(_CP_IMPORT.search(src.text))

    def tool_at(self, offset: int) -> TSTool | None:
        inside = [t for t in self.tools if t.contains(offset)]

        if not inside:
            return None

        return min(inside, key=lambda t: t.body_end - t.body_start)

    def finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        offset: int,
        description: str,
        recommendation: str,
        tool: TSTool | None = None,
    ) -> SecurityFinding:

        tool = tool or self.tool_at(offset)

        return SecurityFinding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            file=str(self.file),
            line=self.src.line_of(offset),
            tool=tool.name if tool else None,
            description=description,
            recommendation=recommendation,
        )

    def calls(self):
        """Yield (offset, receiver, name, arg_spans) for every call."""

        code = self.src.code

        for match in _CALL.finditer(code):

            receiver = re.sub(r"\s+", "", match.group("receiver")).rstrip(".")
            name = match.group("name")

            open_paren = match.end() - 1
            close = find_closing(code, open_paren)

            if close == -1:
                continue

            yield (
                match.start(),
                receiver,
                name,
                split_top_level(code, open_paren + 1, close),
            )

    def arg_tainted(self, span, tool: TSTool | None) -> bool:

        if tool is None:
            return False

        return expr_is_tainted(self.src.code[span[0]:span[1]], tool.tainted)


# ----------------------------------------------------------------
# call classification
# ----------------------------------------------------------------

def _is_fs_call(ctx: _Context, receiver: str, name: str) -> bool:

    if name not in FS_FUNCTIONS:
        return False

    if receiver in FS_RECEIVERS:
        return True

    return receiver == "" and ctx.fs_imported


def _is_net_call(receiver: str, name: str) -> bool:

    if receiver == "" and name in NET_BARE:
        return True

    return receiver in NET_RECEIVERS and name in NET_FUNCTIONS


def _cp_kind(ctx: _Context, receiver: str, name: str) -> str | None:

    if receiver in CP_RECEIVERS:
        pass
    elif receiver == "" and ctx.cp_imported:
        pass
    else:
        return None

    if name in CP_SHELL_FUNCTIONS:
        return "shell"

    if name in CP_SPAWN_FUNCTIONS:
        return "spawn"

    return None


# ----------------------------------------------------------------
# rules
# ----------------------------------------------------------------

def _global_rules(ctx: _Context) -> list[SecurityFinding]:
    """Rules that apply to the whole file, tool or not."""

    findings = []
    src = ctx.src

    # --- MCP-001 command execution ---
    for offset, receiver, name, args in ctx.calls():

        kind = _cp_kind(ctx, receiver, name)

        if kind is None:
            continue

        tool = ctx.tool_at(offset)

        if kind == "shell":

            first = src.code[args[0][0]:args[0][1]] if args else ""

            if _CONSTANT_ARG.match(first):
                continue

            reason = f"{name}() runs a non-constant command through a shell."

        else:

            options = src.code[args[0][0]:args[-1][1]] if args else ""

            if not re.search(r"\bshell\s*:\s*true\b", options):
                continue

            reason = f"{name}() is called with shell: true."

        findings.append(
            ctx.finding(
                "MCP-001", "Dangerous Command Execution", "CRITICAL",
                offset,
                (
                    f"MCP tool '{tool.name}': {reason}"
                    if tool else reason
                ),
                (
                    "Avoid shell execution. Use execFile/spawn with an "
                    "argument array and a strict allowlist, and never "
                    "interpolate tool input into a command string."
                ),
                tool,
            )
        )

    # --- MCP-010 dynamic code execution ---
    for regex, label in (
        (_EVAL, "eval()"),
        (_NEW_FUNCTION, "new Function()"),
        (_VM, "vm code execution"),
    ):
        for match in regex.finditer(src.code):

            findings.append(
                ctx.finding(
                    "MCP-010", "Dynamic Code Execution", "CRITICAL",
                    match.start(),
                    (
                        f"Potentially dangerous dynamic code execution "
                        f"using {label} at line "
                        f"{src.line_of(match.start())}."
                    ),
                    (
                        "Avoid eval(), new Function() and vm with "
                        "untrusted or dynamically controlled input."
                    ),
                )
            )

    # --- MCP-009 unsafe deserialization ---
    for match in _UNSERIALIZE.finditer(src.code):

        findings.append(
            ctx.finding(
                "MCP-009", "Unsafe Deserialization", "CRITICAL",
                match.start(),
                (
                    "Potentially unsafe deserialization at line "
                    f"{src.line_of(match.start())}."
                ),
                (
                    "Do not deserialize untrusted data with "
                    "node-serialize or v8.deserialize. Use JSON with "
                    "schema validation."
                ),
            )
        )

    # --- MCP-002 hardcoded secrets ---
    for match in _SECRET_ASSIGN.finditer(src.clean):

        start = match.start("name")

        # Skip matches that live inside a string literal.
        if src.code[start] == " ":
            continue

        normalized = re.sub(r"[_\-]", "", match.group("name")).lower()

        if normalized not in SECRET_NAMES:
            continue

        value = match.group("value")

        if not value.strip() or "${" in value:
            continue

        findings.append(
            ctx.finding(
                "MCP-002", "Hardcoded Secret", "HIGH", start,
                (
                    "Potential hardcoded secret found in "
                    f"'{match.group('name')}'."
                ),
                (
                    "Remove the secret from source code and load it "
                    "from a secret manager or environment variable."
                ),
            )
        )

    return findings


def _tool_rules(ctx: _Context) -> list[SecurityFinding]:
    """Rules that only apply inside registered MCP tools."""

    findings = []
    src = ctx.src

    # Per-tool capability tracking for MCP-014.
    capabilities: dict[int, set[str]] = {id(t): set() for t in ctx.tools}

    def note(tool, capability):
        if tool is not None:
            capabilities[id(tool)].add(capability)

    for offset, receiver, name, args in ctx.calls():

        tool = ctx.tool_at(offset)

        if tool is None:
            continue

        # ---- filesystem ----
        if _is_fs_call(ctx, receiver, name):

            note(tool, "filesystem")

            # Paths that went through an explicit validation helper
            # (validatePath, sanitize, ...) are not reported.
            first_code = src.code[args[0][0]:args[0][1]] if args else ""

            checked = bool(
                SANITIZER_CALL.search(first_code)
                or (identifiers(first_code) & tool.validated)
            )

            if not checked:
                findings.append(
                    ctx.finding(
                        "MCP-003", "Unsafe File Access", "HIGH", offset,
                        (
                            f"MCP tool '{tool.name}' directly accesses "
                            f"the filesystem using {name}()."
                        ),
                        (
                            "Restrict file access to an explicit "
                            "allowlist of directories. Validate and "
                            "normalize user-provided paths first."
                        ),
                        tool,
                    )
                )

            if args and ctx.arg_tainted(args[0], tool):

                findings.append(
                    ctx.finding(
                        "MCP-011", "Potential Path Traversal", "HIGH",
                        offset,
                        (
                            f"MCP tool '{tool.name}' passes a "
                            f"user-controlled value to {name}() at "
                            f"line {src.line_of(offset)}."
                        ),
                        (
                            "Resolve the path, then verify it stays "
                            "inside an approved directory before use."
                        ),
                        tool,
                    )
                )

        # ---- path construction ----
        elif receiver in PATH_RECEIVERS and name in PATH_FUNCTIONS:

            if any(ctx.arg_tainted(span, tool) for span in args):

                findings.append(
                    ctx.finding(
                        "MCP-011", "Potential Path Traversal", "HIGH",
                        offset,
                        (
                            f"MCP tool '{tool.name}' builds a path from "
                            f"user-controlled input at line "
                            f"{src.line_of(offset)}."
                        ),
                        (
                            "Validate and normalize user supplied paths "
                            "and restrict access to an approved "
                            "directory."
                        ),
                        tool,
                    )
                )

        # ---- network ----
        elif _is_net_call(receiver, name):

            note(tool, "network")

            findings.append(
                ctx.finding(
                    "MCP-004", "Unrestricted Network Access", "MEDIUM",
                    offset,
                    (
                        f"MCP tool '{tool.name}' performs outbound "
                        "network access."
                    ),
                    (
                        "Restrict outbound access to approved "
                        "destinations and protocols."
                    ),
                    tool,
                )
            )

            first = args[0] if args else None

            url_tainted = first is not None and ctx.arg_tainted(first, tool)

            if first is not None and not url_tainted:
                # axios({ url: x }) / fetch(new Request(x))
                options = src.code[first[0]:first[1]]
                url_tainted = bool(
                    re.search(r"\burl\s*:", options)
                    and ctx.arg_tainted(first, tool)
                )

            if url_tainted:

                findings.append(
                    ctx.finding(
                        "MCP-005", "Potential SSRF", "HIGH", offset,
                        (
                            f"MCP tool '{tool.name}' passes "
                            "user-controlled input to an outbound "
                            "network request."
                        ),
                        (
                            "Validate and restrict user-controlled "
                            "URLs and hosts. Block private, loopback, "
                            "link-local and cloud metadata addresses."
                        ),
                        tool,
                    )
                )

        # ---- command / eval capability ----
        if _cp_kind(ctx, receiver, name) or name == "eval":
            note(tool, "command_execution")

    # ---- environment exposure (MCP-013) ----
    for regex, group in ((_ENV_DOT, 1), (_ENV_INDEX, 1)):

        source = src.code if regex is _ENV_DOT else src.clean

        for match in regex.finditer(source):

            tool = ctx.tool_at(match.start())

            if tool is None:
                continue

            env_name = match.group(group)

            if (
                env_name.upper() not in SENSITIVE_ENV_NAMES
                and not re.search(
                    r"(API_?KEY|SECRET|TOKEN|PASSWORD|PRIVATE_?KEY)$",
                    env_name.upper(),
                )
            ):
                continue

            findings.append(
                ctx.finding(
                    "MCP-013", "Sensitive Environment Exposure",
                    "CRITICAL", match.start(),
                    (
                        f"MCP tool '{tool.name}' accesses the sensitive "
                        f"environment variable '{env_name}'. The value "
                        "may be exposed through the tool response."
                    ),
                    (
                        "Keep credentials server-side and return only "
                        "the minimum required data."
                    ),
                    tool,
                )
            )

    for match in _ENV_WHOLE.finditer(src.code):

        tool = ctx.tool_at(match.start())

        if tool is None:
            continue

        findings.append(
            ctx.finding(
                "MCP-013", "Sensitive Environment Exposure", "CRITICAL",
                match.start(),
                (
                    f"MCP tool '{tool.name}' reads the entire process "
                    "environment, which commonly contains secrets and "
                    "may be returned to the model."
                ),
                (
                    "Never return process.env. Expose only specific, "
                    "non-sensitive variables."
                ),
                tool,
            )
        )

    # ---- prompt injection (MCP-008) ----
    for match in _PROMPT_DECL.finditer(src.code):

        variable = match.group(1)

        if variable.lower() not in PROMPT_VARIABLES:
            continue

        tool = ctx.tool_at(match.start())

        if tool is None:
            continue

        end = match.end()

        while end < tool.body_end and src.code[end] not in ";\n":
            end += 1

        expression = src.code[match.end():end]

        if "`" not in expression and "+" not in expression:
            continue

        if not expr_is_tainted(expression, tool.tainted):
            continue

        findings.append(
            ctx.finding(
                "MCP-008", "Potential Prompt Injection", "HIGH",
                match.start(),
                (
                    f"MCP tool '{tool.name}' places user-controlled "
                    f"input into the prompt '{variable}'."
                ),
                (
                    "Treat tool parameters as untrusted. Validate and "
                    "constrain input before building prompts."
                ),
                tool,
            )
        )

    # ---- per-tool metadata rules ----
    for tool in ctx.tools:

        line_offset = _offset_of_line(src, tool.line)

        # MCP-007 tool poisoning
        if tool.description:

            matched = find_override_phrases(tool.description)

            if matched:
                findings.append(
                    ctx.finding(
                        "MCP-007", "Potential Tool Poisoning", "HIGH",
                        line_offset,
                        (
                            f"MCP tool '{tool.name}' contains "
                            f"suspicious instructions: "
                            f"{', '.join(matched)}."
                        ),
                        (
                            "Review the tool description. Metadata "
                            "should describe functionality, not "
                            "instruct the model to bypass controls or "
                            "disclose sensitive information."
                        ),
                        tool,
                    )
                )

        # MCP-006 dangerous capability by name
        if _snake(tool.name) in DANGEROUS_TOOL_NAMES:
            findings.append(
                ctx.finding(
                    "MCP-006", "Dangerous Tool Capability", "HIGH",
                    line_offset,
                    (
                        f"MCP tool '{tool.name}' exposes a potentially "
                        "privileged system capability."
                    ),
                    (
                        "Apply least privilege and restrict privileged "
                        "operations to explicitly approved use cases."
                    ),
                    tool,
                )
            )

        # MCP-014 excessive capability
        caps = capabilities[id(tool)]

        if len(caps) >= 2:
            findings.append(
                ctx.finding(
                    "MCP-014", "Excessive Tool Capability", "HIGH",
                    line_offset,
                    (
                        f"MCP tool '{tool.name}' combines multiple "
                        f"high-risk capabilities: "
                        f"{', '.join(sorted(caps))}."
                    ),
                    (
                        "Split broad tools into narrowly scoped tools, "
                        "each limited to the capability it needs."
                    ),
                    tool,
                )
            )

    return findings


def _offset_of_line(src: Source, line: int) -> int:
    """Offset of the first character of ``line`` (1-based)."""

    offset = 0

    for _ in range(line - 1):
        offset = src.text.find("\n", offset) + 1

    return offset


# ----------------------------------------------------------------
# entry point
# ----------------------------------------------------------------

def run_typescript_rules(files: list[Path]) -> list[SecurityFinding]:
    """
    Analyse JS/TS files. Files are only analysed when the repository
    contains at least one recognisable MCP server file, so unrelated
    JavaScript in a monorepo does not generate findings.
    """

    files = [f for f in files if is_ts_file(f)]

    sources = {}

    for file in files:

        src = load_source(file)

        if src is not None:
            sources[file] = src

    if not any(is_mcp_source(s.text) for s in sources.values()):
        return []

    findings: list[SecurityFinding] = []

    for file, src in sources.items():

        tools = (
            discover_tools(src, file) if is_mcp_source(src.text) else []
        )

        ctx = _Context(file, src, tools)

        findings.extend(_global_rules(ctx))
        findings.extend(_tool_rules(ctx))

    return findings
