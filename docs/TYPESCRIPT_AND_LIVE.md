# TypeScript support and live scanning (v0.2)

## TypeScript / JavaScript static analysis

`mcp-sentinel scan <path>` now analyses `.ts .mts .cts .js .mjs .cjs` files
(skipping `.d.ts`, `.min.js`, `*.test.*`, `*.spec.*`, `node_modules`, `dist`,
`build`).

Recognised tool registrations:

| Style | Example |
|-------|---------|
| MCP TypeScript SDK | `server.registerTool(name, config, handler)` / `server.tool(name, desc, schema, handler)` |
| Low-level SDK | `server.setRequestHandler(CallToolRequestSchema, handler)` |
| FastMCP (TS) | `server.addTool({ name, description, execute })` |
| mcp-framework | `class X extends MCPTool { execute() {} }` |

Rules mirrored from the Python scanner: MCP-001, 002, 003, 004, 005, 006,
007, 008, 009, 010, 011, 013, 014. (MCP-012 is folded into MCP-005; MCP-015
is skipped because zod/JSON-schema validation makes it noisy.)

Taint tracking follows tool inputs through `const x = ...` assignments,
destructuring and template strings. A value that passes through a function
whose name contains `validate`, `sanitize`, `normalize`, `escape`, `assert`
or `authorize` is treated as checked.

Implementation: a dependency-free lexer (`mcp_sentinel/ts/lexer.py`) blanks
comments and string contents so brace matching and sink detection cannot be
fooled by text in strings. It is not a full parser; see *Limitations*.

## Live scanning

```
# stdio server (the command is executed!)
mcp-sentinel live --command "npx -y @modelcontextprotocol/server-everything"

# remote Streamable HTTP server
mcp-sentinel live --url https://example.com/mcp -H "Authorization: Bearer $TOKEN"

# rug-pull detection
mcp-sentinel live -c "node server.js" --save-baseline baseline.json
mcp-sentinel live -c "node server.js" --baseline baseline.json --fail-on high

# continuous monitoring
mcp-sentinel live -c "node server.js" --watch 60
```

The scan is **read-only**: it performs `initialize`, `tools/list`,
`prompts/list`, `resources/list` and never `tools/call`.

Spawned servers receive a scrubbed environment (PATH/HOME-style variables
only) unless `--inherit-env` is given. Only scan servers you trust, ideally
inside a container.

| ID | Meaning |
|----|---------|
| MCP-006 | Dangerous tool name |
| MCP-007 | Poisoning / instruction override / cross-tool steering in any tool, prompt, resource or schema text, or server instructions |
| MCP-101 | Hidden content: zero-width/bidi characters, HTML comments, base64 blobs, very long text |
| MCP-103 | Metadata references sensitive files (`~/.ssh`, `.env`, `mcp.json`, ...) |
| MCP-104 | Free-form command/code/SQL/path/URL parameter without enum or pattern |
| MCP-105 | Duplicate, lookalike or non-ASCII tool names |
| MCP-106 | Definition changed / added / removed vs baseline or previous watch run |
| MCP-108 | Plaintext HTTP to a non-local host; remote server answering without credentials |

## Limitations

* TypeScript analysis is heuristic: no type information, no cross-function
  or cross-file data flow, no dynamic `require`.
* Legacy HTTP+SSE transport is not supported (Streamable HTTP and stdio are).
* Live mode does not fuzz tools or call them.
