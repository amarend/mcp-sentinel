# MCP Sentinel 

**Static security analysis for Model Context Protocol (MCP) servers.**

MCP Sentinel analyzes MCP server implementations for common security risks across command execution, filesystem access, network communication, secrets, tool poisoning, prompt injection, unsafe deserialization, and other dangerous behaviors.

The goal is to help developers and security teams identify security weaknesses in MCP servers before deployment.

> **Status:** v0.1 — Initial security rule set

---

## Why MCP Sentinel?

Model Context Protocol (MCP) enables AI applications to interact with external tools, resources, and data sources. MCP tools can perform powerful operations such as accessing files, calling APIs, executing commands, and interacting with external systems.

Because tools can perform arbitrary operations, MCP implementations require strong security controls and careful validation.

MCP's security guidance emphasizes user consent and control, data privacy, tool safety, access controls, and appropriate protection of sensitive operations.

MCP Sentinel provides a static-analysis layer that helps identify potentially dangerous patterns in MCP server source code.

---

## Features

* MCP server detection
* 15 security rules
* Python AST-based analysis
* Hardcoded secret detection
* Dangerous command execution detection
* Unsafe filesystem access detection
* Network and SSRF detection
* Tool poisoning detection
* Prompt injection detection
* Unsafe deserialization detection
* Dynamic code execution detection
* Sensitive environment exposure detection
* Excessive tool capability detection
* Input validation analysis
* Rich CLI output
* Unit and integration testing

---

# Security Rules

MCP Sentinel v0.1 contains 15 security rules.

| ID      | Rule                               | Severity |
| ------- | ---------------------------------- | -------- |
| MCP-001 | Dangerous Command Execution        | Critical |
| MCP-002 | Hardcoded Secrets                  | High     |
| MCP-003 | Unsafe File Access                 | High     |
| MCP-004 | MCP Network Access                 | High     |
| MCP-005 | Server-Side Request Forgery (SSRF) | High     |
| MCP-006 | Dangerous Tool Capability          | High     |
| MCP-007 | Tool Poisoning                     | High     |
| MCP-008 | Prompt Injection                   | High     |
| MCP-009 | Unsafe Deserialization             | Critical |
| MCP-010 | Dynamic Code Execution             | Critical |
| MCP-011 | Path Traversal                     | High     |
| MCP-012 | Unrestricted URL/Destination       | High     |
| MCP-013 | Sensitive Environment Exposure     | Critical |
| MCP-014 | Excessive Tool Capability          | High     |
| MCP-015 | Missing Input Validation           | High     |

See [Security Rules](docs/SECURITY_RULES.md) for detailed descriptions and examples.

---

# Architecture

MCP Sentinel currently follows a simple static-analysis pipeline:

```text
                MCP Server Repository
                         │
                         ▼
                ┌─────────────────┐
                │ File Discovery  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Repository      │
                │ Representation  │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ MCP Detection   │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Python AST      │
                │ Analysis        │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Security Rules  │
                │ MCP-001..015    │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Security        │
                │ Findings        │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ CLI Report      │
                └─────────────────┘
```

---

# Installation

Clone the repository:

```bash
git clone <repository-url>
cd mcp-sentinel
```

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

---

# Usage

Scan an MCP server repository:

```bash
mcp-sentinel scan /path/to/mcp-server
```

The scanner will:

1. Discover source files.
2. Analyze the repository for MCP server implementations.
3. Identify MCP tools.
4. Execute the security rule set.
5. Report detected findings.

Example:

```text
MCP Sentinel
Analyze and audit MCP servers

Scanning: ./my-mcp-server

Found 12 source files

MCP Detection
──────────────────────────────
✓ MCP Server Detected

Language     : Python
Framework    : FastMCP
Confidence   : HIGH

Security Findings
──────────────────────────────

Found 2 security issue(s)

CRITICAL MCP-001 Dangerous Command Execution
File           : server.py
Description    : ...
Recommendation : ...

HIGH MCP-003 Unsafe File Access
File           : server.py
Description    : ...
Recommendation : ...
```

Check the version:

```bash
mcp-sentinel version
```

---

# Testing

Run the complete test suite:

```bash
python -m pytest -v
```

Run only security-rule tests:

```bash
python -m pytest tests/test_rules.py -v
```

Run tests for an individual rule:

```bash
python -m pytest tests/test_rules.py -k "mcp_009" -v
```

The project uses both:

* Unit tests for individual security rules
* Integration tests for the complete security-rule runner

Integration tests verify that rules are correctly registered and executed by the scanner.

---

# Current Scope

MCP Sentinel v0.1 focuses primarily on **static analysis of Python MCP server implementations**.

The current implementation analyzes source code using Python's Abstract Syntax Tree (AST).

The scanner is intended to identify potentially dangerous patterns rather than prove that a vulnerability is exploitable.

A finding should therefore be treated as a security signal that requires review.

---

# Limitations

The v0.1 implementation intentionally favors simple and deterministic detection patterns.

It may not currently understand:

* Complex data-flow relationships
* Inter-procedural taint propagation
* Dynamic imports
* Runtime-generated code
* Highly indirect function calls
* Complex validation logic
* Custom security frameworks
* Runtime authorization policies
* Deployment-level security controls

These areas are planned for future refinement.

---

# Security Philosophy

MCP Sentinel follows a defense-in-depth approach.

Static analysis is only one layer of MCP security.

Secure MCP deployments should additionally implement:

* Authentication
* Authorization
* Least privilege
* Input validation
* Output sanitization
* User consent for sensitive actions
* Secure secret management
* Network restrictions
* Logging and monitoring
* Rate limiting

These controls complement static analysis rather than being replaced by it. MCP's own security guidance stresses that tool execution and data access require appropriate consent, access controls, and security protections.

