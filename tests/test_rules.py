from pathlib import Path

from mcp_sentinel.rules.command_execution import detect_command_execution
from mcp_sentinel.rules.hardcoded_secrets import detect_hardcoded_secrets
from mcp_sentinel.rules.file_access import detect_unsafe_file_access

from mcp_sentinel.rules import run_security_rules



def test_detects_shell_command_execution(tmp_path: Path):
    """MCP-001 should detect subprocess execution with shell=True."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        """
import subprocess

def execute_command(command):
    return subprocess.run(
        command,
        shell=True,
        capture_output=True
    )
"""
    )

    findings = detect_command_execution([server_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "MCP-001"
    assert finding.severity == "CRITICAL"
    assert finding.file == str(server_file)


def test_does_not_flag_safe_subprocess(tmp_path: Path):
    """MCP-001 should not flag subprocess execution without shell=True."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        """
import subprocess

def execute_command(command):
    return subprocess.run(
        ["echo", command],
        capture_output=True
    )
"""
    )

    findings = detect_command_execution([server_file])

    assert len(findings) == 0

def test_detects_hardcoded_password(tmp_path: Path):
    """MCP-002 should detect a hardcoded password."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        '''
PASSWORD = "my-super-secret-password"
'''
    )

    findings = detect_hardcoded_secrets([server_file])

    assert len(findings) == 1

    assert findings[0].rule_id == "MCP-002"
    assert findings[0].severity == "HIGH"

def test_does_not_flag_environment_variable(tmp_path: Path):
    """Environment-based secrets should not trigger MCP-002."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        '''
import os

API_KEY = os.getenv("API_KEY")
'''
    )

    findings = detect_hardcoded_secrets([server_file])

    assert findings == []

def test_does_not_flag_normal_variable(tmp_path: Path):
    """Normal variables should not trigger MCP-002."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        '''
API_KEY_NAME = "my-api-key"
MESSAGE = "hello"
'''
    )

    findings = detect_hardcoded_secrets([server_file])

    assert findings == []

def test_security_rule_runner_detects_secret(tmp_path: Path):
    """The security rule runner should execute MCP-002."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        '''
API_KEY = "super-secret"
'''
    )

    findings = run_security_rules([server_file])

    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-002"
    assert findings[0].severity == "HIGH"

def test_detects_unsafe_file_access(tmp_path: Path):
    """MCP-003 should detect filesystem access inside an MCP tool."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Test Server")


@mcp.tool()
def read_file(path: str) -> str:
    with open(path, "r") as f:
        return f.read()
'''
    )

    findings = detect_unsafe_file_access([server_file])

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "MCP-003"
    assert finding.title == "Unsafe File Access"
    assert finding.severity == "HIGH"
    assert finding.file == str(server_file)

def test_does_not_flag_non_mcp_file_access(tmp_path: Path):
    """MCP-003 should not flag normal internal file access."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        '''
def internal_reader():
    with open("config.json", "r") as f:
        return f.read()
'''
    )

    findings = detect_unsafe_file_access([server_file])

    assert findings == []

def test_does_not_flag_mcp_tool_without_file_access(tmp_path: Path):
    """MCP-003 should not flag tools that don't access files."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Test Server")


@mcp.tool()
def hello(name: str) -> str:
    return f"Hello {name}"
'''
    )

    findings = detect_unsafe_file_access([server_file])

    assert findings == []

def test_security_rule_runner_detects_unsafe_file_access(
    tmp_path: Path,
):
    """The security rule runner should execute MCP-003."""

    server_file = tmp_path / "server.py"

    server_file.write_text(
        '''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Test Server")


@mcp.tool()
def read_file(path: str) -> str:
    with open(path, "r") as f:
        return f.read()
'''
    )

    findings = run_security_rules([server_file])

    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-003"
    assert findings[0].severity == "HIGH"