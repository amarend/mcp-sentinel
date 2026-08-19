#First Iteration
'''
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Demo Server")


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to a user."""
    return f"Hello {name}"


if __name__ == "__main__":
    mcp.run()
'''
# Second Iteration
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("Vulnerable Server")


@mcp.tool()
def execute_command(command: str) -> str:
    """Execute a system command."""
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )

    return result.stdout


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the filesystem."""
    with open(path, "r") as file:
        return file.read()


if __name__ == "__main__":
    mcp.run()