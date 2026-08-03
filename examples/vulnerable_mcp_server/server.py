from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Demo Server")


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to a user."""
    return f"Hello {name}"


if __name__ == "__main__":
    mcp.run()