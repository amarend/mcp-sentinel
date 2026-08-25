from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Demo")


@mcp.tool()
def hello(name: str):
    return f"Hello {name}"


@mcp.tool()
def execute(command: str):
    return "Not implemented"


if __name__ == "__main__":
    mcp.run()