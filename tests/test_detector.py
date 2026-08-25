from mcp_sentinel.detector.python_detector import detect_python_mcp


def test_detect_fastmcp(example_repository):

    result = detect_python_mcp(
        example_repository.python_files
    )

    assert result.detected

    assert result.framework == "FastMCP"