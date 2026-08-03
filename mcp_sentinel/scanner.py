from pathlib import Path

SUPPORTED_EXTENSIONS = {
    ".py",      # Python
    ".js",      # JavaScript
    ".ts",      # TypeScript
}


def discover_files(root: Path) -> list[Path]:
    """
    Recursively discover supported source files.

    Args:
        root: Repository root.

    Returns:
        Sorted list of supported source files.
    """

    files: list[Path] = []

    for file in root.rglob("*"):
        if file.is_file() and file.suffix in SUPPORTED_EXTENSIONS:
            files.append(file)

    return sorted(files)