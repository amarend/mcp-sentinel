from pathlib import Path


SUPPORTED_EXTENSIONS = {".py", ".js", ".ts"}


def discover_files(root: str) -> list[Path]:
    """Discover supported source files in a repository."""

    root = Path(root)

    if not root.exists():
        raise ValueError(f"Path does not exist: {root}")

    if not root.is_dir():
        raise ValueError(f"Path is not a directory: {root}")

    files: list[Path] = []

    for file in root.rglob("*"):
        if file.is_file() and file.suffix in SUPPORTED_EXTENSIONS:
            files.append(file)
    return files