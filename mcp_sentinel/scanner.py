import os
from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js", ".mjs", ".cjs",
    ".ts", ".mts", ".cts",
}


# Directories that never contain first-party server code.
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "site-packages",
    "__pycache__",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
}

# Test directories are skipped by default because they intentionally
# contain vulnerable-looking fixtures. Use include_tests=True to scan them.
TEST_DIRS = {
    "tests",
    "test",
    "__tests__",
}


def _is_excluded_dir(
    name: str,
    extra: set[str],
    include_tests: bool,
) -> bool:

    if name in DEFAULT_EXCLUDED_DIRS or name in extra:
        return True

    if name.endswith(".egg-info"):
        return True

    if not include_tests and name in TEST_DIRS:
        return True

    return False


def discover_files(
    root: str | Path,
    exclude: list[str] | None = None,
    include_tests: bool = False,
) -> list[Path]:
    """
    Discover supported source files in a repository.

    Skips dependency, build, VCS and (by default) test directories.
    ``exclude`` adds extra directory names to skip.
    """

    root = Path(root)

    if not root.exists():
        raise ValueError(f"Path does not exist: {root}")

    if not root.is_dir():
        raise ValueError(f"Path is not a directory: {root}")

    extra = set(exclude or [])

    files: list[Path] = []

    for current, dirs, filenames in os.walk(root):

        # Prune in place so os.walk never descends into excluded dirs.
        dirs[:] = sorted(
            d
            for d in dirs
            if not _is_excluded_dir(d, extra, include_tests)
        )

        for filename in sorted(filenames):

            path = Path(current) / filename

            if (
                path.suffix in SUPPORTED_EXTENSIONS
                and not filename.endswith((".d.ts", ".min.js"))
                and ".test." not in filename
                and ".spec." not in filename
            ):
                files.append(path)

    return files
