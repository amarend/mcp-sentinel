from pathlib import Path

from .scanner import DEFAULT_EXCLUDED_DIRS


class Repository:
    """Represents a repository being scanned."""

    def __init__(self, root: str | Path, files: list[Path]):
        self.root = Path(root)
        self.files = files

    @property
    def python_files(self) -> list[Path]:
        return [
            file for file in self.files
            if file.suffix == ".py"
        ]

    @property
    def javascript_files(self) -> list[Path]:
        return [
            file for file in self.files
            if file.suffix in {".js", ".mjs", ".cjs"}
        ]

    @property
    def typescript_files(self) -> list[Path]:
        return [
            file for file in self.files
            if file.suffix in {".ts", ".mts", ".cts"}
        ]

    @property
    def dockerfiles(self) -> list[Path]:
        return [
            file for file in self.root.rglob("Dockerfile*")
            if file.is_file()
            and not (set(file.parts) & DEFAULT_EXCLUDED_DIRS)
        ]

    @property
    def has_package_json(self) -> bool:
        return (self.root / "package.json").exists()

    @property
    def has_requirements_txt(self) -> bool:
        return (self.root / "requirements.txt").exists()
