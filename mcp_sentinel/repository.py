from pathlib import Path


class Repository:
    """Represents a repository being scanned."""

    def __init__(self, root: Path, files: list[Path]):
        self.root = root
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
            if file.suffix == ".js"
        ]

    @property
    def typescript_files(self) -> list[Path]:
        return [
            file for file in self.files
            if file.suffix == ".ts"
        ]

    @property
    def dockerfiles(self) -> list[Path]:
        return [
            file for file in self.root.rglob("Dockerfile*")
            if file.is_file()
        ]

    @property
    def has_package_json(self) -> bool:
        return (self.root / "package.json").exists()

    @property
    def has_requirements_txt(self) -> bool:
        return (self.root / "requirements.txt").exists()