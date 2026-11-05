"""Collect a bounded set of non-secret project files without executing them."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from shipsure.security import redact_secrets

MAX_FILES = 400
MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 3_000_000
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".turbo",
    "coverage",
    "target",
    ".terraform",
}
SECRET_NAMES = ("secret", "credential", "id_rsa", "id_ed25519", ".pem", ".p12", ".pfx")
INTERESTING_NAMES = {
    "dockerfile",
    "procfile",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "vercel.json",
    "render.yaml",
    "fly.toml",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
    "cloudformation.yaml",
    "template.yaml",
    "serverless.yml",
    "sam.yaml",
}
INTERESTING_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".txt",
    ".sh",
}


@dataclass(frozen=True)
class ProjectSnapshot:
    root: Path
    files: dict[str, str]
    omitted_files: int
    observations: tuple[str, ...]


def _is_interesting(path: Path) -> bool:
    name = path.name.lower()
    if any(marker in name for marker in SECRET_NAMES):
        return False
    if name in {".env", ".env.local", ".env.production", ".env.development"}:
        return False
    if name in {".env.example", ".env.sample", ".env.template"}:
        return True
    if name.startswith(".env.") and not name.endswith((".example", ".sample", ".template")):
        return False
    if name in INTERESTING_NAMES:
        return True
    if path.suffix.lower() not in INTERESTING_SUFFIXES:
        return False
    return path.suffix.lower() != ".txt" or name.startswith("requirements") or name in {"procfile"}


def inspect_project(root: str | Path) -> ProjectSnapshot:
    """Read deployment-relevant text files under ``root`` with hard resource caps."""
    project_root = Path(root).expanduser().resolve(strict=True)
    if not project_root.is_dir():
        raise ValueError("project root must be a directory")

    files: dict[str, str] = {}
    observations: list[str] = []
    total_bytes = 0
    omitted = 0
    for current, directories, names in os.walk(project_root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            name
            for name in directories
            if name not in SKIP_DIRS and not (current_path / name).is_symlink()
        )
        for name in sorted(names):
            path = current_path / name
            if not _is_interesting(path):
                continue
            if len(files) >= MAX_FILES or total_bytes >= MAX_TOTAL_BYTES:
                omitted += 1
                continue
            try:
                if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                    omitted += 1
                    continue
                relative = path.relative_to(project_root).as_posix()
                raw = path.read_bytes()
                if b"\x00" in raw:
                    omitted += 1
                    continue
                total_bytes += len(raw)
                content = raw.decode("utf-8", errors="replace")
                files[relative] = redact_secrets(content, max_length=MAX_FILE_BYTES)
            except (OSError, ValueError):
                omitted += 1

    if omitted:
        observations.append(f"Inspection limits or file-safety checks skipped {omitted} file(s).")
    return ProjectSnapshot(project_root, files, omitted, tuple(observations))
