"""Safe, non-executing dependency and environment-name inventories."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from shipsure.inspectors.local import inspect_project
from shipsure.models import (
    DependencyEntry,
    DependencyInventory,
    EnvironmentInventory,
    Evidence,
)
from shipsure.security import redact_secrets

_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$")
_ENV_REFERENCE = re.compile(
    r"(?:os\.(?:getenv|environ\.get)\s*\(\s*|os\.environ\s*\[\s*|process\.env\s*\.\s*|process\.env\s*\[\s*|import\.meta\.env\s*\.\s*)['\"]?([A-Za-z_][A-Za-z0-9_]*)"
)
_ENV_EXAMPLE = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=")


def _add_dependency(
    entries: dict[tuple[str, str, str], DependencyEntry],
    name: str,
    version: str | None,
    scope: str,
    source: str,
) -> None:
    clean_name = name.strip()
    if not clean_name or clean_name.lower() in {"python", "node", "nodejs"}:
        return
    key = (clean_name.lower(), scope, source)
    entries[key] = DependencyEntry(
        name=clean_name,
        version=redact_secrets(version or "").strip() or None,
        scope=scope,  # type: ignore[arg-type]
        source=source,
    )


def inspect_dependencies(root: str | Path) -> DependencyInventory:
    """Read declared dependencies and package scripts without invoking package tools."""
    snapshot = inspect_project(root)
    entries: dict[tuple[str, str, str], DependencyEntry] = {}
    scripts: dict[str, str] = {}
    manifests = []
    for path, content in snapshot.files.items():
        name = Path(path).name.lower()
        if name == "package.json":
            manifests.append(path)
            try:
                package = json.loads(content)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(package, dict):
                continue
            for scope_key, scope in (
                ("dependencies", "runtime"),
                ("devDependencies", "development"),
                ("optionalDependencies", "optional"),
            ):
                mapping = package.get(scope_key, {})
                if isinstance(mapping, dict):
                    for dependency, version in mapping.items():
                        _add_dependency(entries, str(dependency), str(version), scope, path)
            if path == "package.json":
                raw_scripts = package.get("scripts", {})
                if isinstance(raw_scripts, dict):
                    scripts = {
                        str(key): redact_secrets(str(value))
                        for key, value in raw_scripts.items()
                        if isinstance(value, str)
                    }
        elif name.startswith("requirements") and name.endswith(".txt"):
            manifests.append(path)
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "-", "git+", "http:", "https:")):
                    continue
                match = _REQUIREMENT.match(stripped)
                if match:
                    _add_dependency(
                        entries, match.group(1), match.group(2) or None, "runtime", path
                    )
        elif name == "pyproject.toml":
            manifests.append(path)
            try:
                pyproject = tomllib.loads(content)
            except tomllib.TOMLDecodeError:
                continue
            project = pyproject.get("project", {})
            for dependency in project.get("dependencies", []) if isinstance(project, dict) else []:
                if isinstance(dependency, str):
                    match = _REQUIREMENT.match(dependency)
                    if match:
                        _add_dependency(
                            entries, match.group(1), match.group(2) or None, "runtime", path
                        )
            optional = project.get("optional-dependencies", {}) if isinstance(project, dict) else {}
            if isinstance(optional, dict):
                for group, group_deps in optional.items():
                    scope = (
                        "development"
                        if group.lower() in {"dev", "test", "development"}
                        else "optional"
                    )
                    for dependency in group_deps if isinstance(group_deps, list) else []:
                        if isinstance(dependency, str):
                            match = _REQUIREMENT.match(dependency)
                            if match:
                                _add_dependency(
                                    entries, match.group(1), match.group(2) or None, scope, path
                                )
            tool = pyproject.get("tool", {})
            tool = tool if isinstance(tool, dict) else {}
            poetry = tool.get("poetry", {})
            poetry = poetry if isinstance(poetry, dict) else {}
            poetry = poetry.get("dependencies", {})
            if isinstance(poetry, dict):
                for dependency, version in poetry.items():
                    if dependency.lower() != "python":
                        _add_dependency(entries, dependency, str(version), "runtime", path)
    return DependencyInventory(
        root=str(snapshot.root),
        dependencies=sorted(
            entries.values(), key=lambda item: (item.scope, item.name.lower(), item.source)
        ),
        scripts=scripts,
        manifests=sorted(set(manifests)),
        limitations=[
            "Only declared manifest entries were inspected; packages installed in an environment or lockfile resolution were not queried."
        ],
    )


def inspect_environment_configuration(root: str | Path) -> EnvironmentInventory:
    """Compare source-referenced environment variable names with safe example files."""
    snapshot = inspect_project(root)
    references: dict[str, list[tuple[str, int]]] = {}
    documented: set[str] = set()
    example_files = []
    for path, content in snapshot.files.items():
        base = Path(path).name.lower()
        if base in {".env.example", ".env.sample", ".env.template"}:
            example_files.append(path)
            for line in content.splitlines():
                match = _ENV_EXAMPLE.match(line)
                if match:
                    documented.add(match.group(1))
        elif Path(path).suffix.lower() in {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
            for line_number, line in enumerate(content.splitlines(), start=1):
                for match in _ENV_REFERENCE.finditer(line):
                    references.setdefault(match.group(1), []).append((path, line_number))
    referenced_names = sorted(references)
    undocumented = sorted(set(referenced_names) - documented)
    evidence = []
    for variable in undocumented:
        path, line_number = references[variable][0]
        evidence.append(
            Evidence(
                source="project source",
                location=f"{path}:{line_number}",
                excerpt=f"Application code reads environment variable {variable}; no matching name was found in the inspected example files.",
                kind="source",
            )
        )
    return EnvironmentInventory(
        root=str(snapshot.root),
        referenced_names=referenced_names,
        documented_names=sorted(documented),
        undocumented_names=undocumented,
        files_inspected=sorted(snapshot.files),
        evidence=evidence,
        limitations=[
            "Only variable names were compared. ShipSure never reads local .env files or provider values, and this does not prove a variable is missing in a live environment."
        ],
    )
