"""Validated domain types shared by the CLI, MCP server, and Agent Skill."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(StrictModel):
    source: str
    location: str
    excerpt: str
    kind: Literal["log", "configuration", "source", "provider", "command"]


class FileChange(StrictModel):
    path: str
    before: str
    after: str


class Diagnosis(StrictModel):
    id: str
    category: str
    title: str
    root_cause: str
    confidence: float = Field(ge=0, le=1)
    confidence_label: Literal["low", "moderate", "high"]
    status: Literal[
        "suspected",
        "supported",
        "fix_proposed",
        "fix_applied",
        "locally_verified",
        "deployment_verified",
    ] = "supported"
    evidence: list[Evidence] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    recommendation: str
    verification_steps: list[str] = Field(default_factory=list)
    proposed_changes: list[FileChange] = Field(default_factory=list)


class ProjectSummary(StrictModel):
    root: str
    frameworks: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    files_inspected: list[str] = Field(default_factory=list)


class DiagnosticReport(StrictModel):
    project: ProjectSummary
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: Literal["issues_found", "no_known_issue", "inconclusive"]
    summary: str
    diagnoses: list[Diagnosis] = Field(default_factory=list)
    provider_observations: list[Evidence] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class VerificationResult(StrictModel):
    command: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime
    exit_code: int | None
    timed_out: bool = False
    output_excerpt: str = ""
    verified: bool
    scope: Literal["local", "deployment"]
    note: str


class ProviderReport(StrictModel):
    provider: Literal["vercel", "aws"]
    target: str
    observations: list[Evidence] = Field(default_factory=list)
    diagnoses: list[Diagnosis] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class DependencyEntry(StrictModel):
    name: str
    version: str | None = None
    scope: Literal["runtime", "development", "optional", "unknown"]
    source: str


class DependencyInventory(StrictModel):
    root: str
    dependencies: list[DependencyEntry] = Field(default_factory=list)
    scripts: dict[str, str] = Field(default_factory=dict)
    manifests: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class EnvironmentInventory(StrictModel):
    root: str
    referenced_names: list[str] = Field(default_factory=list)
    documented_names: list[str] = Field(default_factory=list)
    undocumented_names: list[str] = Field(default_factory=list)
    files_inspected: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
