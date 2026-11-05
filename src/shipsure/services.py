"""Application services shared by CLI and MCP interfaces."""

from __future__ import annotations

from pathlib import Path

from shipsure.engine import diagnose_project
from shipsure.models import DiagnosticReport, ProviderReport


def merge_provider_reports(
    root: str | Path,
    provider_reports: list[ProviderReport],
    *,
    logs: str = "",
    platform: str | None = None,
) -> DiagnosticReport:
    """Combine local evidence and provider reads into a single ranked report."""
    provider_logs = [
        observation.excerpt
        for provider_report in provider_reports
        for observation in provider_report.observations
        if observation.kind == "log"
    ]
    combined_logs = "\n".join(part for part in [logs, *provider_logs] if part)
    report = diagnose_project(root, logs=combined_logs, platform=platform)
    report.limitations = [
        item for item in report.limitations if "live provider state was not queried" not in item
    ]
    for provider_report in provider_reports:
        report.provider_observations.extend(provider_report.observations)
        report.diagnoses.extend(provider_report.diagnoses)
        report.limitations.extend(provider_report.limitations)
        provider_name = "Vercel" if provider_report.provider == "vercel" else "AWS"
        if provider_name not in report.project.platforms:
            report.project.platforms.append(provider_name)
    unique = {item.id: item for item in report.diagnoses}
    report.diagnoses = sorted(
        unique.values(), key=lambda item: (-item.confidence, item.category, item.id)
    )
    if report.diagnoses:
        report.status = "issues_found"
        report.summary = f"Found {len(report.diagnoses)} evidence-backed diagnostic finding(s) across local and provider evidence. No issue is marked resolved without verification."
    elif provider_reports:
        report.status = "no_known_issue"
        report.summary = "No known diagnostic rule matched the local and provider evidence collected. This is not proof that the deployment is healthy."
    return report
