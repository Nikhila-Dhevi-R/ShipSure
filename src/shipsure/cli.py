"""Standalone ShipSure command-line interface."""

from __future__ import annotations

import re
import shlex
import sys
from importlib.resources import files
from pathlib import Path
from typing import Annotated, Literal

import typer

from shipsure.adapters.aws import AwsReadOnlyAdapter
from shipsure.adapters.vercel import VercelReadOnlyAdapter
from shipsure.analysis import inspect_dependencies, inspect_environment_configuration
from shipsure.engine import diagnose_project
from shipsure.models import DiagnosticReport, ProviderReport
from shipsure.repairs import (
    ApprovalRequired,
    apply_file_change,
    load_applied_change,
    preview_text_replacement,
    rollback_file_change,
    run_verification,
)
from shipsure.reporting import render_json, render_markdown
from shipsure.security import redact_secrets
from shipsure.services import merge_provider_reports

app = typer.Typer(
    name="shipsure",
    help="Evidence-backed deployment diagnosis, safe repair previews, and verified local checks.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
aws_app = typer.Typer(help="Read-only AWS diagnostics.", no_args_is_help=True)
vercel_app = typer.Typer(help="Read-only Vercel diagnostics.", no_args_is_help=True)
app.add_typer(aws_app, name="aws")
app.add_typer(vercel_app, name="vercel")

OutputFormat = Literal["markdown", "json"]


def _load_logs(log_file: Path | None) -> str:
    if log_file is None:
        return ""
    if not log_file.is_file():
        raise typer.BadParameter(f"log file does not exist: {log_file}")
    if log_file.stat().st_size > 1_000_000:
        raise typer.BadParameter("log file exceeds the 1 MB analysis limit")
    return redact_secrets(
        log_file.read_text(encoding="utf-8", errors="replace"), max_length=1_000_000
    )


def _emit_report(report: DiagnosticReport, output_format: OutputFormat) -> None:
    typer.echo(render_json(report) if output_format == "json" else render_markdown(report))


def _emit_provider(report: ProviderReport, output_format: OutputFormat) -> None:
    if output_format == "json":
        typer.echo(report.model_dump_json(indent=2))
        return
    merged = merge_provider_reports(Path.cwd(), [report], platform=report.provider.upper())
    _emit_report(merged, output_format)


def _exit_for_exception(exc: Exception) -> None:
    typer.echo(_safe_terminal_text(str(exc)), err=True)
    raise typer.Exit(code=1) from exc


def _safe_terminal_text(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", redact_secrets(normalized))


@app.command("diagnose")
def diagnose_command(
    root: Annotated[
        Path, typer.Option(help="Project directory to inspect. No project code is executed.")
    ] = Path("."),
    log_file: Annotated[
        Path | None,
        typer.Option(
            "--log-file", help="Optional deployment log file (up to 1 MB). Values are redacted."
        ),
    ] = None,
    platform: Annotated[
        str | None, typer.Option(help="Optional deployment platform label, such as vercel or aws.")
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Diagnose local project evidence and optional supplied deployment logs."""
    try:
        report = diagnose_project(root, logs=_load_logs(log_file), platform=platform)
        _emit_report(report, output_format)
    except (OSError, ValueError) as exc:
        _exit_for_exception(exc)


@app.command("dependencies")
def dependencies_command(
    root: Annotated[
        Path, typer.Option(help="Project directory to inspect without executing package tools.")
    ] = Path("."),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """List declared Python/Node dependencies and package scripts."""
    try:
        inventory = inspect_dependencies(root)
        if output_format == "json":
            typer.echo(inventory.model_dump_json(indent=2))
        else:
            typer.echo(f"# Declared dependencies in {_safe_terminal_text(inventory.root)}\n")
            manifests = _safe_terminal_text(", ".join(inventory.manifests) or "none found")
            typer.echo(f"Manifests: {manifests}\n")
            if inventory.dependencies:
                typer.echo("| Name | Version | Scope | Source |\n|---|---|---|---|")
                for dependency in inventory.dependencies:
                    typer.echo(
                        "| "
                        + " | ".join(
                            _safe_terminal_text(value)
                            for value in (
                                dependency.name,
                                dependency.version or "unspecified",
                                dependency.scope,
                                dependency.source,
                            )
                        )
                        + " |"
                    )
            else:
                typer.echo("No declared dependencies found.")
            if inventory.scripts:
                typer.echo("\n## Root package scripts\n")
                for name, command in sorted(inventory.scripts.items()):
                    typer.echo(f"- `{_safe_terminal_text(name)}`: `{_safe_terminal_text(command)}`")
            for note in inventory.limitations:
                typer.echo(f"\n- {_safe_terminal_text(note)}")
    except (OSError, ValueError) as exc:
        _exit_for_exception(exc)


@app.command("env-check")
def env_check_command(
    root: Annotated[
        Path, typer.Option(help="Project directory to inspect. Local .env files are skipped.")
    ] = Path("."),
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Compare source-referenced environment variable names with safe examples."""
    try:
        inventory = inspect_environment_configuration(root)
        if output_format == "json":
            typer.echo(inventory.model_dump_json(indent=2))
        else:
            typer.echo(f"# Environment name check in {_safe_terminal_text(inventory.root)}\n")
            typer.echo(
                "Referenced names: " + (", ".join(inventory.referenced_names) or "none found")
            )
            typer.echo(
                "Documented names: " + (", ".join(inventory.documented_names) or "none found")
            )
            typer.echo(
                "Not documented in examples: " + (", ".join(inventory.undocumented_names) or "none")
            )
            typer.echo(
                "\nThis compares names only; it does not determine whether a live environment contains them."
            )
    except (OSError, ValueError) as exc:
        _exit_for_exception(exc)


@app.command("fix-preview")
def fix_preview_command(
    path: Annotated[str, typer.Argument(help="Project-relative file path.")],
    old_text: Annotated[str, typer.Option(help="Exact text expected once in the file.")],
    new_text: Annotated[str, typer.Option(help="Replacement text to preview.")],
    root: Annotated[Path, typer.Option(help="Project directory.")] = Path("."),
) -> None:
    """Show a safe local file change without applying it."""
    try:
        change = preview_text_replacement(root, path, old_text, new_text)
        typer.echo(f"Preview only: {change.path}\n")
        typer.echo("--- current\n+++ proposed")
        typer.echo("-" + _safe_terminal_text(change.before).replace("\n", "\n-"), nl=False)
        typer.echo("+" + _safe_terminal_text(change.after).replace("\n", "\n+"), nl=False)
        typer.echo(
            "\nNo files were changed. Use `shipsure fix-apply` to review and approve this exact change."
        )
    except (OSError, ValueError) as exc:
        _exit_for_exception(exc)


@app.command("fix-apply")
def fix_apply_command(
    path: Annotated[str, typer.Argument(help="Project-relative file path.")],
    old_text: Annotated[str, typer.Option(help="Exact text expected once in the file.")],
    new_text: Annotated[str, typer.Option(help="Replacement text to apply after confirmation.")],
    root: Annotated[Path, typer.Option(help="Project directory.")] = Path("."),
    approve: Annotated[
        bool, typer.Option("--approve", help="Approve the preview without an interactive prompt.")
    ] = False,
) -> None:
    """Preview and request approval before applying a reversible local fix."""
    try:
        change = preview_text_replacement(root, path, old_text, new_text)
        typer.echo(f"ShipSure proposes changing {_safe_terminal_text(change.path)}.\n")
        typer.echo("--- current\n+++ proposed")
        typer.echo("-" + change.before.replace("\n", "\n-"), nl=False)
        typer.echo("+" + change.after.replace("\n", "\n+"), nl=False)
        if not approve and not typer.confirm(
            "Apply this exact local change? A private rollback copy will be kept."
        ):
            typer.echo("No file was changed.")
            raise typer.Exit(code=0)
        applied = apply_file_change(root, change, approved=True)
        change_id = Path(applied.backup_path).parent.name
        typer.echo(f"Applied. Rollback ID: {change_id}")
    except typer.Exit:
        raise
    except (OSError, ValueError, ApprovalRequired) as exc:
        _exit_for_exception(exc)


@app.command("apply-proposal")
def apply_proposal_command(
    root: Annotated[Path, typer.Option(help="Project directory to diagnose and repair.")] = Path(
        "."
    ),
    log_file: Annotated[
        Path | None,
        typer.Option("--log-file", help="Optional deployment log file, up to 1 MB."),
    ] = None,
    platform: Annotated[str | None, typer.Option(help="Optional platform label.")] = None,
    finding: Annotated[
        int, typer.Option(min=1, help="One-based finding number from the report.")
    ] = 1,
    approve: Annotated[
        bool, typer.Option("--approve", help="Approve the displayed proposal without a prompt.")
    ] = False,
) -> None:
    """Apply one deterministic diagnosis proposal after showing it for user approval."""
    try:
        report = diagnose_project(root, logs=_load_logs(log_file), platform=platform)
        if finding > len(report.diagnoses):
            raise ValueError(
                f"finding {finding} does not exist; ShipSure found {len(report.diagnoses)} finding(s)"
            )
        diagnosis = report.diagnoses[finding - 1]
        if len(diagnosis.proposed_changes) != 1:
            raise ValueError(
                "the selected finding has no single automated file proposal; use its recommendation and safe-fix preview"
            )
        change = diagnosis.proposed_changes[0]
        typer.echo(f"Finding {finding}: {_safe_terminal_text(diagnosis.title)}")
        typer.echo(_safe_terminal_text(diagnosis.root_cause))
        typer.echo(f"\nShipSure proposes changing {_safe_terminal_text(change.path)}:")
        typer.echo("--- current\n+++ proposed")
        for line in _safe_terminal_text(change.before).splitlines():
            typer.echo("-" + line)
        for line in _safe_terminal_text(change.after).splitlines():
            typer.echo("+" + line)
        if not approve and not typer.confirm(
            "Apply this exact diagnosis-backed change? A private rollback copy will be kept."
        ):
            typer.echo("No file was changed.")
            raise typer.Exit(code=0)
        applied = apply_file_change(root, change, approved=True)
        change_id = Path(applied.backup_path).parent.name
        typer.echo(f"Applied. Rollback ID: {change_id}")
    except typer.Exit:
        raise
    except (OSError, ValueError, ApprovalRequired) as exc:
        _exit_for_exception(exc)


@app.command("rollback")
def rollback_command(
    change_id: Annotated[str, typer.Argument(help="ID printed by fix-apply.")],
    root: Annotated[Path, typer.Option(help="Project directory.")] = Path("."),
    approve: Annotated[
        bool, typer.Option("--approve", help="Approve rollback without an interactive prompt.")
    ] = False,
) -> None:
    """Restore a ShipSure-created backup if the file has not changed since the fix."""
    try:
        applied = load_applied_change(root, change_id)
        if not approve and not typer.confirm(
            f"Restore {applied.path} from ShipSure rollback ID {change_id}?"
        ):
            typer.echo("No file was changed.")
            raise typer.Exit(code=0)
        rollback_file_change(root, applied, approved=True)
        typer.echo(f"Restored {_safe_terminal_text(applied.path)} from the ShipSure backup.")
    except typer.Exit:
        raise
    except (OSError, ValueError) as exc:
        _exit_for_exception(exc)


@app.command("verify")
def verify_command(
    command: Annotated[
        str,
        typer.Option(
            "--command",
            help="Allowlisted local check, for example `python -m pytest` or `npm run build`.",
        ),
    ],
    root: Annotated[Path, typer.Option(help="Project directory.")] = Path("."),
    timeout: Annotated[int, typer.Option(help="Maximum time in seconds (1-300).")] = 120,
    approve: Annotated[
        bool, typer.Option("--approve", help="Approve execution without an interactive prompt.")
    ] = False,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Result format.")
    ] = "markdown",
) -> None:
    """Run a selected, allowlisted local check after explicit approval."""
    try:
        argv = shlex.split(command, posix=(sys.platform != "win32"))
        if not approve and not typer.confirm(
            f"Run this local command in {root.resolve()}?\n{command}"
        ):
            typer.echo("Verification was not run.")
            raise typer.Exit(code=0)
        result = run_verification(root, argv, approved=True, timeout_seconds=timeout)
        if output_format == "json":
            typer.echo(result.model_dump_json(indent=2))
        else:
            typer.echo(f"Local verification: {'PASSED' if result.verified else 'FAILED'}")
            typer.echo(f"Command: {result.command}\nExit code: {result.exit_code}\n{result.note}")
            if result.output_excerpt:
                typer.echo(result.output_excerpt)
        if not result.verified:
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except (OSError, ValueError, ApprovalRequired) as exc:
        _exit_for_exception(exc)


@app.command("install-skill")
def install_skill_command(
    client: Annotated[
        Literal["codex", "claude", "both"],
        typer.Option(help="Install under the supported client skill directory."),
    ] = "both",
    root: Annotated[Path, typer.Option(help="Project directory receiving the skill.")] = Path("."),
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing customized ShipSure skill.")
    ] = False,
) -> None:
    """Copy the canonical ShipSure skill into Codex, Claude Code, or both project folders."""
    content = files("shipsure").joinpath("data/shipsure-skill.md").read_text(encoding="utf-8")
    project_root = root.expanduser().resolve()
    targets = []
    if client in {"codex", "both"}:
        targets.append(project_root / ".agents" / "skills" / "shipsure" / "SKILL.md")
    if client in {"claude", "both"}:
        targets.append(project_root / ".claude" / "skills" / "shipsure" / "SKILL.md")
    for target in targets:
        ancestor = target.parent
        while ancestor != project_root:
            if ancestor.is_symlink():
                raise ValueError("ShipSure refuses to install skills through symbolic-link folders")
            ancestor = ancestor.parent
        if target.is_symlink():
            raise ValueError("ShipSure refuses to replace a symbolic-link skill file")
        try:
            target.resolve(strict=False).relative_to(project_root)
        except ValueError as exc:
            raise ValueError("skill installation path must stay inside the project root") from exc
        if target.is_file():
            existing = target.read_text(encoding="utf-8")
            if existing == content:
                typer.echo(f"ShipSure skill is already current: {_safe_terminal_text(str(target))}")
                continue
            if not force and not typer.confirm(
                f"Replace the existing ShipSure skill at {_safe_terminal_text(str(target))}?"
            ):
                typer.echo(f"Kept existing skill: {_safe_terminal_text(str(target))}")
                continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        typer.echo(f"Installed ShipSure skill: {_safe_terminal_text(str(target))}")


@app.command("mcp")
def mcp_command(
    transport: Annotated[
        Literal["stdio", "streamable-http"],
        typer.Option(help="MCP transport; stdio is recommended for local clients."),
    ] = "stdio",
    port: Annotated[
        int, typer.Option(help="Loopback HTTP port when streamable-http is selected.")
    ] = 8765,
) -> None:
    """Start the read-only MCP server."""
    try:
        from shipsure.mcp_server import build_server

        server = build_server()
    except RuntimeError as exc:
        _exit_for_exception(exc)
    if transport == "stdio":
        server.run()
    else:
        server.run(transport="streamable-http", host="127.0.0.1", port=port)


@vercel_app.command("project")
def vercel_project_command(
    project_id: Annotated[str, typer.Argument(help="Vercel project ID or name.")],
    team_id: Annotated[str | None, typer.Option(help="Optional Vercel team ID.")] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Read deployment configuration metadata for a Vercel project."""
    try:
        with VercelReadOnlyAdapter() as adapter:
            provider_report = adapter.inspect_project(project_id, team_id=team_id)
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@vercel_app.command("env")
def vercel_env_command(
    project_id: Annotated[str, typer.Argument(help="Vercel project ID or name.")],
    team_id: Annotated[str | None, typer.Option(help="Optional Vercel team ID.")] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """List environment-variable names, types, and targets; values are never output."""
    try:
        with VercelReadOnlyAdapter() as adapter:
            provider_report = adapter.inspect_environment(project_id, team_id=team_id)
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@vercel_app.command("deployment")
def vercel_deployment_command(
    deployment_id: Annotated[str, typer.Argument(help="Vercel deployment ID or URL.")],
    root: Annotated[
        Path, typer.Option(help="Local project directory to correlate with provider evidence.")
    ] = Path("."),
    project_id: Annotated[
        str | None, typer.Option(help="Optional project ID for environment metadata.")
    ] = None,
    team_id: Annotated[str | None, typer.Option(help="Optional Vercel team ID.")] = None,
    limit: Annotated[int, typer.Option(help="Maximum event lines to inspect (1-200).")] = 100,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Inspect one deployment and correlate its events with local project files."""
    try:
        with VercelReadOnlyAdapter() as adapter:
            provider_report = adapter.inspect_deployment(
                deployment_id, project_id=project_id, team_id=team_id, limit=limit
            )
        report = merge_provider_reports(root, [provider_report], platform="Vercel")
        _emit_report(report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@vercel_app.command("deployments")
def vercel_deployments_command(
    project_id: Annotated[str, typer.Argument(help="Vercel project ID.")],
    team_id: Annotated[str | None, typer.Option(help="Optional Vercel team ID.")] = None,
    limit: Annotated[int, typer.Option(help="Maximum deployments to list (1-100).")] = 20,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """List recent deployment state and target metadata."""
    try:
        with VercelReadOnlyAdapter() as adapter:
            provider_report = adapter.list_deployments(project_id, team_id=team_id, limit=limit)
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@vercel_app.command("runtime-logs")
def vercel_runtime_logs_command(
    deployment_id: Annotated[str, typer.Argument(help="Vercel deployment ID or URL.")],
    root: Annotated[Path, typer.Option(help="Local project directory for correlation.")] = Path(
        "."
    ),
    project_id: Annotated[str | None, typer.Option(help="Optional project ID/name.")] = None,
    since: Annotated[
        str, typer.Option(help="Log time range, such as 1h, or an ISO timestamp.")
    ] = "1h",
    limit: Annotated[int, typer.Option(help="Maximum entries to read (1-1000).")] = 100,
    query: Annotated[str | None, typer.Option(help="Optional full-text log search.")] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Read runtime logs through an already-installed and authenticated Vercel CLI."""
    try:
        with VercelReadOnlyAdapter() as adapter:
            provider_report = adapter.inspect_runtime_logs(
                deployment_id,
                project_id=project_id,
                root=root,
                since=since,
                limit=limit,
                query=query,
            )
        report = merge_provider_reports(root, [provider_report], platform="Vercel")
        _emit_report(report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@aws_app.command("ec2")
def aws_ec2_command(
    instance_id: Annotated[
        list[str], typer.Option("--instance-id", help="EC2 ID; repeat up to 50 times.")
    ],
    region: Annotated[
        str | None, typer.Option(help="AWS region; defaults to the configured profile region.")
    ] = None,
    profile: Annotated[str | None, typer.Option(help="Optional AWS profile name.")] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Read EC2 instance and status checks for explicitly named instances."""
    try:
        provider_report = AwsReadOnlyAdapter(region_name=region, profile_name=profile).inspect_ec2(
            instance_id
        )
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@aws_app.command("ecs")
def aws_ecs_command(
    cluster: Annotated[str, typer.Option(help="ECS cluster name or ARN.")],
    service: Annotated[list[str], typer.Option(help="Service name; repeat up to 10 times.")],
    region: Annotated[str | None, typer.Option(help="AWS region.")] = None,
    profile: Annotated[str | None, typer.Option(help="Optional AWS profile name.")] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Read ECS service deployments, events, and running task counts."""
    try:
        provider_report = AwsReadOnlyAdapter(region_name=region, profile_name=profile).inspect_ecs(
            cluster, service
        )
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@aws_app.command("lambda")
def aws_lambda_command(
    function_name: Annotated[
        str, typer.Argument(help="Lambda function name, ARN, or partial ARN.")
    ],
    region: Annotated[str | None, typer.Option(help="AWS region.")] = None,
    profile: Annotated[str | None, typer.Option(help="Optional AWS profile name.")] = None,
    lookback_minutes: Annotated[
        int, typer.Option(help="CloudWatch log lookback window (1-1440 minutes).")
    ] = 60,
    log_limit: Annotated[
        int, typer.Option(help="Maximum CloudWatch events to read (1-500).")
    ] = 100,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Read Lambda configuration and recent, unmasked CloudWatch logs."""
    try:
        provider_report = AwsReadOnlyAdapter(
            region_name=region, profile_name=profile
        ).inspect_lambda(function_name, lookback_minutes=lookback_minutes, log_limit=log_limit)
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@aws_app.command("iam-role")
def aws_iam_role_command(
    role_name: Annotated[str, typer.Argument(help="IAM role name to inspect.")],
    region: Annotated[
        str | None, typer.Option(help="AWS region for SDK client configuration.")
    ] = None,
    profile: Annotated[str | None, typer.Option(help="Optional AWS profile name.")] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Inspect one IAM role's trust and attached policy documents for broad allows."""
    try:
        provider_report = AwsReadOnlyAdapter(
            region_name=region, profile_name=profile
        ).inspect_iam_role(role_name)
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@aws_app.command("cloudformation")
def aws_cloudformation_command(
    stack_name: Annotated[str, typer.Argument(help="CloudFormation stack name or ID.")],
    region: Annotated[str | None, typer.Option(help="AWS region.")] = None,
    profile: Annotated[str | None, typer.Option(help="Optional AWS profile name.")] = None,
    event_limit: Annotated[
        int, typer.Option(help="Maximum recent stack events to read (1-500).")
    ] = 100,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Read CloudFormation stack status and recent resource events."""
    try:
        provider_report = AwsReadOnlyAdapter(
            region_name=region, profile_name=profile
        ).inspect_cloudformation_stack(stack_name, event_limit=event_limit)
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


@aws_app.command("cloudwatch-logs")
def aws_cloudwatch_logs_command(
    log_group: Annotated[str, typer.Argument(help="Exact CloudWatch log group name.")],
    region: Annotated[str | None, typer.Option(help="AWS region.")] = None,
    profile: Annotated[str | None, typer.Option(help="Optional AWS profile name.")] = None,
    lookback_minutes: Annotated[
        int, typer.Option(help="Log lookback window (1-1440 minutes).")
    ] = 60,
    log_limit: Annotated[int, typer.Option(help="Maximum events to read (1-500).")] = 100,
    filter_pattern: Annotated[
        str | None, typer.Option(help="Optional CloudWatch filter pattern.")
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Report format.")
    ] = "markdown",
) -> None:
    """Read a named CloudWatch log group without unmasking sensitive fields."""
    try:
        provider_report = AwsReadOnlyAdapter(
            region_name=region, profile_name=profile
        ).inspect_cloudwatch_logs(
            log_group,
            lookback_minutes=lookback_minutes,
            log_limit=log_limit,
            filter_pattern=filter_pattern,
        )
        _emit_provider(provider_report, output_format)
    except (OSError, ValueError, RuntimeError) as exc:
        _exit_for_exception(exc)


def main() -> None:
    app()
