"""Human-readable and machine-readable diagnostic report formatting."""

from __future__ import annotations

import difflib
import html
import re

from shipsure.models import DiagnosticReport
from shipsure.security import redact_secrets

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL.sub("", redact_secrets(normalized))


def _text(value: str) -> str:
    safe = _clean(value).replace("\n", " ")
    escaped = html.escape(safe, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", escaped)


def _inline_code(value: str) -> str:
    safe = _clean(value).replace("\n", " ")
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", safe)), default=0)
    fence = "`" * (longest + 1)
    padding = " " if safe.startswith("`") or safe.endswith("`") else ""
    return f"{fence}{padding}{safe}{padding}{fence}"


def _fence(value: str) -> tuple[str, str]:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)
    marker = "`" * max(3, longest + 1)
    return marker, marker


def render_json(report: DiagnosticReport) -> str:
    return report.model_dump_json(indent=2)


def render_markdown(report: DiagnosticReport) -> str:
    lines = [
        "# ShipSure deployment diagnosis",
        "",
        f"- **Status:** {report.status.replace('_', ' ')}",
        f"- **Project:** {_inline_code(report.project.root)}",
        f"- **Frameworks:** {_text(', '.join(report.project.frameworks) or 'not detected')}",
        f"- **Platforms:** {_text(', '.join(report.project.platforms) or 'not specified')}",
        f"- **Files inspected:** {len(report.project.files_inspected)}",
        "",
        _text(report.summary),
        "",
    ]
    for index, diagnosis in enumerate(report.diagnoses, start=1):
        lines.extend(
            [
                f"## {index}. {diagnosis.title}",
                "",
                f"- **Category:** {diagnosis.category}",
                f"- **Evidence strength:** {diagnosis.confidence_label} ({diagnosis.confidence:.0%})",
                f"- **Status:** {diagnosis.status.replace('_', ' ')}",
                f"- **Root cause:** {_text(diagnosis.root_cause)}",
                "",
                "### Supporting evidence",
                "",
            ]
        )
        for evidence in diagnosis.evidence:
            lines.append(
                f"- {_inline_code(evidence.location)} ({evidence.kind}): {_inline_code(evidence.excerpt)}"
            )
        lines.extend(
            [
                "",
                "### Recommended action",
                "",
                _text(diagnosis.recommendation),
                "",
                "### Verification",
                "",
            ]
        )
        lines.extend(f"- {_text(step)}" for step in diagnosis.verification_steps)
        if diagnosis.alternatives:
            lines.extend(["", "### Other plausible causes", ""])
            lines.extend(f"- {_text(alternative)}" for alternative in diagnosis.alternatives)
        for change in diagnosis.proposed_changes:
            diff = "".join(
                difflib.unified_diff(
                    change.before.splitlines(keepends=True),
                    change.after.splitlines(keepends=True),
                    fromfile=f"a/{change.path}",
                    tofile=f"b/{change.path}",
                )
            )
            if diff:
                opening, closing = _fence(diff)
                lines.extend(
                    [
                        "",
                        "### Proposed file change (not applied)",
                        "",
                        f"{opening}diff",
                        _clean(diff),
                        closing,
                    ]
                )
        lines.append("")
    if report.provider_observations:
        lines.extend(["## Provider evidence", ""])
        for evidence in report.provider_observations:
            lines.append(
                f"- {_text(evidence.source)} — {_inline_code(evidence.location)}: {_inline_code(evidence.excerpt)}"
            )
        lines.append("")
    if report.observations:
        lines.extend(["## Inspection notes", ""])
        lines.extend(f"- {_text(item)}" for item in report.observations)
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {_text(item)}" for item in report.limitations)
    lines.append(
        "- A recommendation is not proof of a fix. ShipSure marks verification only after observing a successful check."
    )
    return "\n".join(lines).rstrip() + "\n"
