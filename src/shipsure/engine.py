"""Deterministic deployment diagnosis from local files and supplied log evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal

from shipsure.inspectors.local import ProjectSnapshot, inspect_project
from shipsure.models import Diagnosis, DiagnosticReport, Evidence, FileChange, ProjectSummary
from shipsure.security import redact_secrets

_PYTHON_MISSING = re.compile(
    r"(?:ModuleNotFoundError|ImportError):\s*(?:No module named\s+)?['\"]?([\w.]+)"
)
_PYTHON_IMPORT_TARGET = re.compile(r"Could not import module ['\"]([^'\"]+)['\"]")
_UVICORN_TARGET = re.compile(
    r"(?:uvicorn|gunicorn)(?:\s+-k\s+uvicorn\.workers\.UvicornWorker)?\s+([\w.]+(?::\w+)?)"
)
MAX_LOG_TEXT = 1_000_000


def _frameworks(files: dict[str, str]) -> list[str]:
    found: set[str] = set()
    for name, content in files.items():
        lower = content.lower()
        base = Path(name).name.lower()
        if "fastapi" in lower or base.startswith("requirements") and "fastapi" in lower:
            found.add("FastAPI")
        if base == "package.json":
            try:
                package = json.loads(content)
            except json.JSONDecodeError:
                continue
            if not isinstance(package, dict):
                continue
            dependencies = package.get("dependencies", {})
            dev_dependencies = package.get("devDependencies", {})
            scripts = package.get("scripts", {})
            dependencies = dependencies if isinstance(dependencies, dict) else {}
            dev_dependencies = dev_dependencies if isinstance(dev_dependencies, dict) else {}
            dependencies = {**dependencies, **dev_dependencies}
            if "react" in dependencies:
                found.add("React")
            if "vite" in dependencies or "vite" in str(scripts):
                found.add("Vite")
        if base == "dockerfile" or base in {
            "compose.yml",
            "compose.yaml",
            "docker-compose.yml",
            "docker-compose.yaml",
        }:
            found.add("Docker")
        if name.startswith(".github/workflows/"):
            found.add("GitHub Actions")
        if base == "vercel.json" or ".vercel/" in name:
            found.add("Vercel")
        if any(term in lower for term in ("aws::", "aws_lambda_function", "ecs:", "ec2:")):
            found.add("AWS")
    return sorted(found)


def _evidence(
    source: str,
    location: str,
    excerpt: str,
    kind: Literal["log", "configuration", "source", "provider", "command"],
) -> Evidence:
    return Evidence(
        source=source, location=location, excerpt=redact_secrets(excerpt.strip()), kind=kind
    )


def _diag(
    category: str,
    title: str,
    root_cause: str,
    confidence: float,
    evidence: list[Evidence],
    recommendation: str,
    verification_steps: list[str],
    alternatives: list[str] | None = None,
) -> Diagnosis:
    label: Literal["low", "moderate", "high"] = (
        "high" if confidence >= 0.85 else "moderate" if confidence >= 0.65 else "low"
    )
    basis = "|".join([category, title, *(e.location + e.excerpt for e in evidence)])
    identifier = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
    return Diagnosis(
        id=identifier,
        category=category,
        title=title,
        root_cause=root_cause,
        confidence=confidence,
        confidence_label=label,
        status="supported" if confidence >= 0.65 else "suspected",
        evidence=evidence,
        alternatives=alternatives or [],
        recommendation=recommendation,
        verification_steps=verification_steps,
    )


def _file_evidence(
    files: dict[str, str],
    match: str,
    kind: Literal["log", "configuration", "source", "provider", "command"] = "configuration",
) -> list[Evidence]:
    results = []
    for name, content in files.items():
        for line_number, line in enumerate(content.splitlines(), start=1):
            if match.lower() in line.lower():
                results.append(_evidence("project", f"{name}:{line_number}", line, kind))
                if len(results) >= 3:
                    return results
    return results


def _log_evidence(logs: str) -> list[tuple[int, str]]:
    rows = []
    for number, raw_line in enumerate(logs[:MAX_LOG_TEXT].splitlines(), start=1):
        line = redact_secrets(raw_line.strip(), max_length=1000)
        if line:
            rows.append((number, line))
    return rows[-200:]


def _startup_change(snapshot: ProjectSnapshot) -> list[FileChange]:
    """Offer a narrow Procfile edit only when the untouched source is safe to disclose."""
    for name in ("Procfile", "Dockerfile", "render.yaml", "fly.toml"):
        text = snapshot.files.get(name)
        if not text or "main:app" not in text or "app.main:app" in text:
            continue
        try:
            actual = (snapshot.root / name).read_bytes().decode("utf-8")
        except (OSError, UnicodeError):
            continue
        if actual != text:
            continue
        updated, count = re.subn(r"(?<![\w.])main:app(?![\w.])", "app.main:app", actual, count=1)
        if count:
            return [FileChange(path=name, before=actual, after=updated)]
    return []


def _diagnose_python(snapshot: ProjectSnapshot, log_rows: list[tuple[int, str]]) -> list[Diagnosis]:
    files = snapshot.files
    diagnoses: list[Diagnosis] = []
    file_names = set(files)
    logs = "\n".join(line for _, line in log_rows)

    missing = _PYTHON_MISSING.search(logs)
    if missing:
        module = missing.group(1)
        top_module = module.split(".")[0]
        known_distributions = {
            "yaml": "PyYAML",
            "cv2": "opencv-python",
            "PIL": "Pillow",
            "dotenv": "python-dotenv",
        }
        distribution = known_distributions.get(top_module, top_module)
        dependency_files = [
            name
            for name in file_names
            if name == "requirements.txt"
            or name.endswith("requirements.txt")
            or name == "pyproject.toml"
        ]
        declares = any(
            re.search(rf"(?im)^\s*{re.escape(distribution)}(?:[<=>~!;\[]|\s|$)", files[name])
            for name in dependency_files
        )
        line_number, line = next(
            (item for item in log_rows if module in item[1]), (1, missing.group(0))
        )
        evidence = [_evidence("deployment log", f"log:{line_number}", line, "log")]
        if declares:
            evidence.extend(_file_evidence(files, distribution))
            cause = f"The deployed environment could not import {module}; although {distribution} appears in a project dependency manifest, dependency installation may be skipped, stale, or using another environment."
            recommendation = "Rebuild from the committed dependency manifest and confirm the deployment uses the intended Python environment; do not add a duplicate dependency until the install step is checked."
            confidence = 0.78
        else:
            cause = f"The runtime import for {module} failed and the dependency manifests inspected do not declare {distribution}."
            recommendation = f"Declare {distribution} in the dependency manifest used by the deployment, then rebuild. Confirm it is a runtime dependency if imported by the deployed application."
            confidence = 0.93
        diagnoses.append(
            _diag(
                "dependency",
                f"Python module {module} is unavailable at runtime",
                cause,
                confidence,
                evidence,
                recommendation,
                [
                    "Install from the committed manifest in a clean environment.",
                    "Run the application startup command with the same interpreter used by deployment.",
                    "Inspect the next deployment logs for the original import error.",
                ],
            )
        )

    target_match = _PYTHON_IMPORT_TARGET.search(logs)
    target_from_command = None
    command_evidence: list[Evidence] = []
    for name, content in files.items():
        if Path(name).name.lower() in {"procfile", "dockerfile", "render.yaml", "fly.toml"}:
            match = _UVICORN_TARGET.search(content)
            if match:
                target_from_command = match.group(1).split(":")[0]
                command_evidence.append(
                    _evidence("project", f"{name}:startup", match.group(0), "configuration")
                )
                break
    target = target_match.group(1) if target_match else target_from_command
    if target:
        module_path = target.replace(".", "/")
        module_exists = any(
            name in file_names for name in (f"{module_path}.py", f"{module_path}/__init__.py")
        )
        if target_match or (target_from_command and not module_exists):
            ev = []
            if target_match:
                line_number, line = next(
                    (item for item in log_rows if target in item[1]), (1, target_match.group(0))
                )
                ev.append(_evidence("deployment log", f"log:{line_number}", line, "log"))
            ev.extend(command_evidence)
            present = sorted(
                name
                for name in file_names
                if name.endswith(".py")
                and (Path(name).stem == "main" or Path(name).name == "__init__.py")
            )[:8]
            for module_file in present:
                ev.append(
                    _evidence(
                        "project layout",
                        module_file,
                        "Python module exists at this project-relative path.",
                        "source",
                    )
                )
            suggestion = None
            if target == "main" and "app/main.py" in file_names:
                suggestion = "app.main:app"
            if suggestion:
                proposed = f"Replace the startup module target `{target}:app` with `{suggestion}` in the deployment start command."
                confidence = 0.95 if target_match else 0.89
            else:
                proposed = f"Make the startup target `{target}` match the module path present in the repository, or correct the deployment working directory."
                confidence = 0.82 if target_match else 0.7
            diagnosis = _diag(
                "startup",
                "Python deployment startup target does not match the module layout",
                f"The deployment startup command targets `{target}`, but that import path is not present at the project root inspected. Available Python module files include: {', '.join(present) or 'none found'}.",
                confidence,
                ev,
                proposed,
                [
                    "Confirm the service working directory is the repository root.",
                    "Run the corrected Uvicorn import target from that directory.",
                    "Check the deployment logs for an application startup success message.",
                ],
                ["A different deployment root or build output may provide the target module."],
            )
            if suggestion:
                diagnosis.proposed_changes = _startup_change(snapshot)
                if diagnosis.proposed_changes:
                    diagnosis.status = "fix_proposed"
            diagnoses.append(diagnosis)

    return diagnoses


def _diagnose_node(snapshot: ProjectSnapshot, log_rows: list[tuple[int, str]]) -> list[Diagnosis]:
    files = snapshot.files
    package_text = files.get("package.json")
    if not package_text:
        return []
    try:
        package = json.loads(package_text)
    except json.JSONDecodeError:
        return []
    if not isinstance(package, dict):
        return []
    logs = "\n".join(line for _, line in log_rows)
    diagnoses = []
    vite_missing = re.search(
        r"(?:sh:|/bin/sh:)?\s* vite: (?:not found|command not found)|(?:vite: command not found)",
        logs,
        re.IGNORECASE,
    )
    vite_missing = vite_missing or re.search(
        r"\b(?:vite|react-scripts): command not found\b", logs, re.IGNORECASE
    )
    if vite_missing:
        line_number, line = next(
            (item for item in log_rows if "vite" in item[1].lower()), (1, "vite: command not found")
        )
        evidence = [
            _evidence("deployment log", f"log:{line_number}", line, "log"),
            _evidence(
                "project",
                "package.json:scripts",
                json.dumps(package.get("scripts", {}), sort_keys=True),
                "configuration",
            ),
        ]
        dev_dependencies = package.get("devDependencies", {})
        dependencies = package.get("dependencies", {})
        dev_dependencies = dev_dependencies if isinstance(dev_dependencies, dict) else {}
        dependencies = dependencies if isinstance(dependencies, dict) else {}
        if "vite" in dev_dependencies:
            evidence.append(
                _evidence(
                    "project",
                    "package.json:devDependencies.vite",
                    str(dev_dependencies["vite"]),
                    "configuration",
                )
            )
            cause = "The build process could not find Vite even though package.json declares it as a development dependency; dependency installation likely omitted development packages before the build step."
            recommendation = "Ensure the build stage installs development dependencies (for npm, avoid production-only install before `npm run build`); keep build tools in devDependencies and ship only the generated output."
            confidence = 0.94
        elif "vite" in dependencies:
            cause = "Vite is declared but unavailable in the build environment, indicating an install/workspace or package-manager mismatch."
            recommendation = "Run the package manager's clean install from the directory containing package.json, then confirm the build command uses that workspace."
            confidence = 0.78
        else:
            cause = "The build log cannot find Vite and package.json does not declare it."
            recommendation = "Add the project's intended build tool to package.json and commit the lockfile, then run the documented build command locally."
            confidence = 0.9
        diagnoses.append(
            _diag(
                "build",
                "Frontend build tool is unavailable",
                cause,
                confidence,
                evidence,
                recommendation,
                [
                    "Install dependencies from the lockfile in a clean build environment.",
                    "Run the configured build script.",
                    "Inspect the deployment build output for a successful artifact generation.",
                ],
            )
        )
    return diagnoses


def _diagnose_common(snapshot: ProjectSnapshot, log_rows: list[tuple[int, str]]) -> list[Diagnosis]:
    files = snapshot.files
    diagnoses = []
    signatures: list[tuple[re.Pattern[str], str, str, str, float, list[str]]] = [
        (
            re.compile(r"EADDRINUSE|address already in use", re.I),
            "runtime",
            "Application port is already occupied",
            "A process attempted to bind a network port that is already in use.",
            0.88,
            [
                "Confirm only one server process is started.",
                "Bind to the deployment-provided port and inspect startup logs.",
            ],
        ),
        (
            re.compile(r"health.?check.{0,40}(?:failed|unhealthy)|unhealthy container", re.I),
            "health_check",
            "Deployment health check is failing",
            "The platform did not observe the configured health check becoming healthy.",
            0.72,
            [
                "Compare the health check path and port with the app's actual bind address.",
                "Check application startup and health endpoint logs.",
            ],
        ),
        (
            re.compile(r"bind: address already in use|port is already allocated", re.I),
            "container",
            "Container port binding failed",
            "The host port requested for the container is already occupied.",
            0.92,
            [
                "Choose a free host port or remove the duplicate local container.",
                "Retry the container startup and inspect its health status.",
            ],
        ),
        (
            re.compile(r"exec format error", re.I),
            "container",
            "Container image architecture does not match the runtime",
            "The image executable format is incompatible with the deployment host architecture or its entrypoint file format.",
            0.82,
            [
                "Check the image and host architecture and rebuild for the target platform.",
                "Inspect the configured entrypoint's file format and line endings.",
            ],
        ),
        (
            re.compile(
                r"(?:permission denied.*(?:entrypoint|\.sh)|(?:entrypoint|\.sh).*permission denied)",
                re.I,
            ),
            "container",
            "Container entrypoint cannot be executed",
            "The configured entrypoint is not executable or has an incompatible format.",
            0.78,
            [
                "Check the Dockerfile entrypoint path and executable permission.",
                "Build the image and run its entrypoint in a clean container.",
            ],
        ),
        (
            re.compile(r"npm ERR! missing script: build|missing script: build", re.I),
            "build",
            "Build script is missing",
            "The deployment runs a build script that package.json does not define.",
            0.9,
            [
                "Compare the configured build command with package.json scripts.",
                "Run the selected build command locally.",
            ],
        ),
        (
            re.compile(r"Could not resolve|Module not found: Error: Can't resolve", re.I),
            "build",
            "Build cannot resolve an imported module",
            "A source import refers to a module or path the build environment cannot resolve.",
            0.74,
            [
                "Check the import spelling and casing against the tracked file path.",
                "Install the referenced package or correct the source path, then rebuild.",
            ],
        ),
        (
            re.compile(
                r"Environment Variable .* (?:not found|is missing)|Missing required environment variable",
                re.I,
            ),
            "configuration",
            "Required environment variable is missing",
            "The application or deployment build reports a required environment variable as absent.",
            0.9,
            [
                "Compare the variable name with the project's environment example and provider metadata.",
                "Set the value in the deployment provider's secure settings and create a new deployment; never put secret values in source control.",
            ],
        ),
        (
            re.compile(
                r"AccessDenied|AccessDeniedException|not authorized to perform|not authorized to access",
                re.I,
            ),
            "permissions",
            "Cloud permission denied",
            "The identity or service role used by the deployment lacks permission for the reported operation.",
            0.84,
            [
                "Identify the principal and exact denied action from the service event.",
                "Grant only the specific missing action on the narrow resource scope, then retry the read/deployment operation.",
            ],
        ),
        (
            re.compile(
                r"Task failed to start|Essential container in task exited|CannotPullContainerError",
                re.I,
            ),
            "container",
            "ECS task failed to start",
            "The ECS task did not reach a running state; image pull, startup, or an essential container exit is indicated.",
            0.84,
            [
                "Inspect ECS stopped reason and the essential container's exit code and logs.",
                "Check the image reference, execution-role pull permissions, and container startup command.",
            ],
        ),
        (
            re.compile(r"Task timed out after|Task timed out", re.I),
            "runtime",
            "Serverless function exceeded its timeout",
            "The function invocation ran longer than its configured timeout.",
            0.83,
            [
                "Compare duration and timeout from the same invocation.",
                "Check for blocked I/O, unbounded work, or cold-start initialization before increasing the timeout.",
            ],
        ),
        (
            re.compile(
                r"OutOfMemory|JavaScript heap out of memory|Killed process .* out of memory", re.I
            ),
            "resources",
            "Process exceeded available memory",
            "The runtime or build process was terminated after exhausting its memory limit.",
            0.9,
            [
                "Check memory use and build/runtime limits for the failing process.",
                "Reduce peak memory or use a supported larger resource size after confirming the limit.",
            ],
        ),
        (
            re.compile(r"No space left on device", re.I),
            "resources",
            "Deployment environment ran out of disk space",
            "A build or runtime write failed because its filesystem has no available space.",
            0.94,
            [
                "Identify the largest temporary/build artifacts and available ephemeral storage.",
                "Remove unnecessary generated artifacts from the build or adjust supported storage limits.",
            ],
        ),
        (
            re.compile(r"ERR_MODULE_NOT_FOUND|Cannot find module", re.I),
            "startup",
            "Node.js module could not be resolved at runtime",
            "The deployed Node.js process cannot resolve a module imported by the application.",
            0.76,
            [
                "Check whether the module is declared as a runtime dependency and included in the deployed workspace.",
                "Run the production start command after a clean production install.",
            ],
        ),
        (
            re.compile(r"failed to solve:|ERROR: failed to build", re.I),
            "container_build",
            "Docker image build failed",
            "Docker reported a failed build step; the failing instruction must be taken from nearby build output.",
            0.68,
            [
                "Inspect the first failing Docker build instruction and preceding command output.",
                "Re-run the build from a clean context after correcting that instruction.",
            ],
        ),
        (
            re.compile(
                r"Error: Process completed with exit code [1-9]|Process completed with exit code [1-9]",
                re.I,
            ),
            "ci",
            "GitHub Actions step failed",
            "A workflow command returned a non-zero exit code; the exact cause is not included in this line.",
            0.62,
            [
                "Inspect earlier output from the same workflow step for the first concrete error.",
                "Reproduce the step with the same runtime and environment variables, excluding secrets.",
            ],
        ),
        (
            re.compile(r"Unable to resolve action .* reference|Unable to resolve action", re.I),
            "ci",
            "GitHub Actions action reference could not be resolved",
            "The workflow references an action version or repository reference GitHub cannot resolve.",
            0.9,
            [
                "Verify the action repository and ref exist and are accessible.",
                "Pin the action to a maintained version or commit SHA and rerun the workflow.",
            ],
        ),
        (
            re.compile(
                r"ResolutionImpossible|ERESOLVE unable to resolve dependency tree|dependency conflict",
                re.I,
            ),
            "dependency",
            "Dependency constraints cannot be resolved",
            "The package manager reports incompatible dependency constraints; the responsible package constraints must be inspected before changing versions.",
            0.86,
            [
                "Inspect the resolver's conflicting package/version constraints.",
                "Choose compatible versions based on the project's supported runtime, update the lockfile, then repeat a clean install.",
            ],
        ),
        (
            re.compile(
                r"No Output Directory named .+ found after the Build completed|Output Directory .+ not found",
                re.I,
            ),
            "configuration",
            "Configured deployment output directory is missing",
            "The deployment expects a build artifact directory that was not produced at the configured path.",
            0.88,
            [
                "Compare the deployment output-directory setting with the build tool's configured output path.",
                "Run the build and confirm the expected directory exists before deploying.",
            ],
        ),
        (
            re.compile(r"FUNCTION_INVOCATION_FAILED|FUNCTION_INVOCATION_TIMEOUT", re.I),
            "runtime",
            "Serverless function invocation failed",
            "The platform reports that a function invocation did not complete successfully; the underlying cause requires function logs.",
            0.68,
            [
                "Fetch the matching function runtime logs and request ID.",
                "Use the first application exception or timeout evidence to refine the diagnosis.",
            ],
        ),
        (
            re.compile(r"vite: (?:not found|command not found)|vite: command not found", re.I),
            "build",
            "Vite build tool is unavailable",
            "The build environment attempted to run Vite but could not find its executable.",
            0.78,
            [
                "Confirm Vite is declared in the correct workspace manifest and installed before the build step.",
                "Run the committed build script from the package directory.",
            ],
        ),
        (
            re.compile(r"Runtime\.ImportModuleError|Unable to import module", re.I),
            "startup",
            "Lambda handler module could not be imported",
            "Lambda could not import the configured handler module from the deployment package.",
            0.87,
            [
                "Compare the configured handler module and function with files in the deployment artifact.",
                "Rebuild the package with the handler at the expected archive path.",
            ],
        ),
        (
            re.compile(
                r"Instance reachability check failed|System reachability check failed", re.I
            ),
            "infrastructure",
            "EC2 instance status check failed",
            "AWS reports a failed instance or system reachability status check.",
            0.82,
            [
                "Distinguish the instance check from the system check and review recent status events.",
                "Use the relevant recovery action only after determining whether the issue is guest OS or host infrastructure.",
            ],
        ),
        (
            re.compile(
                r"AccessDenied.*(?:logs:|DescribeLogGroups)|not authorized.*(?:logs:|DescribeLogGroups)",
                re.I,
            ),
            "permissions",
            "CloudWatch Logs access was denied",
            "The caller lacks the permission required to read the requested log group or events.",
            0.9,
            [
                "Confirm the selected role and log group ARN.",
                "Grant only the required read action such as logs:FilterLogEvents for the scoped log group.",
            ],
        ),
    ]
    for pattern, category, title, cause, confidence, steps in signatures:
        matched = [(number, line) for number, line in log_rows if pattern.search(line)]
        if not matched:
            continue
        number, line = matched[0]
        evidence = [_evidence("deployment log", f"log:{number}", line, "log")]
        if category == "configuration":
            variable = re.search(r"(?:Variable\s+|variable\s+)([A-Z][A-Z0-9_]{2,})", line)
            if variable:
                evidence.extend(_file_evidence(files, variable.group(1)))
        diagnoses.append(
            _diag(
                category,
                title,
                cause,
                confidence,
                evidence,
                "Review the cited evidence, then follow the verification steps before changing deployment state.",
                steps,
            )
        )
    return diagnoses


def _platforms(files: dict[str, str], requested: str | None) -> list[str]:
    known = _frameworks(files)
    mapping = {
        "github actions": "GitHub Actions",
        "github": "GitHub Actions",
        "vercel": "Vercel",
        "aws": "AWS",
        "docker": "Docker",
    }
    if requested:
        mapped = mapping.get(requested.lower(), requested)
        if mapped not in known:
            known.append(mapped)
    return sorted(set(known))


def diagnose_project(
    root: str | Path, *, logs: str = "", platform: str | None = None
) -> DiagnosticReport:
    """Inspect project evidence and return ranked, deterministic deployment diagnoses."""
    snapshot = inspect_project(root)
    logs_truncated = len(logs) > MAX_LOG_TEXT
    logs = logs[:MAX_LOG_TEXT]
    log_rows = _log_evidence(logs)
    diagnoses = (
        _diagnose_python(snapshot, log_rows)
        + _diagnose_node(snapshot, log_rows)
        + _diagnose_common(snapshot, log_rows)
    )
    unique: dict[str, Diagnosis] = {diagnosis.id: diagnosis for diagnosis in diagnoses}
    ranked = sorted(
        unique.values(),
        key=lambda diagnosis: (-diagnosis.confidence, diagnosis.category, diagnosis.id),
    )
    project = ProjectSummary(
        root=str(snapshot.root),
        frameworks=_frameworks(snapshot.files),
        platforms=_platforms(snapshot.files, platform),
        files_inspected=sorted(snapshot.files),
    )
    status: Literal["issues_found", "no_known_issue", "inconclusive"]
    if ranked:
        status = "issues_found"
        summary = f"Found {len(ranked)} evidence-backed diagnostic finding(s). No issue is marked resolved without verification."
    elif log_rows:
        status = "inconclusive"
        summary = "No known diagnostic rule matched the supplied evidence; the deployment state is inconclusive."
    else:
        status = "no_known_issue"
        summary = "No known deployment issue was detected in the inspected project files. This is not proof that deployment is healthy."
    limitations = [
        "Only bounded local project files and log text supplied to this run were analyzed; live provider state was not queried."
    ]
    if logs_truncated:
        limitations.append(
            f"Supplied log text exceeded {MAX_LOG_TEXT} characters and was truncated before analysis."
        )
    return DiagnosticReport(
        project=project,
        status=status,
        summary=summary,
        diagnoses=ranked,
        observations=list(snapshot.observations),
        limitations=limitations,
    )


def diagnose_log_text(logs: str, *, platform: str | None = None) -> list[Diagnosis]:
    """Run the same deterministic signatures on provider log text without local files."""
    del platform  # platform metadata is attached by the caller; signatures remain shared.
    snapshot = ProjectSnapshot(root=Path.cwd(), files={}, omitted_files=0, observations=())
    rows = _log_evidence(logs)
    diagnoses = (
        _diagnose_python(snapshot, rows)
        + _diagnose_node(snapshot, rows)
        + _diagnose_common(snapshot, rows)
    )
    return sorted(
        {item.id: item for item in diagnoses}.values(),
        key=lambda item: (-item.confidence, item.category, item.id),
    )
