"""Bounded, read-only Vercel REST API adapter."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from typing import Any
from urllib.parse import quote

import httpx

from shipsure.engine import _diag, diagnose_log_text
from shipsure.models import Evidence, ProviderReport
from shipsure.security import redact_secrets

API_ROOT = "https://api.vercel.com"
MAX_PROVIDER_RESPONSE = 4_000_000
MAX_RUNTIME_LOG_BYTES = 4_000_000
_ENVIRONMENT_CAP_LIMITATION = "Vercel environment metadata was capped at 500 entries; absence of a name beyond the cap is inconclusive."
_PROJECT_FIELDS = (
    "id",
    "name",
    "framework",
    "rootDirectory",
    "buildCommand",
    "installCommand",
    "outputDirectory",
    "devCommand",
    "nodeVersion",
    "regions",
    "createdAt",
    "updatedAt",
)
_ENV_FIELDS = ("key", "type", "target", "gitBranch", "createdAt", "updatedAt", "id")
_DEPLOYMENT_FIELDS = (
    "id",
    "url",
    "name",
    "state",
    "readyState",
    "readyStateReason",
    "errorCode",
    "target",
    "createdAt",
    "ready",
    "meta",
    "projectId",
)


class VercelApiError(RuntimeError):
    """A provider response failed without exposing its body or authorization data."""


class VercelReadOnlyAdapter:
    """Use Vercel's read endpoints only; never request decrypted environment values."""

    def __init__(self, token: str | None = None, *, client: httpx.Client | None = None) -> None:
        resolved_token = token or os.environ.get("VERCEL_TOKEN")
        self._token = resolved_token
        self._client = client or httpx.Client(
            base_url=API_ROOT,
            headers={"Accept": "application/json"},
            timeout=httpx.Timeout(connect=5, read=15, write=5, pool=5),
            follow_redirects=False,
        )
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> VercelReadOnlyAdapter:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if not self._token:
            raise VercelApiError(
                "Vercel REST API access requires VERCEL_TOKEN; runtime logs can use an authenticated Vercel CLI installation."
            )
        try:
            chunks = []
            size = 0
            with self._client.stream(
                "GET",
                f"{API_ROOT}{path}",
                params=params,
                headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            ) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_PROVIDER_RESPONSE:
                        raise VercelApiError(
                            f"Vercel API response exceeds the {MAX_PROVIDER_RESPONSE}-byte safety limit"
                        )
                    chunks.append(chunk)
            return json.loads(b"".join(chunks))
        except httpx.HTTPStatusError as exc:
            raise VercelApiError(
                f"Vercel API returned HTTP {exc.response.status_code} for a read request"
            ) from None
        except httpx.RequestError as exc:
            raise VercelApiError(f"Vercel API read request failed: {type(exc).__name__}") from None
        except (ValueError, UnicodeDecodeError):
            raise VercelApiError("Vercel API returned invalid JSON") from None

    @staticmethod
    def _team_params(team_id: str | None) -> dict[str, str]:
        return {"teamId": team_id} if team_id else {}

    def inspect_project(self, project_id: str, *, team_id: str | None = None) -> ProviderReport:
        data = self._get(f"/v9/projects/{quote(project_id, safe='')}", self._team_params(team_id))
        safe_data = {
            key: data[key] for key in _PROJECT_FIELDS if isinstance(data, dict) and key in data
        }
        evidence = [
            Evidence(
                source="Vercel project API",
                location=f"project:{project_id}/{key}",
                excerpt=redact_secrets(f"{key}={safe_data[key]}"),
                kind="provider",
            )
            for key in (
                "framework",
                "rootDirectory",
                "buildCommand",
                "installCommand",
                "outputDirectory",
            )
            if key in safe_data and safe_data[key] is not None
        ]
        return ProviderReport(
            provider="vercel", target=f"project:{project_id}", observations=evidence
        )

    def inspect_environment(self, project_id: str, *, team_id: str | None = None) -> ProviderReport:
        # This endpoint returns environment variable metadata. ShipSure copies only allowlisted
        # names/targets/types and discards the response's value field immediately.
        data = self._get(
            f"/v9/projects/{quote(project_id, safe='')}/env", self._team_params(team_id)
        )
        rows = data.get("env", []) if isinstance(data, dict) else []
        evidence = []
        for item in rows[:500]:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                continue
            safe = {key: item[key] for key in _ENV_FIELDS if key in item}
            targets = safe.get("target", [])
            if isinstance(targets, str):
                targets = [targets]
            excerpt = f"{safe['key']} ({safe.get('type', 'type unavailable')}; targets: {', '.join(map(str, targets or [])) or 'unspecified'})"
            evidence.append(
                Evidence(
                    source="Vercel environment metadata API",
                    location=f"project:{project_id}/env:{safe['key']}",
                    excerpt=redact_secrets(excerpt),
                    kind="provider",
                )
            )
        limitations = [_ENVIRONMENT_CAP_LIMITATION] if len(rows) >= 500 else []
        return ProviderReport(
            provider="vercel",
            target=f"project:{project_id}/environment-metadata",
            observations=evidence,
            limitations=limitations,
        )

    def inspect_deployment(
        self,
        deployment_id_or_url: str,
        *,
        project_id: str | None = None,
        team_id: str | None = None,
        limit: int = 100,
    ) -> ProviderReport:
        safe_limit = min(max(int(limit), 1), 200)
        encoded = quote(deployment_id_or_url, safe="")
        query = self._team_params(team_id)
        deployment = self._get(f"/v13/deployments/{encoded}", query)
        events_result = self._get(
            f"/v3/deployments/{encoded}/events", {**query, "limit": safe_limit}
        )
        events = (
            events_result
            if isinstance(events_result, list)
            else events_result.get("events", [])
            if isinstance(events_result, dict)
            else []
        )
        safe_deployment = {
            key: deployment[key]
            for key in _DEPLOYMENT_FIELDS
            if isinstance(deployment, dict) and key in deployment
        }
        deployment_id = str(safe_deployment.get("id", deployment_id_or_url))
        observations: list[Evidence] = []
        for key in ("readyState", "readyStateReason", "errorCode", "target", "createdAt"):
            if safe_deployment.get(key) is not None:
                observations.append(
                    Evidence(
                        source="Vercel deployment API",
                        location=f"deployment:{deployment_id}/{key}",
                        excerpt=redact_secrets(f"{key}={safe_deployment[key]}"),
                        kind="provider",
                    )
                )
        event_lines = []
        for index, event in enumerate(events[:safe_limit], start=1):
            if not isinstance(event, dict):
                continue
            text = event.get("text") or event.get("message") or event.get("payload") or ""
            if isinstance(text, (dict, list)):
                text = str(text)
            if text:
                excerpt = redact_secrets(str(text), max_length=2000)
                location = f"deployment:{deployment_id}/event:{event.get('id', index)}"
                observations.append(
                    Evidence(
                        source="Vercel deployment event API",
                        location=location,
                        excerpt=excerpt,
                        kind="log",
                    )
                )
                event_lines.append(excerpt)

        diagnoses = diagnose_log_text("\n".join(event_lines), platform="Vercel")
        provider_limitations = [
            "Vercel environment variable values are never returned or compared; only names, types, and targets are inspected."
        ]
        ready_state = str(safe_deployment.get("readyState", "")).upper()
        if ready_state in {"ERROR", "FAILED"}:
            cause_detail = (
                safe_deployment.get("readyStateReason")
                or safe_deployment.get("errorCode")
                or "Vercel marked this deployment as failed."
            )
            event_evidence = [
                item for item in observations if item.source == "Vercel deployment API"
            ]
            diagnoses.insert(
                0,
                _diag(
                    "deployment",
                    "Vercel deployment failed",
                    f"Vercel reports deployment state {ready_state}: {redact_secrets(str(cause_detail))}.",
                    0.98,
                    event_evidence
                    or [
                        Evidence(
                            source="Vercel deployment API",
                            location=f"deployment:{deployment_id}",
                            excerpt=f"readyState={ready_state}",
                            kind="provider",
                        )
                    ],
                    "Inspect the deployment build events and runtime logs to identify the failing step, then apply only a local, reviewed fix.",
                    [
                        "Identify the first failing build or runtime event.",
                        "Apply a reviewed correction locally.",
                        "Create a new deployment and verify its state and relevant logs.",
                    ],
                ),
            )

        if project_id:
            project_report = self.inspect_project(project_id, team_id=team_id)
            environment_report = self.inspect_environment(project_id, team_id=team_id)
            observations.extend(project_report.observations)
            observations.extend(environment_report.observations)
            provider_limitations.extend(project_report.limitations)
            provider_limitations.extend(environment_report.limitations)
            available_names = {
                item.location.rsplit("/env:", 1)[-1]: item
                for item in environment_report.observations
                if "/env:" in item.location
            }
            missing_env_logs = re.findall(
                r"(?i)Environment Variable\s+([A-Z][A-Z0-9_]*)\s+(?:not found|is missing)",
                "\n".join(event_lines),
            )
            environment_is_capped = _ENVIRONMENT_CAP_LIMITATION in environment_report.limitations
            for variable in sorted(set(missing_env_logs)):
                matched_finding = next(
                    (
                        item
                        for item in diagnoses
                        if item.category == "configuration"
                        and any(variable in proof.excerpt for proof in item.evidence)
                    ),
                    None,
                )
                if not matched_finding:
                    continue
                if variable in available_names:
                    env_evidence = available_names[variable].model_copy(
                        update={
                            "excerpt": f"Vercel metadata lists {variable}; targets must include the environment used by this deployment, and values were excluded."
                        }
                    )
                    matched_finding.evidence.append(env_evidence)
                    matched_finding.alternatives.append(
                        "The variable exists but may not target this deployment environment, or the deployment may predate the variable update."
                    )
                elif not environment_is_capped:
                    matched_finding.evidence.append(
                        Evidence(
                            source="Vercel environment metadata API",
                            location=f"project:{project_id}/env:lookup:{variable}",
                            excerpt=f"No Vercel environment metadata entry named {variable} was returned among {len(available_names)} inspected variable names; values were excluded.",
                            kind="provider",
                        )
                    )
                    matched_finding.confidence = max(matched_finding.confidence, 0.97)
                    matched_finding.confidence_label = "high"
                    matched_finding.status = "supported"
        return ProviderReport(
            provider="vercel",
            target=f"deployment:{deployment_id}",
            observations=observations,
            diagnoses=diagnoses,
            limitations=provider_limitations,
        )

    def list_deployments(
        self, project_id: str, *, team_id: str | None = None, limit: int = 20
    ) -> ProviderReport:
        bounded_limit = min(max(int(limit), 1), 100)
        params = {
            **self._team_params(team_id),
            "projectId": project_id,
            "limit": bounded_limit,
        }
        data = self._get("/v6/deployments", params)
        deployments = data.get("deployments", []) if isinstance(data, dict) else []
        observations = []
        for item in deployments[:bounded_limit]:
            if not isinstance(item, dict):
                continue
            fields = {
                key: item[key]
                for key in ("uid", "url", "state", "target", "created", "ready")
                if key in item
            }
            observations.append(
                Evidence(
                    source="Vercel deployments API",
                    location=f"project:{project_id}/deployment:{fields.get('uid', 'unknown')}",
                    excerpt=redact_secrets(
                        ", ".join(f"{key}={value}" for key, value in fields.items())
                    ),
                    kind="provider",
                )
            )
        return ProviderReport(
            provider="vercel", target=f"project:{project_id}/deployments", observations=observations
        )

    def inspect_runtime_logs(
        self,
        deployment_id_or_url: str,
        *,
        project_id: str | None = None,
        root: str | os.PathLike[str] = ".",
        since: str = "1h",
        limit: int = 100,
        query: str | None = None,
    ) -> ProviderReport:
        """Read bounded runtime logs through an already-installed Vercel CLI."""
        if not re.fullmatch(r"(?:[1-9][0-9]*[mhd]|\d{4}-\d{2}-\d{2}T[^\s]+Z?)", since):
            raise ValueError(
                "since must be a relative window such as 30m or 2h, or an ISO timestamp"
            )
        safe_limit = min(max(int(limit), 1), 1000)
        executable = shutil.which("vercel") or shutil.which("vercel.cmd")
        if not executable:
            raise VercelApiError(
                "Vercel runtime log retrieval requires the Vercel CLI to already be installed and authenticated"
            )
        command = [
            executable,
            "logs",
            "--deployment",
            deployment_id_or_url,
            "--json",
            "--limit",
            str(safe_limit),
            "--since",
            since,
            "--no-branch",
            "--no-follow",
        ]
        if project_id:
            command.extend(["--project", project_id])
        if query:
            if len(query) > 256:
                raise ValueError("runtime log query is limited to 256 characters")
            command.extend(["--query", query])
        process = subprocess.Popen(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        stdout_parts: list[bytes] = []
        stderr_parts: list[bytes] = []
        remaining = [MAX_RUNTIME_LOG_BYTES]
        lock = threading.Lock()
        output_exceeded = threading.Event()

        def drain(stream: Any, target: list[bytes]) -> None:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                with lock:
                    keep = min(len(chunk), remaining[0])
                    if keep:
                        target.append(chunk[:keep])
                        remaining[0] -= keep
                    if keep != len(chunk):
                        output_exceeded.set()
                if output_exceeded.is_set():
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return

        readers = [
            threading.Thread(target=drain, args=(process.stdout, stdout_parts), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr_parts), daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise VercelApiError("Vercel runtime log request timed out after 60 seconds") from None
        except OSError as exc:
            raise VercelApiError(
                f"Vercel runtime log request could not start ({type(exc).__name__})"
            ) from None
        finally:
            for reader in readers:
                reader.join(timeout=2)
        if output_exceeded.is_set():
            raise VercelApiError(
                f"Vercel runtime log output exceeded the {MAX_RUNTIME_LOG_BYTES}-byte safety limit"
            )
        stdout = b"".join(stdout_parts).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_parts).decode("utf-8", errors="replace")
        if process.returncode:
            raise VercelApiError(
                f"Vercel runtime log request failed with exit code {process.returncode}: {redact_secrets(stderr, max_length=2000)}"
            )
        lines = stdout.splitlines()[-safe_limit:]
        observations: list[Evidence] = []
        log_text = []
        for index, raw_line in enumerate(lines, start=1):
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError:
                record = {"message": raw_line}
            if isinstance(record, dict):
                message = record.get("message") or record.get("text") or str(record)
                metadata = ", ".join(
                    f"{key}={record[key]}"
                    for key in ("level", "statusCode", "requestId", "route", "timestamp")
                    if key in record
                )
                excerpt = redact_secrets(
                    f"{metadata}: {message}" if metadata else str(message), max_length=2000
                )
            else:
                excerpt = redact_secrets(str(record), max_length=2000)
            if excerpt:
                observations.append(
                    Evidence(
                        source="Vercel CLI runtime logs",
                        location=f"deployment:{deployment_id_or_url}/runtime-log:{index}",
                        excerpt=excerpt,
                        kind="log",
                    )
                )
                log_text.append(excerpt)
        diagnoses = diagnose_log_text("\n".join(log_text), platform="Vercel")
        return ProviderReport(
            provider="vercel",
            target=f"deployment:{deployment_id_or_url}/runtime-logs",
            observations=observations,
            diagnoses=diagnoses,
            limitations=[
                "Runtime logs were read using the installed Vercel CLI with a bounded time window and entry limit. No deployment or project settings were changed."
            ],
        )
