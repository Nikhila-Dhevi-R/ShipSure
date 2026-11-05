"""Explicitly approved, reversible local fixes and bounded verification runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from shipsure.models import FileChange, VerificationResult
from shipsure.security import contained_path, redact_secrets

MAX_EDIT_BYTES = 512_000
_FORBIDDEN_PARTS = {".env", ".aws", ".ssh", ".azure", ".config"}
_FORBIDDEN_MARKERS = (
    "secret",
    "credential",
    "private",
    "id_rsa",
    "id_ed25519",
    ".pem",
    ".p12",
    ".pfx",
)
_SECRET_ENV = re.compile(
    r"(?i)(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|^AWS_|^VERCEL_|^GITHUB_TOKEN|^NPM_TOKEN|SSH_AUTH_SOCK)"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ApprovalRequired(PermissionError):
    """Raised when a caller attempts a mutating or executing operation without approval."""


@dataclass(frozen=True)
class AppliedChange:
    path: str
    backup_path: str
    before_sha256: str
    after_sha256: str


def _safe_target(root: Path, relative_path: str) -> tuple[Path, str]:
    normalized = relative_path.replace("\\", "/")
    pieces = Path(normalized).parts
    if not normalized or Path(normalized).is_absolute() or any(part == ".." for part in pieces):
        raise ValueError("file path must stay inside the project root")
    if any(part.lower() in _FORBIDDEN_PARTS for part in pieces):
        raise ValueError("ShipSure refuses to edit secret or credential directories")
    if any(marker in Path(normalized).name.lower() for marker in _FORBIDDEN_MARKERS):
        raise ValueError("ShipSure refuses to edit files that may contain credentials")
    target = contained_path(root, normalized)
    if target.is_symlink():
        raise ValueError("ShipSure refuses to edit symbolic links")
    return target, normalized


def _safe_content(text: str) -> bool:
    return redact_secrets(text, max_length=max(len(text), 1)) == text


def preview_text_replacement(
    root: str | Path, relative_path: str, old_text: str, new_text: str
) -> FileChange:
    """Build a single-match preview without writing to disk or exposing secret-bearing files."""
    project_root = Path(root).expanduser().resolve(strict=True)
    target, normalized = _safe_target(project_root, relative_path)
    if not target.is_file() or target.stat().st_size > MAX_EDIT_BYTES:
        raise ValueError("only small, regular text files can be edited")
    before = target.read_bytes().decode("utf-8")
    if not _safe_content(before) or not _safe_content(new_text):
        raise ValueError(
            "ShipSure refuses to preview or write content containing credential-like values"
        )
    if not old_text or before.count(old_text) != 1:
        raise ValueError("the expected text must occur exactly once in the file")
    after = before.replace(old_text, new_text, 1)
    return FileChange(path=normalized, before=before, after=after)


def _state_directory(project_root: Path) -> Path:
    if os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    elif os.environ.get("XDG_STATE_HOME"):
        base = Path(os.environ["XDG_STATE_HOME"])
    else:
        base = Path.home() / ".local" / "state"
    project_id = hashlib.sha256(str(project_root).encode("utf-8")).hexdigest()[:24]
    backup_root = base / "ShipSure" / "backups" / project_id
    backup_root.mkdir(parents=True, exist_ok=True)
    try:
        backup_root.chmod(0o700)
    except OSError:
        pass
    return backup_root


def _atomic_write(target: Path, content: str, mode: int) -> None:
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="", delete=False, dir=target.parent
        ) as stream:
            temp_name = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, target)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def apply_file_change(
    root: str | Path, change: FileChange, *, approved: bool = False
) -> AppliedChange:
    """Atomically apply a reviewed file change after validating its original contents."""
    if not approved:
        raise ApprovalRequired("explicit user approval is required before changing a file")
    project_root = Path(root).expanduser().resolve(strict=True)
    target, normalized = _safe_target(project_root, change.path)
    current = target.read_bytes().decode("utf-8")
    if current != change.before:
        raise ValueError("the file changed after preview; create a fresh preview before applying")
    if not _safe_content(current) or not _safe_content(change.after):
        raise ValueError("ShipSure refuses to apply content containing credential-like values")
    backup_root = _state_directory(project_root) / uuid.uuid4().hex
    backup_target = backup_root / Path(normalized)
    backup_target.parent.mkdir(parents=True, exist_ok=True)
    try:
        backup_target.chmod(0o600)
    except OSError:
        pass
    mode = target.stat().st_mode & 0o777
    backup_target.write_bytes(current.encode("utf-8"))
    try:
        backup_target.chmod(0o600)
    except OSError:
        pass
    _atomic_write(target, change.after, mode)
    result = AppliedChange(
        path=normalized,
        backup_path=str(backup_target),
        before_sha256=hashlib.sha256(current.encode("utf-8")).hexdigest(),
        after_sha256=hashlib.sha256(change.after.encode("utf-8")).hexdigest(),
    )
    manifest = backup_root / "manifest.json"
    manifest.write_text(json.dumps(result.__dict__, indent=2), encoding="utf-8")
    try:
        manifest.chmod(0o600)
    except OSError:
        pass
    return result


def load_applied_change(root: str | Path, change_id: str) -> AppliedChange:
    """Load a local rollback record created by ShipSure, identified by its random ID."""
    if not re.fullmatch(r"[a-f0-9]{32}", change_id):
        raise ValueError("rollback ID must be a ShipSure-generated 32-character ID")
    project_root = Path(root).expanduser().resolve(strict=True)
    record_root = _state_directory(project_root) / change_id
    manifest = (record_root / "manifest.json").resolve(strict=True)
    try:
        manifest.relative_to(record_root.resolve(strict=True))
    except ValueError as exc:
        raise ValueError("rollback record is outside its private state directory") from exc
    data = json.loads(manifest.read_text(encoding="utf-8"))
    backup_path = Path(data["backup_path"]).resolve(strict=True)
    try:
        backup_path.relative_to(record_root.resolve(strict=True))
    except ValueError as exc:
        raise ValueError("rollback backup is outside its private state directory") from exc
    return AppliedChange(**data)


def rollback_file_change(
    root: str | Path, applied: AppliedChange, *, approved: bool = False
) -> None:
    """Restore a ShipSure backup only if the target still matches the applied version."""
    if not approved:
        raise ApprovalRequired("explicit user approval is required before restoring a file")
    project_root = Path(root).expanduser().resolve(strict=True)
    target, _ = _safe_target(project_root, applied.path)
    if hashlib.sha256(target.read_bytes()).hexdigest() != applied.after_sha256:
        raise ValueError(
            "the file changed after ShipSure applied the fix; refusing to overwrite newer work"
        )
    backup = Path(applied.backup_path).resolve(strict=True)
    backup_bytes = backup.read_bytes()
    backup_text = backup_bytes.decode("utf-8")
    if hashlib.sha256(backup_bytes).hexdigest() != applied.before_sha256:
        raise ValueError("the ShipSure backup failed its integrity check")
    _atomic_write(target, backup_text, target.stat().st_mode & 0o777)


def _allowed_command(argv: Sequence[str]) -> bool:
    if len(argv) >= 3 and Path(argv[0]).name.lower() in {
        "python",
        "python3",
        "python.exe",
        "python3.exe",
        Path(sys.executable).name.lower(),
    }:
        if argv[1:3] in (["-m", "compileall"], ["-m", "pip"], ["-m", "pytest"]):
            return len(argv) == 3 if argv[1:3] == ["-m", "pip"] else True
    if (
        len(argv) == 3
        and Path(argv[0]).name.lower() in {"npm", "npm.cmd", "npm.exe"}
        and argv[1] == "run"
        and argv[2] in {"build", "lint"}
    ):
        return True
    return False


def run_verification(
    root: str | Path,
    command: Sequence[str],
    *,
    approved: bool = False,
    timeout_seconds: int = 120,
) -> VerificationResult:
    """Run one approved allowlisted project check without a shell or inherited secrets."""
    if not approved:
        raise ApprovalRequired("explicit user approval is required before running project commands")
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise ValueError("verification command must be a non-empty argument list")
    if not _allowed_command(command):
        raise ValueError("command is not on ShipSure's verification allowlist")
    if not 1 <= timeout_seconds <= 300:
        raise ValueError("verification timeout must be between 1 and 300 seconds")
    project_root = Path(root).expanduser().resolve(strict=True)
    safe_env = {key: value for key, value in os.environ.items() if not _SECRET_ENV.search(key)}
    started = datetime.now(UTC)
    try:
        completed = subprocess.run(
            list(command),
            cwd=project_root,
            env=safe_env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
        exit_code = completed.returncode
        raw_output = (completed.stdout + "\n" + completed.stderr)[-32_000:]
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        exit_code = None
        stdout = (
            exc.stdout.decode(errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode(errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        raw_output = (stdout + "\n" + stderr)[-32_000:]
        timed_out = True
    finished = datetime.now(UTC)
    verified = exit_code == 0 and not timed_out
    return VerificationResult(
        command=" ".join(command),
        started_at=started,
        finished_at=finished,
        exit_code=exit_code,
        timed_out=timed_out,
        output_excerpt=_CONTROL.sub("", redact_secrets(raw_output.replace("\r", "\n"))),
        verified=verified,
        scope="local",
        note="Local command completed successfully."
        if verified
        else "Local verification did not pass; no deployment health claim is made.",
    )
