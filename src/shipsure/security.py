"""Redaction and path-safety helpers for untrusted project and log data."""

from __future__ import annotations

import re
from pathlib import Path

_ASSIGNMENT_SECRET = re.compile(
    r"""(?i)(\b(?:[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|AUTHORIZATION)[A-Z0-9_]*)\b\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)"""
)
_AUTHORIZATION = re.compile(
    r"(?i)(\b(?:proxy-)?authorization\b\s*[:=]\s*)(?:Bearer|Basic)\s+[^\s,;]+"
)
_BEARER = re.compile(r"(?i)(\b(?:Bearer|Basic)\s+)([^\s,;]+)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?\b")
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_COMMON_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|vercel_[A-Za-z0-9_-]{16,})\b"
)
_URL_CREDENTIALS = re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.DOTALL,
)


def redact_secrets(value: str, *, max_length: int = 16_000) -> str:
    """Mask common credentials and cap untrusted text before it reaches a report."""
    value = value[:max_length]
    value = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)
    value = _AUTHORIZATION.sub(r"\1[REDACTED]", value)
    value = _ASSIGNMENT_SECRET.sub(r"\1[REDACTED]", value)
    value = _BEARER.sub(r"\1[REDACTED]", value)
    value = _JWT.sub("[REDACTED JWT]", value)
    value = _AWS_ACCESS_KEY.sub("[REDACTED AWS KEY]", value)
    value = _COMMON_TOKEN.sub("[REDACTED TOKEN]", value)
    value = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)
    return value


def contained_path(root: Path, relative_path: str) -> Path:
    """Resolve a project-relative path and reject traversal or symlink escapes."""
    base = root.resolve(strict=True)
    candidate = (base / relative_path).resolve(strict=False)
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError("path is outside the project root") from exc
    return candidate
