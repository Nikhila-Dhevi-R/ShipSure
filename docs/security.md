# Security model

## Trust boundaries

- **Project files and logs:** untrusted input. These can contain prompt injection, credentials, very large files, binary data, or misleading messages. ShipSure does not execute files during diagnosis. Findings are produced by deterministic signatures and parsed configuration facts.
- **MCP host:** may invoke read-only tools. Tool annotations are protocol hints and are not treated as an approval mechanism. The MCP server has no apply-fix or run-command tool.
- **Local repair:** a separate CLI operation. It rejects paths outside the project, symlinks, secret directories/files, credential-like contents, ambiguous matches, and stale previews. It creates a private backup outside the project and atomically replaces the file only after explicit approval.
- **Verification:** project checks can run arbitrary project-controlled scripts even when invoked by common build/test commands. ShipSure requires explicit approval, restricts command shapes, uses `shell=False`, applies a hard timeout, strips common secret-bearing environment variables, and redacts captured output.
- **Provider credentials:** Vercel uses `VERCEL_TOKEN` or a logged-in Vercel CLI; AWS uses the boto3 credential chain/profile. ShipSure does not request credentials through tool arguments, print tokens, or perform cloud mutations.

## Local inspection controls

- Root-scoped walk; symlink directories are not traversed.
- Excludes VCS metadata, virtual environments, dependency directories, caches, build outputs, local `.env` files, keys, and credential-named files.
- Reads only relevant text extensions, with 400 files, 256 KB per file, and 3 MB total read limits.
- Log input is capped to 200 relevant lines in the rule engine; output excerpts are bounded and redacted.
- Path replacement is resolved and checked against the chosen project root.

## Cloud read controls

- AWS APIs are tied to explicitly supplied resource IDs/names. Requests and result windows are capped. Log reads set `unmask=False`; IAM inspection is limited to one named role.
- Vercel API responses are reduced to an allowlist of project/deployment metadata. Environment response `value` fields are discarded and never included in reports. Runtime logs are obtained from the documented CLI read command with no follow/stream mode.
- HTTP transport, when selected, binds to loopback only. Prefer stdio for coding agents.

## Known limits

Redaction is defense in depth, not a promise to recognize every custom secret format. Keep secrets out of deployment logs and report outputs. Review generated reports before sharing them. Live provider behavior and access policies have not been validated against the user's cloud accounts.
