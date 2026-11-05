# Architecture

```text
Codex Skill ─┐
Claude Skill ├── CLI / MCP adapters ── Application services ── Evidence engine
Standalone CLI┘                                              ├─ Local inspectors
                                                           ├─ Log signatures
                                                           ├─ Vercel read adapter
                                                           ├─ AWS read adapter
                                                           └─ JSON / Markdown reports
```

## Shared diagnostic path

The CLI and MCP server call `diagnose_project`, `inspect_dependencies`, `inspect_environment_configuration`, `merge_provider_reports`, and the repair/verification service functions. Provider adapters normalize observations into the same `Evidence`, `Diagnosis`, and `ProviderReport` types used by local rules. No interface has a separate root-cause algorithm.

The evidence engine checks a bounded set of project files and log lines against deterministic rules. Each finding carries a stable ID, a category, a confidence score and label, one or more evidence locations, alternate explanations when appropriate, a recommendation, and local/deployment verification steps. Findings stay `suspected` at low confidence or `supported` when the evidence threshold is met. Fixes never change a finding to verified by themselves.

## Project file inspection

`inspectors/local.py` walks without executing or following symlinks, excludes sensitive/dependency/build directories, and enforces per-file, total-byte, and file-count caps. `analysis.py` inventories declared dependency names and source-referenced environment variable names. It does not load `.env` values.

## Provider adapters

`adapters/vercel.py` makes bounded GET requests against Vercel project, deployment, events, and environment-metadata APIs. Runtime logs use an already-installed Vercel CLI because the API adapter does not assume a runtime-log endpoint absent an authoritative REST reference. It never calls a decrypted env-values endpoint.

`adapters/aws.py` creates boto3 clients with bounded timeouts/retries and the default credential chain or an explicit profile. It uses exact-resource calls for EC2, ECS, Lambda, CloudWatch Logs, IAM, and CloudFormation. It does not mutate cloud resources or call policy simulation.

## Repair and verification

`repairs.py` builds exact single-replacement previews, verifies original content before edit, atomically writes after approval, stores rollback material under the user's private state directory, and refuses rollback if newer edits exist. `apply-proposal` connects an evidence-backed startup module-path correction to that approval flow; other findings provide recommended actions rather than automatic edits. Verification uses an allowlist and a direct argument vector with `shell=False`; it strips common cloud credential environment variables and applies timeouts. Only a successful process result produces `verified=True`, scoped to local checks.

## Extension point

Add new provider adapters that return `ProviderReport`, implement deterministic parsers/rules over normalized observations, and register read-only CLI/MCP tools that call the same functions. Keep provider requests bounded, credentials outside arguments/output, and mutations outside the diagnosis path.
