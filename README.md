# ShipSure

**Diagnose. Fix. Verify. Deploy.**

An open-source MCP server, standalone CLI, and Agent Skills for OpenAI Codex and Claude Code. Diagnose deployment failures, pinpoint evidence-backed causes, apply safe fixes with approval, and inspect deployment health across AWS, Vercel, Docker, and CI/CD. Stop debugging. Start shipping.

ShipSure is an open-source deployment diagnosis toolkit with one deterministic evidence engine shared by its CLI and MCP server. It correlates application files, dependency declarations, deployment configuration, and supplied or provider-read logs. Findings include source evidence, confidence, plausible alternatives, a safe recommended action, and concrete verification steps.

ShipSure does not need an LLM or send project data to an external model service. Connect the MCP server to Codex or Claude Code to let an agent follow the included workflow skill. The agent remains responsible for explaining the evidence; ShipSure remains responsible for deterministic checks and observable verification results.

## What it supports

- Python, FastAPI, Uvicorn, requirements files, and `pyproject.toml`
- Node.js, React, Vite, npm scripts and dependency manifests
- Dockerfiles, Docker Compose, container build/startup/port/health failures
- GitHub Actions workflow files and common action/step failures
- Vercel deployment state/events, project deployment configuration, environment variable **names and targets only**, and runtime logs through an already-installed Vercel CLI
- AWS EC2 status checks, ECS service deployments/events, Lambda configuration and CloudWatch logs, named CloudWatch log groups, scoped IAM role/policy review, and CloudFormation stack events
- JSON and Markdown reports, local fix previews, reversible local edits, and execution-backed local verification

The rule engine has fixture-driven checks for 26 realistic errors across these platforms. It reports an unrecognized failure as inconclusive; it never treats “no matching rule” as deployment health.

## Install

ShipSure requires Python 3.11 or newer. After the first package release, install the CLI and both provider integrations in a virtual environment with:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install "shipsure[all]"
```

On macOS or Linux:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'shipsure[all]'
```

Install without live provider integrations using `python -m pip install shipsure`. The `mcp` and `aws` extras can also be selected separately. This project has not been published to PyPI yet; from this checkout, install with `python -m pip install -e '.[all]'` or, for development, `python -m pip install -e '.[all,dev]'`.

## CLI

Diagnose a project without running its code:

```bash
shipsure diagnose --root .
shipsure diagnose --root . --log-file deploy.log --platform vercel --format json
```

Review the local environment variable names and dependency manifests:

```bash
shipsure dependencies --root .
shipsure env-check --root .
```

Inspect a failed Vercel deployment (REST API token required):

```bash
# Set VERCEL_TOKEN using your shell's secure environment configuration.
shipsure vercel deployment dpl_your_deployment --project-id your_project --team-id team_your_team
shipsure vercel env your_project --team-id team_your_team
```

Runtime log reading uses an existing authenticated Vercel CLI. ShipSure will not install it:

```bash
shipsure vercel runtime-logs dpl_your_deployment --project-id your_project --since 1h --limit 100
```

Preview, apply, and roll back a local edit:

```bash
shipsure fix-preview Procfile --root . --old-text 'uvicorn main:app' --new-text 'uvicorn app.main:app'
shipsure fix-apply Procfile --root . --old-text 'uvicorn main:app' --new-text 'uvicorn app.main:app'
shipsure rollback YOUR_ROLLBACK_ID --root .
```

Apply a deterministic proposal directly from a diagnosis report:

```bash
shipsure apply-proposal --root . --log-file deploy.log --finding 1
```

`fix-apply` and `apply-proposal` display the exact change and ask before editing. Both store a private rollback copy outside the project. If the file changes after preview or after application, ShipSure refuses to overwrite newer work. Automated proposals are currently limited to unambiguous FastAPI/Uvicorn startup module-path corrections; other findings receive safe, evidence-backed recommendations and verification steps.

Run a selected local verification check only after reviewing the command:

```bash
shipsure verify --root . --command "python -m pytest"
shipsure verify --root . --command "npm run build" --format json
```

The CLI asks before execution unless you explicitly pass `--approve`. Only checks on ShipSure's allowlist run; the process does not use a shell, has a 300-second maximum timeout, strips common cloud/token secrets from its environment, and redacts captured output. A local test or build does not verify a live deployment.

## MCP server

Start the local server using stdio, the recommended transport for coding clients:

```bash
shipsure-mcp
# Or: shipsure mcp
```

To use Streamable HTTP for a local client, ShipSure binds to loopback only:

```bash
shipsure-mcp --transport streamable-http --host 127.0.0.1 --port 8765
```

The server will reject non-loopback bind addresses. It exposes read-only diagnosis, provider inspections, report generation, and fix previews. It does not apply edits or execute repository commands through MCP because MCP tool annotations are hints, not reliable human approval. Use the interactive CLI for those actions.

### MCP tools

- `diagnose_project`, `analyze_deployment_logs`
- `inspect_project_dependencies`, `check_environment_configuration`
- `diagnose_container_failure`, `analyze_ci_workflow`
- `suggest_safe_fix`, `verify_proposed_fix`, `generate_diagnostic_report`
- `inspect_vercel_project`, `inspect_vercel_environment`, `inspect_vercel_deployment`, `inspect_vercel_runtime_logs`
- `inspect_aws_ec2`, `inspect_aws_ecs`, `inspect_aws_lambda`, `inspect_aws_cloudwatch_logs`, `inspect_aws_iam_role`, `inspect_aws_cloudformation_stack`

MCP project paths are restricted to the server's starting directory. To change this workspace boundary, set `SHIPSURE_WORKSPACE_ROOT` before starting the server.

## Codex and Claude Code

The repository includes the same `SKILL.md` at `.agents/skills/shipsure/SKILL.md` for Codex and `.claude/skills/shipsure/SKILL.md` for Claude Code. These are the clients' project-scoped skill directories. The canonical skill is in `skills/shipsure/SKILL.md` and ships in the Python package.

You can install or refresh the skills in another project with:

```bash
shipsure install-skill --client both --root /path/to/project
```

The installer asks before replacing a customized ShipSure skill; `--force` explicitly replaces it.

Copy `examples/codex.config.toml` into `~/.codex/config.toml` or merge its MCP section. Copy the server entry from `examples/claude.mcp.json` into the project's `.mcp.json`. Both examples use `shipsure-mcp` over stdio, so the command must be on `PATH` in the client process. For more detail, see [Codex skills](https://developers.openai.com/plugins/concepts/skills), [Claude Code skills](https://code.claude.com/docs/en/skills), and the [MCP Python SDK](https://py.sdk.modelcontextprotocol.io/v2/).

## Provider setup and permissions

### Vercel

For REST reads, set `VERCEL_TOKEN` in the process environment using a token with read access to only the required project/team. ShipSure calls deployment/project/environment read endpoints and drops all environment `value` fields. To retrieve runtime logs, install and authenticate the official Vercel CLI separately; ShipSure invokes only `vercel logs` with a bounded time window and entry limit. It will not install or update the CLI.

### AWS

Install the `aws` extra and configure the AWS SDK's normal credential chain or a named profile. Supply a region and explicit resource identifiers. ShipSure does not ask for access keys or print credentials. See [AWS read permissions](docs/provider-permissions.md) for the per-command action list and a least-privilege policy example.

## Security and verification model

- Project files and logs are untrusted data; diagnosis never executes them.
- `.env`, private keys, VCS directories, dependency trees, caches, and build outputs are excluded from project inspection. Input size, file count, and output sizes are bounded.
- Secret-looking values are redacted before evidence is reported. Vercel environment values are never returned.
- AWS uses named-resource `Get`, `List`, and `Describe` operations only. CloudWatch log reads set `unmask=False`.
- No provider mutation, deployment, policy simulation, repository command, or local file change is initiated by diagnosis or MCP.
- Proposed local replacements must be unambiguous, small, in-root, and free of credential-like content. Applying and rolling back require explicit approval.
- “Locally verified” and “deployment verified” are separate claims. Only observed successful command/deployment evidence can set those statuses.

See [the security model](docs/security.md) and [the architecture](docs/architecture.md).

## Test and develop

```bash
python -m venv .venv
python -m pip install -e '.[all,dev]'
python -m unittest discover -s tests -v
ruff check src tests
ruff format --check src tests
mypy src
python -m build
shipsure --help
shipsure-mcp --help
```

The provider tests use controlled fake clients and HTTP transports; they do not require AWS or Vercel credentials. Do not run the test suite against real production accounts. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Current boundaries

- Diagnosis is deterministic and rule-based. It does not call an LLM and does not claim to infer unknown root causes.
- Vercel runtime logs require the official CLI because the adapter uses the documented `vercel logs` command; no unverified REST endpoint is assumed.
- AWS operations are scoped to specific resource types and IDs. ShipSure does not inspect all AWS resources, query secret values, or perform policy simulation.
- Live provider calls were not made during local development. Check permissions, endpoint access, and client behavior in a non-production account before operational use.
- External deployment verification is observational only. ShipSure does not deploy changes or alter cloud resources.
