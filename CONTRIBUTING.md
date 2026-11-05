# Contributing

Thanks for helping improve ShipSure. Keep changes evidence-based, cross-platform, and within the security model.

## Development setup

```bash
python -m venv .venv
python -m pip install -e '.[all,dev]'
python -m unittest discover -s tests -v
ruff check src tests
ruff format --check src tests
mypy src
python -m build
```

Provider tests must use fake clients or mock HTTP transports. Do not require live credentials or contact production accounts from automated tests.

## Adding a diagnostic rule

1. Add a realistic minimal fixture/log to `tests/test_scenarios.py` and make it fail before adding the rule.
2. Implement a deterministic rule in the shared engine or a focused module. A finding needs evidence, calibrated confidence, alternatives when ambiguous, a safe recommendation, and verification steps.
3. Add negative or ambiguity coverage where a signature could cause false positives.
4. Keep log and source excerpts redacted and bounded. Never read `.env` values or execute project code during diagnosis.
5. Run the full local suite and format/lint checks.

## Adding a provider

Return normalized `ProviderReport` observations/findings, make reads resource-scoped and bounded, use timeouts, document exact read permissions, and test with fake API clients. Do not add mutations to MCP or default diagnosis.

## Pull requests

Explain the failure scenario and supporting evidence, identify security impact, include test output, and update the supported-platform documentation. Avoid claiming a live deployment was verified unless a test actually observed that state.
