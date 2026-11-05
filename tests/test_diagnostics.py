from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from shipsure.engine import diagnose_project
from shipsure.models import Evidence
from shipsure.reporting import render_markdown
from shipsure.security import redact_secrets


class RedactionTests(unittest.TestCase):
    def test_redacts_common_provider_and_bearer_secrets(self) -> None:
        source = (
            "VERCEL_TOKEN=vercel_abcdefghijklmnop AWS_SECRET_ACCESS_KEY=abc123 "
            'Authorization: Bearer opaque-access-token-value PASSWORD="two words" '
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.signature"
        )

        redacted = redact_secrets(source)

        self.assertNotIn("abcdefghijklmnop", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("opaque-access-token-value", redacted)
        self.assertNotIn("words", redacted)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED]"), 3)


class DiagnosisTests(unittest.TestCase):
    def test_correlates_fastapi_import_failure_with_project_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app").mkdir()
            (root / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
            (root / "requirements.txt").write_text("fastapi==0.115.0\nuvicorn==0.30.0\n")
            (root / "Procfile").write_text("web: uvicorn main:app --host 0.0.0.0 --port $PORT\n")

            report = diagnose_project(
                root,
                logs="ERROR: Could not import module 'main'",
                platform="render",
            )

        self.assertTrue(report.diagnoses)
        diagnosis = report.diagnoses[0]
        self.assertEqual(diagnosis.category, "startup")
        self.assertTrue(any("app/main.py" in item.location for item in diagnosis.evidence))
        self.assertTrue(diagnosis.recommendation)
        self.assertTrue(diagnosis.verification_steps)
        self.assertNotEqual(diagnosis.status, "verified")
        self.assertTrue(diagnosis.proposed_changes)
        self.assertIn("app.main:app", diagnosis.proposed_changes[0].after)

    def test_vite_not_found_correlates_with_production_dependency_omission(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {"build": "vite build"},
                        "dependencies": {"react": "^18.3.0"},
                        "devDependencies": {"vite": "^5.4.0"},
                    }
                )
            )
            (root / "vercel.json").write_text('{"buildCommand":"npm run build"}')
            report = diagnose_project(root, logs="sh: vite: not found", platform="vercel")

        self.assertTrue(any(d.category == "build" for d in report.diagnoses))
        self.assertTrue(any(d.evidence for d in report.diagnoses))

    def test_report_serializes_with_evidence_and_no_fake_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("fastapi\n")
            report = diagnose_project(root, logs="ModuleNotFoundError: No module named 'uvicorn'")

        data = report.model_dump(mode="json")
        self.assertIn("diagnoses", data)
        self.assertIn("project", data)
        self.assertTrue(all(d["status"] != "verified" for d in data["diagnoses"]))

    def test_oversized_log_input_is_bounded_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = diagnose_project(Path(temp_dir), logs="x" * 1_000_001)

        self.assertTrue(any("truncated" in item.lower() for item in report.limitations))

    def test_markdown_report_escapes_untrusted_provider_text_and_redacts_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = diagnose_project(Path(temp_dir))
        report = report.model_copy(
            update={
                "summary": '# forged heading PASSWORD="secret value"\x1b[31m',
                "observations": ["\n# injected heading\nVERCEL_TOKEN=vercel_abcdefghijklmnop"],
                "provider_observations": [
                    Evidence(
                        source="provider **name**",
                        location="log:1",
                        excerpt="`untrusted` TOKEN=opaque-secret-value",
                        kind="log",
                    )
                ],
            }
        )

        rendered = render_markdown(report)

        self.assertNotIn("\n# forged heading", rendered)
        self.assertNotIn("\n# injected heading", rendered)
        self.assertNotIn("secret value", rendered)
        self.assertNotIn("abcdefghijklmnop", rendered)
        self.assertNotIn("opaque-secret-value", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertIn("provider \\*\\*name\\*\\*", rendered)


if __name__ == "__main__":
    unittest.main()
