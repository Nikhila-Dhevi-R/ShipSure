from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from typer.testing import CliRunner

from shipsure.cli import app


class CliTests(unittest.TestCase):
    def test_dependency_and_environment_commands_report_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("fastapi>=0.110\n", encoding="utf-8")
            (root / "app.py").write_text(
                'import os\nDATABASE_URL = os.getenv("DATABASE_URL")\n', encoding="utf-8"
            )
            (root / ".env.example").write_text("PUBLIC_NAME=example\n", encoding="utf-8")
            (root / ".env").write_text("DATABASE_URL=local-secret-value\n", encoding="utf-8")

            dependencies = CliRunner().invoke(
                app,
                ["dependencies", "--root", str(root), "--format", "json"],
            )
            environment = CliRunner().invoke(
                app,
                ["env-check", "--root", str(root), "--format", "json"],
            )

        self.assertEqual(dependencies.exit_code, 0, dependencies.output)
        self.assertIn("fastapi", dependencies.output.lower())
        self.assertEqual(environment.exit_code, 0, environment.output)
        self.assertIn("DATABASE_URL", environment.output)
        self.assertNotIn("local-secret-value", environment.output)

    def test_install_skill_writes_codex_and_claude_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            result = CliRunner().invoke(
                app,
                ["install-skill", "--client", "both", "--root", str(root)],
            )

            codex_skill = root / ".agents" / "skills" / "shipsure" / "SKILL.md"
            claude_skill = root / ".claude" / "skills" / "shipsure" / "SKILL.md"

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(codex_skill.is_file())
            self.assertEqual(codex_skill.read_bytes(), claude_skill.read_bytes())
            self.assertIn("ShipSure", codex_skill.read_text(encoding="utf-8"))

    def test_diagnosis_proposal_is_reviewed_and_applied_with_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app").mkdir()
            (root / "app" / "main.py").write_text(
                "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8"
            )
            (root / "requirements.txt").write_text("fastapi\nuvicorn\n", encoding="utf-8")
            procfile = root / "Procfile"
            procfile.write_text("web: uvicorn main:app --port $PORT\n", encoding="utf-8")
            log_file = root / "deploy.log"
            log_file.write_text("ERROR: Could not import module 'main'\n", encoding="utf-8")
            command = [
                "apply-proposal",
                "--root",
                str(root),
                "--log-file",
                str(log_file),
                "--finding",
                "1",
            ]

            declined = CliRunner().invoke(app, command, input="n\n")

            self.assertEqual(declined.exit_code, 0, declined.output)
            self.assertIn("No file was changed", declined.output)
            self.assertIn("uvicorn main:app", procfile.read_text(encoding="utf-8"))

            accepted = CliRunner().invoke(app, command + ["--approve"])

            self.assertEqual(accepted.exit_code, 0, accepted.output)
            self.assertIn("Applied. Rollback ID:", accepted.output)
            self.assertIn("uvicorn app.main:app", procfile.read_text(encoding="utf-8"))

    def test_install_skill_preserves_custom_content_without_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill = root / ".agents" / "skills" / "shipsure" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text("customized local skill\n", encoding="utf-8")

            result = CliRunner().invoke(
                app,
                ["install-skill", "--client", "codex", "--root", str(root)],
                input="n\n",
            )

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(skill.read_text(encoding="utf-8"), "customized local skill\n")


if __name__ == "__main__":
    unittest.main()
