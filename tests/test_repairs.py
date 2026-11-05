from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from shipsure.repairs import (
    ApprovalRequired,
    apply_file_change,
    preview_text_replacement,
    rollback_file_change,
    run_verification,
)


class SafeRepairTests(unittest.TestCase):
    def test_preview_is_read_only_and_apply_needs_approval_then_is_reversible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "Procfile"
            target.write_bytes(b"web: uvicorn main:app --port $PORT\r\n")
            change = preview_text_replacement(root, "Procfile", "main:app", "app.main:app")
            self.assertTrue(change.before.endswith("\r\n"))
            self.assertEqual(target.read_bytes(), b"web: uvicorn main:app --port $PORT\r\n")
            with self.assertRaises(ApprovalRequired):
                apply_file_change(root, change)

            applied = apply_file_change(root, change, approved=True)
            self.assertIn(b"app.main:app", target.read_bytes())
            self.assertTrue(target.read_bytes().endswith(b"\r\n"))
            self.assertTrue(Path(applied.backup_path).is_file())
            with self.assertRaises(ApprovalRequired):
                rollback_file_change(root, applied)
            rollback_file_change(root, applied, approved=True)
            self.assertEqual(target.read_bytes(), b"web: uvicorn main:app --port $PORT\r\n")

    def test_refuses_traversal_secrets_ambiguous_and_stale_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "Procfile").write_text("web: run\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                preview_text_replacement(root, "../outside", "run", "safe")
            with self.assertRaises(ValueError):
                preview_text_replacement(root, ".env", "token", "safe")

            target = root / "Procfile"
            change = preview_text_replacement(root, "Procfile", "run", "safe")
            target.write_text("web: changed\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                apply_file_change(root, change, approved=True)

            (root / "settings.yaml").write_text(
                "API_TOKEN=abc123\ncommand: run\n", encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                preview_text_replacement(root, "settings.yaml", "run", "safe")

    def test_verification_is_not_run_without_approval_and_success_is_execution_based(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaises(ApprovalRequired):
                run_verification(root, ["python", "-m", "compileall"], approved=False)
            with self.assertRaises(ValueError):
                run_verification(root, ["python", "-c", "print('unsafe')"], approved=True)

            result = run_verification(
                root, ["python", "-m", "compileall", "."], approved=True, timeout_seconds=10
            )

        self.assertTrue(result.verified)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.scope, "local")


if __name__ == "__main__":
    unittest.main()
