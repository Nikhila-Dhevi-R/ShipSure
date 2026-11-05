from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from shipsure.analysis import inspect_dependencies, inspect_environment_configuration
from shipsure.engine import diagnose_project


class ProjectInventoryTests(unittest.TestCase):
    def test_dependency_inventory_reads_manifests_without_executing_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text(
                "fastapi>=0.110\nuvicorn[standard]\n", encoding="utf-8"
            )
            (root / "package.json").write_text(
                '{"scripts":{"build":"vite build"},"dependencies":{"react":"^18.0.0"},"devDependencies":{"vite":"^5.0.0"}}',
                encoding="utf-8",
            )
            inventory = inspect_dependencies(root)

        names = {item.name.lower() for item in inventory.dependencies}
        self.assertTrue({"fastapi", "uvicorn", "react", "vite"}.issubset(names))
        self.assertEqual(inventory.scripts["build"], "vite build")

    def test_environment_inspection_compares_names_only_and_ignores_real_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text(
                'import os\nkey = os.getenv("DATABASE_URL")\n', encoding="utf-8"
            )
            (root / ".env.example").write_text("PUBLIC_NAME=example\n", encoding="utf-8")
            (root / ".env").write_text(
                "DATABASE_URL=postgres://user:secret-value@host/db\n", encoding="utf-8"
            )
            inspection = inspect_environment_configuration(root)

        self.assertIn("DATABASE_URL", inspection.referenced_names)
        self.assertIn("DATABASE_URL", inspection.undocumented_names)
        self.assertNotIn("secret-value", str(inspection.model_dump()))
        self.assertNotIn(".env", inspection.files_inspected)

    def test_malformed_but_valid_package_json_does_not_crash_inventory_or_diagnosis(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text("[]", encoding="utf-8")

            inventory = inspect_dependencies(root)
            report = diagnose_project(root, logs="some unrecognized failure message")

        self.assertEqual(inventory.dependencies, [])
        self.assertEqual(report.project.frameworks, [])
        self.assertEqual(report.status, "inconclusive")


if __name__ == "__main__":
    unittest.main()
