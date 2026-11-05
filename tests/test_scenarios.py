from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from shipsure.engine import diagnose_project

SCENARIOS = [
    ("python missing package", "ModuleNotFoundError: No module named 'uvicorn'", "dependency"),
    ("python import path mismatch", "ERROR: Could not import module 'main'", "startup"),
    (
        "python dependency resolver conflict",
        "ERROR: ResolutionImpossible: conflicting dependencies",
        "dependency",
    ),
    ("node module absent", "Error: Cannot find module 'express'", "startup"),
    (
        "node ESM module absent",
        "Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'vite'",
        "startup",
    ),
    ("npm build script absent", "npm ERR! Missing script: build", "build"),
    ("vite executable absent", "sh: vite: not found", "build"),
    (
        "vite peer dependency conflict",
        "npm error ERESOLVE unable to resolve dependency tree",
        "dependency",
    ),
    ("application port already in use", "OSError: [Errno 98] Address already in use", "runtime"),
    ("container port already allocated", "Error: bind: address already in use", "container"),
    ("container health check fails", "Health check failed: container is unhealthy", "health_check"),
    (
        "container executable architecture mismatch",
        "standard_init_linux.go: exec user process caused: exec format error",
        "container",
    ),
    (
        "container entrypoint permission denied",
        "exec /usr/local/bin/entrypoint.sh: permission denied",
        "container",
    ),
    (
        "docker build instruction failed",
        "ERROR: failed to solve: process '/bin/sh -c npm run build' did not complete successfully",
        "container_build",
    ),
    ("GitHub Action ref invalid", "Unable to resolve action actions/setup-python@v99", "ci"),
    ("GitHub Actions command failure", "Error: Process completed with exit code 1", "ci"),
    (
        "Vercel environment variable missing",
        "Error: Environment Variable DATABASE_URL not found",
        "configuration",
    ),
    (
        "Vercel output directory missing",
        "Error: No Output Directory named 'dist' found after the Build completed",
        "configuration",
    ),
    ("Vercel function timed out", "Task timed out after 10.00 seconds", "runtime"),
    (
        "Vercel function invocation failed",
        "FUNCTION_INVOCATION_FAILED: Serverless function crashed",
        "runtime",
    ),
    (
        "AWS role denied action",
        "AccessDeniedException: not authorized to perform lambda:UpdateFunctionCode",
        "permissions",
    ),
    ("AWS ECS stopped task", "Essential container in task exited", "container"),
    (
        "AWS Lambda handler path mismatch",
        "Runtime.ImportModuleError: Unable to import module 'handler'",
        "startup",
    ),
    ("AWS EC2 reachability failure", "Instance reachability check failed", "infrastructure"),
    (
        "AWS CloudWatch read denied",
        "AccessDeniedException: not authorized logs:FilterLogEvents",
        "permissions",
    ),
    ("build process out of memory", "FATAL ERROR: JavaScript heap out of memory", "resources"),
    ("build filesystem full", "OSError: No space left on device", "resources"),
]


class RealisticScenarioTests(unittest.TestCase):
    def test_failure_scenarios_produce_expected_evidence_backed_categories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for title, log, expected_category in SCENARIOS:
                with self.subTest(scenario=title):
                    report = diagnose_project(root, logs=log)
                    self.assertTrue(report.diagnoses, title)
                    self.assertIn(expected_category, {d.category for d in report.diagnoses}, title)
                    self.assertTrue(all(d.evidence for d in report.diagnoses), title)
                    self.assertTrue(
                        all(d.status != "deployment_verified" for d in report.diagnoses), title
                    )

    def test_unknown_log_is_inconclusive_not_a_success_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = diagnose_project(Path(temp_dir), logs="deployment event 1872")

        self.assertEqual(report.status, "inconclusive")
        self.assertFalse(report.diagnoses)
        self.assertIn("inconclusive", report.summary.lower())


if __name__ == "__main__":
    unittest.main()
